package pki.service;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pki.model.*;
import pki.model.Certificate;
import pki.repository.CertificateRepository;
import pki.repository.RevokedCertificateRepository;
import pki.util.KeyStoreReader;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class RevocationService {

    private final RevokedCertificateRepository revokedCertificateRepository;
    private final CertificateRepository certificateRepository;
    private final KeyStoreReader keyStoreReader;
    private final KeyService keyService;

    @Value("${app.certificate-keystore-password}")
    private String keystorePassword;

    @Value("${app.certificate-keystore-path}")
    private String keyStoreFilePath;

    @Value("${app.admin-wrapped-kek}")
    private String adminWrappedKek;

    @Value("${app.crl-directory:src/main/resources/crl}")
    private String crlDirectory;

    @Value("${app.crl-base-url:http://localhost:8080/api/crl}")
    private String crlBaseUrl;

    private final Map<String, CRLCacheEntry> crlCache = new HashMap<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @PostConstruct
    public void init() {
        try {
            Path crlPath = Paths.get(crlDirectory);
            if (!Files.exists(crlPath)) {
                Files.createDirectories(crlPath);
            }
        } catch (IOException e) {
            log.error("Failed to create CRL directory", e);
        }
    }

    public void revokeCertificate(String serialNumber, RevocationReason reason) {
        Certificate cert = certificateRepository.findFirstBySerialNumber(serialNumber);
        if (cert == null) throw new IllegalArgumentException("Certificate not found: " + serialNumber);

        if (revokedCertificateRepository.existsBySerialNumber(serialNumber))
            throw new IllegalArgumentException("Certificate already revoked: " + serialNumber);

        RevokedCertificate revoked = new RevokedCertificate();
        revoked.setSerialNumber(serialNumber);
        revoked.setReasonCode(reason);
        revoked.setRevokedAt(new Date());
        revoked.setIssuerId(cert.getIssuer().getId());

        revokedCertificateRepository.save(revoked);

        Certificate issuerCert = certificateRepository.findFirstBySubject(cert.getIssuer());
        if (issuerCert != null) {
            crlCache.remove(issuerCert.getSerialNumber());
            try {
                generateCRL(issuerCert.getSerialNumber());
            } catch (Exception e) {
                log.error("Failed to regenerate CRL for issuer {}", issuerCert.getSerialNumber(), e);
            }
        }

        log.info("Certificate {} revoked with reason: {}", serialNumber, reason);
    }

    public void checkCertificateChainRevocation(CertificateParty party) throws Exception {
        Certificate cert = certificateRepository.findFirstBySubject(party);
        if (cert == null) throw new IllegalArgumentException("Certificate not found for party: " + party.getId());

        checkCertificateChainRevocationRecursive(cert);
    }

    private void checkCertificateChainRevocationRecursive(Certificate cert) throws Exception {
        if (cert.getType() == CertificateType.ROOT) {
            if (revokedCertificateRepository.existsBySerialNumber(cert.getSerialNumber())) {
                throw new IllegalArgumentException("Certificate issuance denied: one or more certificates in the chain are revoked");
            }
            return;
        }

        Certificate issuerCert = certificateRepository.findFirstBySubject(cert.getIssuer());
        if (issuerCert == null) throw new IllegalArgumentException("Issuer not found for: " + cert.getSerialNumber());

        X509Certificate x509Cert = getX509Certificate(cert.getSerialNumber());

        if (isCertificateRevokedViaCDP(x509Cert)) {
            throw new IllegalArgumentException("Certificate issuance denied: one or more certificates in the chain are revoked");
        }

        checkCertificateChainRevocationRecursive(issuerCert);
    }

    public boolean isCertificateRevokedViaCDP(X509Certificate certificate) throws Exception {
        byte[] cdpExtension = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (cdpExtension == null) throw new Exception("No CDP extension");

        ASN1Primitive cdpAsn1 = JcaX509ExtensionUtils.parseExtensionValue(cdpExtension);
        CRLDistPoint distPoint = CRLDistPoint.getInstance(cdpAsn1);

        X509Certificate issuerCert = getIssuerCertificate(certificate);
        if (issuerCert == null) {
            throw new SecurityException("Cannot verify CRL: issuer certificate not found");
        }

        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            if (dp.getDistributionPoint() == null) continue;
            DistributionPointName dpName = dp.getDistributionPoint();
            if (dpName.getType() != DistributionPointName.FULL_NAME) continue;

            GeneralNames generalNames = (GeneralNames) dpName.getName();
            for (GeneralName gn : generalNames.getNames()) {
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    String crlUrl = DERIA5String.getInstance(gn.getName()).getString();
                    try {
                        X509CRL crl;
                        if (crlUrl.contains("localhost") || crlUrl.contains("127.0.0.1")) {
                            String fileName = crlUrl.substring(crlUrl.lastIndexOf("/") + 1);
                            Path path = Paths.get(crlDirectory, fileName);
                            try (var in = Files.newInputStream(path)) {
                                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                                crl = (X509CRL) cf.generateCRL(in);
                            }
                        } else {
                            crl = downloadCRL(crlUrl);
                        }

                        if (crl != null) {
                            validateCRL(crl, issuerCert);

                            if (crl.getRevokedCertificate(certificate.getSerialNumber()) != null) {
                                return true;
                            }
                        }
                    } catch (SecurityException e) {
                        log.error("CRL verification failed for URL {}: {}", crlUrl, e.getMessage());
                        throw e;
                    } catch (Exception e) {
                        log.warn("Failed to check CRL {}: {}", crlUrl, e.getMessage());
                    }
                }
            }
        }

        return false;
    }

    private X509CRL downloadCRL(String crlUrl) throws Exception {
        if (crlUrl.startsWith("http://") || crlUrl.startsWith("https://")) {
            URL url = new URL(crlUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(10000);
            try (var in = connection.getInputStream()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return (X509CRL) cf.generateCRL(in);
            } finally {
                connection.disconnect();
            }
        } else if (crlUrl.startsWith("file://")) {
            Path path = Paths.get(URI.create(crlUrl));
            try (var in = Files.newInputStream(path)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return (X509CRL) cf.generateCRL(in);
            }
        }
        throw new IllegalArgumentException("Unsupported CRL URL: " + crlUrl);
    }

    public byte[] generateCRL(String issuerSerialNumber) throws Exception {
        Certificate issuerCert = certificateRepository.findFirstBySerialNumber(issuerSerialNumber);
        if (issuerCert == null) throw new IllegalArgumentException("Issuer not found: " + issuerSerialNumber);

        X509Certificate x509IssuerCert = getX509Certificate(issuerSerialNumber);
        PrivateKey issuerPrivateKey = getIssuerPrivateKey(issuerCert);

        org.bouncycastle.asn1.x500.X500Name issuerName =
                org.bouncycastle.asn1.x500.X500Name.getInstance(x509IssuerCert.getSubjectX500Principal().getEncoded());

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerName, new Date());
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_YEAR, 7);
        crlBuilder.setNextUpdate(calendar.getTime());

        List<RevokedCertificate> revokedCerts = revokedCertificateRepository.findByIssuerId(issuerCert.getSubject().getId());
        for (RevokedCertificate revoked : revokedCerts) {
            BigInteger serial = new BigInteger(revoked.getSerialNumber(), 16);

            CRLReason crlReason = CRLReason.lookup(revoked.getReasonCode().ordinal());

            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen.addExtension(Extension.reasonCode, false, crlReason);
            Extensions extensions = extGen.generate();

            crlBuilder.addCRLEntry(serial, revoked.getRevokedAt(), extensions);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerPrivateKey);
        X509CRLHolder holder = crlBuilder.build(signer);
        byte[] crlBytes = new JcaX509CRLConverter().setProvider("BC").getCRL(holder).getEncoded();

        Path path = Paths.get(crlDirectory, issuerSerialNumber + ".crl");
        Files.write(path, crlBytes);
        crlCache.put(issuerSerialNumber, new CRLCacheEntry(crlBytes, new Date(), calendar.getTime()));

        return crlBytes;
    }

    private X509Certificate getX509Certificate(String serialNumber) throws Exception {
        return (X509Certificate) keyStoreReader.readCertificate(keyStoreFilePath, keystorePassword, serialNumber);
    }

    private PrivateKey getIssuerPrivateKey(Certificate certificate) throws GeneralSecurityException {
        String wrappedDek = certificate.getWrappedDek();
        String wrappedPrivateKey = certificate.getWrappedPrivateKey();
        String wrappedKek = Boolean.TRUE.equals(certificate.getUsedAdminKek()) ? adminWrappedKek
                : certificate.getOrganization().getWrappedKek();
        return keyService.unwrapPrivateKey(wrappedPrivateKey, wrappedDek, wrappedKek);
    }

    private void verifyCRLSignature(X509CRL crl, X509Certificate issuerCertificate) throws Exception {
        try {
            crl.verify(issuerCertificate.getPublicKey(), "BC");
        } catch (Exception e) {
            throw new SecurityException("Invalid CRL signature: " + e.getMessage(), e);
        }
    }

    private void validateCRL(X509CRL crl, X509Certificate issuerCertificate) throws Exception {
        // potpis
        verifyCRLSignature(crl, issuerCertificate);

        // da li je istekao
        Date now = new Date();
        if (crl.getThisUpdate().after(now)) {
            throw new SecurityException("CRL is not yet valid (thisUpdate is in the future)");
        }

        if (crl.getNextUpdate() != null && crl.getNextUpdate().before(now)) {
            throw new SecurityException("CRL has expired");
        }

        if (!crl.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal())) {
            throw new SecurityException("CRL issuer does not match certificate issuer");
        }

        log.debug("CRL validation passed for issuer: {}",
                issuerCertificate.getSerialNumber().toString(16));
    }

    private X509Certificate getIssuerCertificate(X509Certificate certificate) throws Exception {
        String issuerDN = certificate.getIssuerX500Principal().getName();

        List<Certificate> allCerts = certificateRepository.findAll();
        for (Certificate cert : allCerts) {
            try {
                X509Certificate x509 = getX509Certificate(cert.getSerialNumber());
                String subjectDN = x509.getSubjectX500Principal().getName();

                if (normalizeDN(subjectDN).equals(normalizeDN(issuerDN))) {
                    log.debug("Found issuer certificate: {} for DN: {}",
                            cert.getSerialNumber(), issuerDN);
                    return x509;
                }
            } catch (Exception e) {
                log.warn("Failed to load certificate {}: {}",
                        cert.getSerialNumber(), e.getMessage());
            }
        }

        return null;
    }

    private String normalizeDN(String dn) {
        if (dn == null) return "";
        return dn.replaceAll("\\s*,\\s*", ",")
                .replaceAll("\\s*=\\s*", "=")
                .toLowerCase()
                .trim();
    }

    public static class CRLCacheEntry {
        public byte[] crlData;
        public Date generatedAt;
        public Date nextUpdate;

        public CRLCacheEntry(byte[] crlData, Date generatedAt, Date nextUpdate) {
            this.crlData = crlData;
            this.generatedAt = generatedAt;
            this.nextUpdate = nextUpdate;
        }
    }

    public byte[] getOrGenerateCRL(String issuerSerialNumber) throws Exception {
        CRLCacheEntry cached = crlCache.get(issuerSerialNumber);
        if (cached != null && cached.nextUpdate.after(new Date())) {
            log.debug("Returning cached CRL for issuer {}", issuerSerialNumber);
            return cached.crlData;
        }

        try {
            X509CRL crl = loadCRLFromFile(issuerSerialNumber);
            if (crl != null && crl.getNextUpdate().after(new Date())) {
                // potpis
                X509Certificate issuerCert = getX509Certificate(issuerSerialNumber);
                validateCRL(crl, issuerCert);

                byte[] crlBytes = crl.getEncoded();
                crlCache.put(issuerSerialNumber, new CRLCacheEntry(
                        crlBytes,
                        crl.getThisUpdate(),
                        crl.getNextUpdate()
                ));
                return crlBytes;
            }
        } catch (SecurityException e) {
            log.error("CRL verification failed for issuer {}, regenerating CRL",
                    issuerSerialNumber, e);
        } catch (Exception e) {
            log.warn("Failed to load CRL from file for issuer {}: {}",
                    issuerSerialNumber, e.getMessage());
        }
        return generateCRL(issuerSerialNumber);
    }

    private X509CRL loadCRLFromFile(String issuerSerialNumber) throws Exception {
        String fileName = issuerSerialNumber + ".crl";
        Path filePath = Paths.get(crlDirectory, fileName);

        if (!Files.exists(filePath)) {
            return null;
        }

        try (FileInputStream fis = new FileInputStream(filePath.toFile())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(fis);
        }
    }
}