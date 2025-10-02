package pki.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pki.model.RevokedCertificate;
import pki.repository.RevokedCertificateRepository;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
@RequiredArgsConstructor
@Slf4j
public class RevocationService {

    private final RevokedCertificateRepository revokedCertificateRepository;

    @Value("${app.crl-validity-hours:24}")
    private int crlValidityHours;

    // thread safe
    private final Map<String, CachedCRL> crlCache = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> crlNumbers = new ConcurrentHashMap<>();

    /**
     * Generiše CRL za zadatog issuer-a.
     * Koristi keš ako je CRL još uvek validan.
     *
     * @param issuerPrivateKey Private key issuer-a koji potpisuje CRL
     * @param issuerX500Name X500 ime issuer-a
     * @param issuerId ID issuer-a (CertificateParty ID)
     * @param issuerPublicKey Public key issuer-a (za Authority Key Identifier)
     * @return X509CRL objekat
     */
    public synchronized X509CRL generateCRL(PrivateKey issuerPrivateKey,
                                            X500Name issuerX500Name,
                                            String issuerId,
                                            PublicKey issuerPublicKey) throws Exception {

        Date now = new Date();

        cleanupExpiredCRLs();

        // check if valid
        CachedCRL cached = crlCache.get(issuerId);
        if (cached != null && cached.getNextUpdate().after(now)) {
            log.debug("Returning cached CRL for issuer: {}", issuerId);
            return cached.getCrl();
        }

        // generate new
        Date nextUpdate = new Date(now.getTime() + crlValidityHours * 60L * 60 * 1000);
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerX500Name, now);
        crlBuilder.setNextUpdate(nextUpdate); // RFC 5280: RECOMMENDED ig

        // RFC 5280 must
        long crlNum = crlNumbers.computeIfAbsent(issuerId, k -> new AtomicLong(1)).getAndIncrement();
        crlBuilder.addExtension(
                Extension.cRLNumber,
                false,
                new CRLNumber(BigInteger.valueOf(crlNum))
        );

        // RFC 5280: should - authority
        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            crlBuilder.addExtension(
                    Extension.authorityKeyIdentifier,
                    false,
                    extUtils.createAuthorityKeyIdentifier(issuerPublicKey)
            );
        } catch (NoSuchAlgorithmException e) {
            log.warn("Could not add Authority Key Identifier: {}", e.getMessage());
        }

        // add revoked
        List<RevokedCertificate> revokedCertificates = revokedCertificateRepository.findByIssuerId(issuerId);

        for (RevokedCertificate rc : revokedCertificates) {
            try {
                BigInteger serialNumber = new BigInteger(rc.getSerialNumber(), 16);
                int reasonCode = rc.getReasonCode().ordinal();

                crlBuilder.addCRLEntry(serialNumber, rc.getRevokedAt(), reasonCode);

            } catch (NumberFormatException e) {
                log.error("Invalid serial number format for revoked cert: {}", rc.getSerialNumber(), e);
            }
        }

        // sign
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC")
                .build(issuerPrivateKey);

        X509CRL crl = new JcaX509CRLConverter()
                .setProvider("BC")
                .getCRL(crlBuilder.build(signer));

        // cache
        crlCache.put(issuerId, new CachedCRL(crl, nextUpdate));
        log.info("CRL cached for issuer: {} (valid until: {})", issuerId, nextUpdate);

        return crl;
    }


    public void invalidateCache(String issuerId) {
        CachedCRL removed = crlCache.remove(issuerId);
    }

    private void cleanupExpiredCRLs() {
        Date now = new Date();

        Iterator<Map.Entry<String, CachedCRL>> iterator = crlCache.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, CachedCRL> entry = iterator.next();
            if (entry.getValue().getNextUpdate().before(now)) {
                iterator.remove();
            }
        }
    }

    private static class CachedCRL {
        private final X509CRL crl;
        private final Date nextUpdate;

        public CachedCRL(X509CRL crl, Date nextUpdate) {
            this.crl = crl;
            this.nextUpdate = nextUpdate;
        }

        public X509CRL getCrl() {
            return crl;
        }

        public Date getNextUpdate() {
            return nextUpdate;
        }
    }
}