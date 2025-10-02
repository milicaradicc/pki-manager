package pki.service;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pki.dto.*;
import org.modelmapper.ModelMapper;
import pki.model.*;
import pki.model.Certificate;
import pki.repository.CertificatePartyRepository;
import pki.repository.CertificateRepository;
import pki.repository.RevokedCertificateRepository;
import pki.repository.UserRepository;
import pki.util.KeyStoreReader;
import pki.util.KeyStoreWriter;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CertificateService {
    @Value("${app.admin-wrapped-kek}")
    private String adminWrappedKek;
    @Value("${app.keystore-password}")
    private String keystorePassword;

    private static final String keyStoreFilePath = "src/main/resources/static/certificates.jks";

    private final CertificateRepository certificateRepository;
    private final CertificatePartyRepository certificatePartyRepository;
    private final RevokedCertificateRepository revokedCertificateRepository;
    private final KeyStoreReader keyStoreReader;
    private final KeyStoreWriter keyStoreWriter;
    private final UserService userService;
    private final UserRepository userRepository;
    private final RevocationService revocationService;
    private final ModelMapper modelMapper = new ModelMapper();
    private final KeyService keyService;

    @PostConstruct
    private void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void issueRootCertificate(CreateRootCertificateDTO certificateDTO) throws GeneralSecurityException, OperatorCreationException, CertIOException {
        KeyPair keyPair = KeyService.generateKeyPair();
        String wrappedDek = keyService.generateWrappedDek(adminWrappedKek);
        String wrappedPrivateKey = keyService.wrapPrivateKey(keyPair.getPrivate(), wrappedDek, adminWrappedKek);

        CertificateParty subject = modelMapper.map(certificateDTO.getSubject(), CertificateParty.class);
        subject.setId(java.util.UUID.randomUUID().toString());
        subject = certificatePartyRepository.save(subject);

        String serialNumber = UUID.randomUUID().toString().replace("-","");

        Certificate certificate = Certificate.builder()
                .serialNumber(serialNumber)
                .subject(subject)
                .issuer(subject)
                .type(CertificateType.ROOT)
                .publicKey(keyPair.getPublic())
                .wrappedPrivateKey(wrappedPrivateKey)
                .wrappedDek(wrappedDek)
                .startDate(certificateDTO.getStartDate())
                .endDate(certificateDTO.getEndDate())
                .usedAdminKek(true)
                .build();

        X509Certificate x509certificate = generateCertificate(certificate, keyPair.getPrivate(), true);

        char[] password = keyService.unwrapDek(wrappedDek, adminWrappedKek).toCharArray();
        keyStoreWriter.loadKeyStore(keyStoreFilePath,  keystorePassword.toCharArray());
        keyStoreWriter.write(serialNumber, keyPair.getPrivate(), password , x509certificate);
        keyStoreWriter.saveKeyStore(keyStoreFilePath,  keystorePassword.toCharArray());

        certificateRepository.save(certificate);
//        keyStoreReader.downloadCertificate(x509certificate);
    }

    public void issueIntermediateCertificate(CreateIntermediateCertificateDTO certificateDTO) throws GeneralSecurityException, OperatorCreationException, IOException {
        issueNonRootCertificate(certificateDTO, true);
    }

    public void issueEndEntityCertificate(CreateEndEntityCertificateDTO certificateDTO) throws GeneralSecurityException, OperatorCreationException, IOException {
        issueNonRootCertificate(certificateDTO, false);
    }

    private void issueNonRootCertificate(CreateNonRootCertificateDTO certificateDTO, boolean intermediate) throws GeneralSecurityException, OperatorCreationException, IOException {
        CertificateParty issuer = certificatePartyRepository.findById(certificateDTO.getIssuerId())
                .orElseThrow(() -> new IllegalArgumentException("Issuer with ID " + certificateDTO.getIssuerId() + " not found"));

        // VAŽNO: Prvo proverite ceo lanac povlačenja
        checkCertificateChainRevocation(issuer);

        Certificate issuerCertificate = certificateRepository.findFirstBySubject(issuer);
        if(issuerCertificate == null)
            throw new IllegalArgumentException("Certificate of issuer with ID " + certificateDTO.getIssuerId() + " not found");

        checkCaPermissions(issuer);

        if(!checkCertificateChainValidity(issuer, certificateDTO.getStartDate(), certificateDTO.getEndDate()))
            throw new IllegalArgumentException("Error validating certificate chain");

        User user = userService.getLoggedUser();
        if (userService.getPrimaryRole().equals("ca")) {
            if(user.getOrganization() == null ||
                    !user.getOrganization().getName().equalsIgnoreCase(certificateDTO.getSubject().getOrganization()))
                throw new IllegalArgumentException("Invalid organization");
        }
        KeyPair keyPair = KeyService.generateKeyPair();
        String wrappedKek;
        if (userService.getPrimaryRole().equals("admin"))
            wrappedKek = adminWrappedKek;
        else if (user.getOrganization() != null)
            wrappedKek = user.getOrganization().getWrappedKek();
        else
            throw new IllegalArgumentException("Logged user does not have an organization");

        String wrappedDek = keyService.generateWrappedDek(wrappedKek);
        String wrappedPrivateKey = keyService.wrapPrivateKey(keyPair.getPrivate(), wrappedDek, wrappedKek);

        CertificateParty subject = modelMapper.map(certificateDTO.getSubject(), CertificateParty.class);
        subject.setId(java.util.UUID.randomUUID().toString());
        subject = certificatePartyRepository.save(subject);

        String serialNumber = UUID.randomUUID().toString().replace("-","");

        Certificate certificate = Certificate.builder()
                .serialNumber(serialNumber)
                .subject(subject)
                .issuer(issuer)
                .type(intermediate ? CertificateType.INTERMEDIATE : CertificateType.END_ENTITY)
                .publicKey(keyPair.getPublic())
                .wrappedPrivateKey(wrappedPrivateKey)
                .wrappedDek(wrappedDek)
                .startDate(certificateDTO.getStartDate())
                .endDate(certificateDTO.getEndDate())
                .organization(user.getOrganization())
                .usedAdminKek(userService.getPrimaryRole().equals("admin"))
                .build();

        String issuerWrappedKek = (issuerCertificate.getUsedAdminKek() != null && issuerCertificate.getUsedAdminKek())
                ? adminWrappedKek
                : issuerCertificate.getOrganization().getWrappedKek();
        PrivateKey issuerPrivateKey = keyService.unwrapPrivateKey(issuerCertificate.getWrappedPrivateKey(),
                issuerCertificate.getWrappedDek(),
                issuerWrappedKek);
        X509Certificate x509certificate = generateCertificate(certificate, issuerPrivateKey, intermediate);

        char[] password = keyService.unwrapDek(wrappedDek, wrappedKek).toCharArray();
        keyStoreWriter.loadKeyStore(keyStoreFilePath,  keystorePassword.toCharArray());
        keyStoreWriter.write(serialNumber, keyPair.getPrivate(), password , x509certificate);
        keyStoreWriter.saveKeyStore(keyStoreFilePath,  keystorePassword.toCharArray());

        certificateRepository.save(certificate);

        boolean isCa = Objects.equals(userService.getPrimaryRole(), "ca");
        boolean isUser = Objects.equals(userService.getPrimaryRole(), "user");
        if((intermediate && isCa) || (!intermediate && (isCa || isUser)))
        {
            user.getOwnedCertificates().add(certificate);
            userRepository.save(user);
        }
    }

    public void processCSR(String csrContent, String issuerId, Date startDate, Date endDate) throws IOException, GeneralSecurityException, OperatorCreationException {
        //TODO: add extensions
        //TODO: decide if this is only for end-entity users
        PemReader pemReader = new PemReader(new StringReader(csrContent));
        byte[] content = pemReader.readPemObject().getContent();

        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(content);

        CertificateParty issuer = certificatePartyRepository.findById(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer with ID " + issuerId + " not found"));

        // VAŽNO: Proveri lanac povlačenja i ovde
        checkCertificateChainRevocation(issuer);

        Certificate issuerCertificate = certificateRepository.findFirstBySubject(issuer);
        if(issuerCertificate == null)
            throw new IllegalArgumentException("Certificate of issuer with ID " + issuerId + " not found");

        if(!checkCertificateChainValidity(issuer, startDate, endDate))
            throw new IllegalArgumentException("Error validating certificate chain");

        X500Name csrSubject = csr.getSubject();

        CertificateParty subject = new CertificateParty();
        subject.setCommonName(getRDNValue(csrSubject, BCStyle.CN));
        subject.setSurname(getRDNValue(csrSubject, BCStyle.SURNAME));
        subject.setGivenName(getRDNValue(csrSubject, BCStyle.GIVENNAME));
        subject.setOrganization(getRDNValue(csrSubject, BCStyle.O));
        subject.setOrganizationalUnit(getRDNValue(csrSubject, BCStyle.OU));
        subject.setCountry(getRDNValue(csrSubject, BCStyle.C));
        subject.setEmail(getRDNValue(csrSubject, BCStyle.EmailAddress));

        subject.setId(java.util.UUID.randomUUID().toString());
        subject = certificatePartyRepository.save(subject);

        User user = userService.getLoggedUser();
        String serialNumber = UUID.randomUUID().toString().replace("-","");

        // TODO: add private key wrapping in case of auto generated key pair
        Certificate certificate = Certificate.builder()
                .serialNumber(serialNumber)
                .subject(subject)
                .issuer(issuer)
                .type(CertificateType.END_ENTITY)
                .publicKey((new JcaPKCS10CertificationRequest(csr)).getPublicKey())
                .wrappedPrivateKey(null) // In case of user provided public key
                .wrappedDek(null)
                .startDate(startDate)
                .endDate(endDate)
                .organization(user.getOrganization())
                .usedAdminKek(userService.getPrimaryRole().equals("admin"))
                .build();

        String issuerWrappedKek = (issuerCertificate.getUsedAdminKek() != null && issuerCertificate.getUsedAdminKek())
                ? adminWrappedKek
                : issuerCertificate.getOrganization().getWrappedKek();
        PrivateKey issuerPrivateKey = keyService.unwrapPrivateKey(issuerCertificate.getWrappedPrivateKey(),
                issuerCertificate.getWrappedDek(),
                issuerWrappedKek);
        X509Certificate x509certificate = generateCertificate(certificate, issuerPrivateKey, false);

        //TODO: sent certificate to user (it isn't saved in keystore)

        certificateRepository.save(certificate);

//        keyStoreReader.downloadCertificate(x509certificate);
    }

    private String getRDNValue(X500Name name, ASN1ObjectIdentifier oid) {
        RDN rdn = name.getRDNs(oid).length > 0 ? name.getRDNs(oid)[0] : null;
        return rdn != null ? rdn.getFirst().getValue().toString() : null;
    }

    private X509Certificate generateCertificate(Certificate certificate, PrivateKey issuerPrivateKey, boolean isCa)
            throws CertificateException, OperatorCreationException, CertIOException {

        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        builder = builder.setProvider("BC");
        ContentSigner contentSigner = builder.build(issuerPrivateKey);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                certificate.getIssuer().getX500Name(),
                new BigInteger(certificate.getSerialNumber(), 16),
                certificate.getStartDate(),
                certificate.getEndDate(),
                certificate.getSubject().getX500Name(),
                certificate.getPublicKey()
        );

        if (isCa) {
            certGen.addExtension(
                    Extension.basicConstraints,
                    true,
                    new BasicConstraints(true)
            );

            certGen.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
            );
        } else {
            certGen.addExtension(
                    Extension.basicConstraints,
                    true,
                    new BasicConstraints(false)
            );

            certGen.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
            );

            // CRL Distribution Point URL (http://localhost:8080/crl/download)
            // klijenti koji validiraju sertifikat mogu dohvatiti CRL i
            // proveriti da li je sertifikat povučen
            DistributionPointName distPoint = new DistributionPointName(
                    new GeneralNames(
                            new GeneralName(GeneralName.uniformResourceIdentifier, "https://localhost:8443/crl/download")
                    )
            );
            DistributionPoint[] distPoints = new DistributionPoint[]{new DistributionPoint(distPoint, null, null)};
            certGen.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints));
        }

        X509CertificateHolder certHolder = certGen.build(contentSigner);

        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
        certConverter = certConverter.setProvider("BC");

        return certConverter.getCertificate(certHolder);
    }

    private boolean checkCertificateChainValidity(CertificateParty issuerParty, Date startDate, Date endDate)
            throws GeneralSecurityException, IOException {

        Certificate issuerCertificate = certificateRepository.findFirstBySubject(issuerParty);
        if(issuerCertificate == null)
            return false;

        // Učitaj issuer sertifikat iz keystore-a
        X509Certificate x509IssuerCert = (X509Certificate) keyStoreReader.readCertificate(
                keyStoreFilePath, keystorePassword, issuerCertificate.getSerialNumber()
        );

        if(x509IssuerCert == null)
            return false;

        // Proveri da li su datumi validni u odnosu na issuer sertifikat
        if(x509IssuerCert.getNotBefore().after(startDate) || x509IssuerCert.getNotAfter().before(endDate))
            return false;

        // Ako je ROOT, verifikacija je završena
        if(issuerCertificate.getType() == CertificateType.ROOT) {
            return true;
        }

        // Ako nije ROOT, proveri issuer-a od issuer-a rekurzivno
        Certificate issuerOfIssuer = certificateRepository.findFirstBySubject(issuerCertificate.getIssuer());
        if(issuerOfIssuer == null)
            return false;

        // Verifikuj potpis
        try {
            x509IssuerCert.verify(issuerOfIssuer.getPublicKey());
        } catch (InvalidKeyException | SignatureException e) {
            return false;
        }

        // Rekurzivno proveri lanac
        return checkCertificateChainValidity(issuerCertificate.getIssuer(), startDate, endDate);
    }

    /**
     * Proverava da li je bilo koji sertifikat u lancu povučen
     * @param issuerParty Issuer od koga počinjemo proveru
     * @throws IllegalArgumentException ako je bilo koji sertifikat u lancu povučen
     */
    private void checkCertificateChainRevocation(CertificateParty issuerParty) {
        Certificate currentCertificate = certificateRepository.findFirstBySubject(issuerParty);

        while (currentCertificate != null) {
            boolean isRevoked = revokedCertificateRepository.existsBySerialNumber(
                    currentCertificate.getSerialNumber()
            );

            if (isRevoked) {
                throw new IllegalArgumentException(
                        "Certificate with serial number " + currentCertificate.getSerialNumber() +
                                " (CN=" + currentCertificate.getSubject().getCommonName() + ") in the chain is revoked"
                );
            }

            if (currentCertificate.getType() == CertificateType.ROOT) {
                break;
            }

            currentCertificate = certificateRepository.findFirstBySubject(
                    currentCertificate.getIssuer()
            );
        }
    }

    private void checkCaPermissions(CertificateParty issuer){
        if(!Objects.equals(userService.getPrimaryRole(), "ca"))
            return;

        List<Certificate> certificates = certificateRepository.findBySubject(issuer);
        if(certificates.isEmpty())
            throw new IllegalArgumentException("Issuer with ID " + issuer.getId() + " not found");
        Certificate certificate = certificates.get(0);
        User user = userService.getLoggedUser();
        if(user.getOwnedCertificates().stream().noneMatch(c -> c.getSerialNumber().equals(certificate.getSerialNumber())))
            throw new IllegalArgumentException("Issuer with ID " + issuer.getId() + " not permitted for logged user");
    }

    public List<GetCertificateDTO> getAllCaCertificates() {
        List<Certificate> certificates;
        if(Objects.equals(userService.getPrimaryRole(), "ca")) {
            certificates = userService.getLoggedUser()
                    .getOwnedCertificates()
                    .stream()
                    .filter(c -> c.getType() != CertificateType.END_ENTITY)
                    .toList();
        } else {
            certificates = certificateRepository.findByTypeIn(
                    List.of(CertificateType.ROOT, CertificateType.INTERMEDIATE)
            );
        }

        return certificates.stream()
                .map(this::mapToGetCertificateDTO)
                .toList();
    }

    public void assignCaUser(AssignCertificateDTO assignCertificateDTO) {
        Certificate certificate = certificateRepository.findFirstBySerialNumber(assignCertificateDTO.getCertificateSerialNumber());
        if (certificate == null)
            throw new IllegalArgumentException("Certificate with serial number " + assignCertificateDTO.getCertificateSerialNumber() + " not found");
        User user = userRepository.findByEmail(assignCertificateDTO.getCaUserEmail()).orElseThrow();
        if (user.getOwnedCertificates() == null)
            user.setOwnedCertificates(new ArrayList<>());
        if (user.getOwnedCertificates().stream().anyMatch(c -> c.getSerialNumber().equals(certificate.getSerialNumber())))
            return;
        user.getOwnedCertificates().add(certificate);
        userRepository.save(user);
    }

    public List<GetCertificateDTO> getAllCertificates() {
        return certificateRepository.findAll()
                .stream()
                .map(this::mapToGetCertificateDTO)
                .toList();
    }

    public void revokeCertificate(String serialNumber, RevocationReason reason) {
        Certificate certificate = certificateRepository.findFirstBySerialNumber(serialNumber);
        if (certificate == null) throw new IllegalArgumentException("Certificate not found");

        RevokedCertificate revokedCertificate = new RevokedCertificate();
        revokedCertificate.setSerialNumber(serialNumber);
        revokedCertificate.setRevokedAt(new Date());
        revokedCertificate.setReasonCode(reason);
        revokedCertificate.setIssuerId(certificate.getIssuer().getId());

        revokedCertificateRepository.save(revokedCertificate);

        try {
            Certificate issuer = certificateRepository.findFirstBySubject(certificate.getIssuer());
            if (issuer == null) throw new IllegalArgumentException("Issuer certificate not found");

            PrivateKey issuerPrivateKey = getIssuerPrivateKey(issuer);
            X500Name issuerName = issuer.getSubject().getX500Name();

            revocationService.generateCRL(issuerPrivateKey, issuerName);
        } catch (Exception e) {
            throw new RuntimeException("Failed to update CRL", e);
        }
    }

    public Certificate getRootCertificate() {
        return certificateRepository.findFirstByType(CertificateType.ROOT);
    }

    public PrivateKey getIssuerPrivateKey(Certificate certificate) throws GeneralSecurityException {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }

        String wrappedDek = certificate.getWrappedDek();
        String wrappedPrivateKey = certificate.getWrappedPrivateKey();

        String wrappedKek;
        if (certificate.getUsedAdminKek() != null && certificate.getUsedAdminKek()) {
            wrappedKek = adminWrappedKek;
        } else if (certificate.getOrganization() != null) {
            wrappedKek = certificate.getOrganization().getWrappedKek();
        } else {
            throw new IllegalArgumentException("Cannot determine KEK for certificate: " +
                    certificate.getSerialNumber());
        }

        return keyService.unwrapPrivateKey(wrappedPrivateKey, wrappedDek, wrappedKek);
    }

    private GetCertificateDTO mapToGetCertificateDTO(Certificate certificate) {
        if (certificate == null) {
            return null;
        }

        CertificateParty subject = certificate.getSubject();
        CertificateParty issuer = certificate.getIssuer();
        Organization org = certificate.getOrganization();

        // Check if certificate is revoked
        boolean revoked = revokedCertificateRepository.existsBySerialNumber(certificate.getSerialNumber());

        return new GetCertificateDTO(
                certificate.getSerialNumber(),
                certificate.getSubject().getId(),

                // Subject fields
                subject != null ? subject.getCommonName() : null,
                subject != null ? subject.getSurname() : null,
                subject != null ? subject.getGivenName() : null,
                subject != null ? subject.getOrganization() : null,
                subject != null ? subject.getOrganizationalUnit() : null,
                subject != null ? subject.getCountry() : null,
                subject != null ? subject.getEmail() : null,

                // Issuer fields
                issuer != null ? issuer.getCommonName() : null,
                issuer != null ? issuer.getSurname() : null,
                issuer != null ? issuer.getGivenName() : null,
                issuer != null ? issuer.getOrganization() : null,
                issuer != null ? issuer.getOrganizationalUnit() : null,
                issuer != null ? issuer.getCountry() : null,
                issuer != null ? issuer.getEmail() : null,

                certificate.getType(),
                org != null ? org.getName() : null,
                certificate.getStartDate(),
                certificate.getEndDate(),
                revoked
        );
    }
}