package pki.service;

import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pki.dto.*;
import org.modelmapper.ModelMapper;
import pki.dto.certificate.DownloadCertificateDTO;
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
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static org.keycloak.utils.StreamsUtil.distinctByKey;

@Service
@RequiredArgsConstructor
public class CertificateService {
    @Value("${app.admin-wrapped-kek}")
    private String adminWrappedKek;
    @Value("${app.certificate-keystore-password}")
    private String keystorePassword;
    @Value("${app.certificate-keystore-path}")
    private String keyStoreFilePath;
    @Value("${app.crl-url}")
    private String crlUrl;

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
    private final ExportService exportService;

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

        certificate.setKeyUsages(Set.of(KeyUsageModel.KEY_CERT_SIGN, KeyUsageModel.CRL_SIGN));

        certificateRepository.save(certificate);
    }

    @Transactional
    public void issueIntermediateCertificate(CreateIntermediateCertificateDTO certificateDTO) throws GeneralSecurityException, OperatorCreationException, IOException {
        try {
            issueNonRootCertificate(certificateDTO, true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Transactional
    public DownloadCertificateDTO issueEndEntityCertificate(CreateEndEntityCertificateDTO certificateDTO) throws GeneralSecurityException, OperatorCreationException, IOException {
        try {
            return issueNonRootCertificate(certificateDTO, false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Transactional
    protected DownloadCertificateDTO issueNonRootCertificate(CreateNonRootCertificateDTO certificateDTO, boolean intermediate) throws Exception {
        CertificateParty issuer = certificatePartyRepository.findById(certificateDTO.getIssuerId())
                .orElseThrow(() -> new IllegalArgumentException("Issuer with ID " + certificateDTO.getIssuerId() + " not found"));

        revocationService.checkCertificateChainRevocation(issuer);

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
            throw new IllegalArgumentException("Logged user does not have an organization"  );

        String wrappedDek = keyService.generateWrappedDek(wrappedKek);
        String wrappedPrivateKey = keyService.wrapPrivateKey(keyPair.getPrivate(), wrappedDek, wrappedKek);

        CertificateParty subject = modelMapper.map(certificateDTO.getSubject(), CertificateParty.class);
        subject.setId(java.util.UUID.randomUUID().toString());
        subject = certificatePartyRepository.save(subject);

        String serialNumber = UUID.randomUUID().toString().replace("-","");

        HashSet<ExtendedKeyUsageModel> extendedKeyUsages = resolveExtendedKeyUsages(certificateDTO.getExtendedKeyUsages(), issuerCertificate);
        HashSet<KeyUsageModel> keyUsages = new HashSet<>();
        if(!intermediate && certificateDTO instanceof CreateEndEntityCertificateDTO endEntityDTO){
            if(endEntityDTO.getKeyUsages() != null && !endEntityDTO.getKeyUsages().isEmpty()){
                keyUsages.addAll(endEntityDTO.getKeyUsages());
            }
        }

        Certificate certificate = Certificate.builder()
                .serialNumber(serialNumber)
                .subject(subject)
                .issuer(issuer)
                .type(intermediate ? CertificateType.INTERMEDIATE : CertificateType.END_ENTITY)
                .publicKey(keyPair.getPublic())
                .wrappedPrivateKey(!intermediate ? null : wrappedPrivateKey)
                .wrappedDek(wrappedDek)
                .startDate(certificateDTO.getStartDate())
                .endDate(certificateDTO.getEndDate())
                .organization(user.getOrganization())
                .usedAdminKek(userService.getPrimaryRole().equals("admin"))
                .extendedKeyUsages(extendedKeyUsages)
                .keyUsages(keyUsages)
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

        if(intermediate)
            certificate.setKeyUsages(Set.of(KeyUsageModel.KEY_CERT_SIGN, KeyUsageModel.CRL_SIGN));

        certificateRepository.save(certificate);

        boolean isUser = Objects.equals(userService.getPrimaryRole(), "user");

        if(!intermediate && isUser){
            if(user.getOwnedCertificates() == null)
                user.setOwnedCertificates(new ArrayList<>());
            user.getOwnedCertificates().add(certificate);
            userRepository.save(user);
        }

        if (intermediate) {
            return null;
        }
        else
            return exportService.exportCertificate(certificate, keyPair.getPrivate());
    }

    private HashSet<ExtendedKeyUsageModel> resolveExtendedKeyUsages(List<ExtendedKeyUsageModel> certificateEKUs, Certificate issuerCertificate){
        HashSet<ExtendedKeyUsageModel> extendedKeyUsages = new HashSet<>();

        if(issuerCertificate.getExtendedKeyUsages()!=null && !issuerCertificate.getExtendedKeyUsages().isEmpty()){
            if(certificateEKUs == null || certificateEKUs.isEmpty())
                extendedKeyUsages.addAll(issuerCertificate.getExtendedKeyUsages());
            else{
                checkExtendedKeyUsage(issuerCertificate.getExtendedKeyUsages(), certificateEKUs);
                extendedKeyUsages.addAll(certificateEKUs);
            }
        }
        else{
            extendedKeyUsages.addAll(certificateEKUs);
        }

        return extendedKeyUsages;
    }

    private void checkExtendedKeyUsage(Collection<ExtendedKeyUsageModel> parentUsages, Collection<ExtendedKeyUsageModel> childUsages){
        for(ExtendedKeyUsageModel usage : childUsages){
            if(!parentUsages.contains(usage))
                throw new IllegalArgumentException("Certificate issuance denied: one or more certificates in the chain are revoked");
        }
    }


    @Transactional
    public void processCSR(String csrContent, String issuerId, Date startDate, Date endDate) throws Exception {
        PemReader pemReader = new PemReader(new StringReader(csrContent));
        byte[] content = pemReader.readPemObject().getContent();

        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(content);

        CertificateParty issuer = certificatePartyRepository.findById(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer with ID " + issuerId + " not found"));

        revocationService.checkCertificateChainRevocation(issuer);

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
        subject.setAlternativeName(getFirstSubjectAlternativeName(csr));

        subject.setId(java.util.UUID.randomUUID().toString());
        subject = certificatePartyRepository.save(subject);

        User user = userService.getLoggedUser();
        String serialNumber = UUID.randomUUID().toString().replace("-","");

        HashSet<KeyUsageModel> keyUsages = getKeyUsagesFromCsr(csr);
        List<ExtendedKeyUsageModel> extendedKeyUsages = getExtendedKeyUsagesFromCsr(csr);

        HashSet<ExtendedKeyUsageModel> resolvedExtendedKeyUsages = resolveExtendedKeyUsages(extendedKeyUsages, issuerCertificate);

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
                .extendedKeyUsages(resolvedExtendedKeyUsages)
                .keyUsages(keyUsages)
                .build();

        String issuerWrappedKek = (issuerCertificate.getUsedAdminKek() != null && issuerCertificate.getUsedAdminKek())
                ? adminWrappedKek
                : issuerCertificate.getOrganization().getWrappedKek();
        PrivateKey issuerPrivateKey = keyService.unwrapPrivateKey(issuerCertificate.getWrappedPrivateKey(),
                issuerCertificate.getWrappedDek(),
                issuerWrappedKek);
        X509Certificate x509certificate = generateCertificate(certificate, issuerPrivateKey, false);

        keyStoreWriter.loadKeyStore(keyStoreFilePath,  keystorePassword.toCharArray());
        keyStoreWriter.write(serialNumber, null, null , x509certificate);
        keyStoreWriter.saveKeyStore(keyStoreFilePath,  keystorePassword.toCharArray());

        certificateRepository.save(certificate);
        keyStoreReader.downloadCertificate(x509certificate);

        if(user.getOwnedCertificates() == null)
            user.setOwnedCertificates(new ArrayList<>());
        user.getOwnedCertificates().add(certificate);
        userRepository.save(user);
    }

    private HashSet<KeyUsageModel> getKeyUsagesFromCsr(PKCS10CertificationRequest csr) {
        HashSet<KeyUsageModel> keyUsages = new HashSet<>();

        for (Attribute attr : csr.getAttributes()) {
            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                ASN1Encodable extValue = attr.getAttrValues().getObjectAt(0);
                Extensions extensions = Extensions.getInstance(extValue);

                Extension keyUsageExt = extensions.getExtension(Extension.keyUsage);
                if (keyUsageExt != null) {
                    KeyUsage keyUsage = KeyUsage.getInstance(keyUsageExt.getParsedValue());

                    if (keyUsage.hasUsages(KeyUsage.digitalSignature)) {
                        keyUsages.add(KeyUsageModel.DIGITAL_SIGNATURE);
                    }
                    if (keyUsage.hasUsages(KeyUsage.nonRepudiation)) {
                        keyUsages.add(KeyUsageModel.NON_REPUDIATION);
                    }
                    if (keyUsage.hasUsages(KeyUsage.keyEncipherment)) {
                        keyUsages.add(KeyUsageModel.KEY_ENCIPHERMENT);
                    }
                    if (keyUsage.hasUsages(KeyUsage.dataEncipherment)) {
                        keyUsages.add(KeyUsageModel.DATA_ENCIPHERMENT);
                    }
                    if (keyUsage.hasUsages(KeyUsage.keyAgreement)) {
                        keyUsages.add(KeyUsageModel.KEY_AGREEMENT);
                    }
                    if (keyUsage.hasUsages(KeyUsage.keyCertSign)) {
                        keyUsages.add(KeyUsageModel.KEY_CERT_SIGN);
                    }
                    if (keyUsage.hasUsages(KeyUsage.cRLSign)) {
                        keyUsages.add(KeyUsageModel.CRL_SIGN);
                    }
                }
            }
        }
        return keyUsages;
    }

    private List<ExtendedKeyUsageModel> getExtendedKeyUsagesFromCsr(PKCS10CertificationRequest csr) {
        List<ExtendedKeyUsageModel> extendedKeyUsages = new ArrayList<>();

        for (Attribute attr : csr.getAttributes()) {
            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                ASN1Encodable extValue = attr.getAttrValues().getObjectAt(0);
                Extensions extensions = Extensions.getInstance(extValue);

                Extension ekuExt = extensions.getExtension(Extension.extendedKeyUsage);
                if (ekuExt != null) {
                    ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ekuExt.getParsedValue());

                    for (KeyPurposeId purposeId : eku.getUsages()) {
                        String oid = purposeId.getId();
                        switch (oid) {
                            case "1.3.6.1.5.5.7.3.1":
                                extendedKeyUsages.add(ExtendedKeyUsageModel.SERVER_AUTH);
                                break;
                            case "1.3.6.1.5.5.7.3.2":
                                extendedKeyUsages.add(ExtendedKeyUsageModel.CLIENT_AUTH);
                                break;
                            case "1.3.6.1.5.5.7.3.3":
                                extendedKeyUsages.add(ExtendedKeyUsageModel.CODE_SIGNING);
                                break;
                            case "1.3.6.1.5.5.7.3.4":
                                extendedKeyUsages.add(ExtendedKeyUsageModel.EMAIL_PROTECTION);
                                break;
                            case "1.3.6.1.5.5.7.3.8":
                                extendedKeyUsages.add(ExtendedKeyUsageModel.TIME_STAMPING);
                                break;
                            case "1.3.6.1.5.5.7.3.9":
                                extendedKeyUsages.add(ExtendedKeyUsageModel.OCSP_SIGNING);
                                break;
                        }
                    }
                }
            }
        }
        return extendedKeyUsages;
    }

    private String getFirstSubjectAlternativeName(PKCS10CertificationRequest csr) {
        for (Attribute attr : csr.getAttributes()) {
            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                ASN1Encodable extValue = attr.getAttrValues().getObjectAt(0);
                Extensions extensions = Extensions.getInstance(extValue);

                Extension sanExt = extensions.getExtension(Extension.subjectAlternativeName);
                if (sanExt != null) {
                    GeneralNames gns = GeneralNames.getInstance(sanExt.getParsedValue());
                    for (GeneralName gn : gns.getNames()) {
                        if (gn.getTagNo() == GeneralName.dNSName) {
                            return DERIA5String.getInstance(gn.getName()).getString();
                        }
                    }
                }
            }
        }
        return null; // no SAN found
    }

    private String getRDNValue(X500Name name, ASN1ObjectIdentifier oid) {
        RDN rdn = name.getRDNs(oid).length > 0 ? name.getRDNs(oid)[0] : null;
        return rdn != null ? rdn.getFirst().getValue().toString() : null;
    }

    private X509Certificate generateCertificate(Certificate certificate, PrivateKey issuerPrivateKey, boolean isCa)
            throws CertificateException, OperatorCreationException, CertIOException {

        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC");
        ContentSigner contentSigner = builder.build(issuerPrivateKey);

        X500Name issuerName = certificate.getIssuer().getX500Name();
        BigInteger serial = new BigInteger(certificate.getSerialNumber(), 16);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                issuerName,
                serial,
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
        }

        if(certificate.getKeyUsages() != null && !certificate.getKeyUsages().isEmpty()){
            int keyUsageBits = 0;
            for(KeyUsageModel usage : certificate.getKeyUsages()){
                keyUsageBits |= mapKeyUsage(usage);
            }
            certGen.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(keyUsageBits)
            );
        }

        if (certificate.getExtendedKeyUsages() != null && !certificate.getExtendedKeyUsages().isEmpty()) {
            List<KeyPurposeId> usages = new ArrayList<>();
            for (ExtendedKeyUsageModel usage : certificate.getExtendedKeyUsages()) {
                usages.add(mapExtendedKeyUsage(usage));
            }
            certGen.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    new ExtendedKeyUsage(usages.toArray(new KeyPurposeId[0]))
            );
        }

        if(certificate.getSubject().getAlternativeName()!=null &&
                !certificate.getSubject().getAlternativeName().isEmpty()){
            GeneralName altName = new GeneralName(GeneralName.dNSName, certificate.getSubject().getAlternativeName());
            GeneralNames subjectAltName = new GeneralNames(altName);
            certGen.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
        }

        if(certificate.getIssuer().getAlternativeName()!=null &&
                !certificate.getIssuer().getAlternativeName().isEmpty()){
            GeneralName altName = new GeneralName(GeneralName.dNSName, certificate.getIssuer().getAlternativeName());
            GeneralNames issuerAltName = new GeneralNames(altName);
            certGen.addExtension(Extension.issuerAlternativeName, false, issuerAltName);
        }


        // VAŽNO: ROOT certifikat NE TREBA CDP ekstenziju!
        // Root je self-signed i ne može biti u tuđem CRL-u
        if (certificate.getType() != CertificateType.ROOT) {
            // Za INTERMEDIATE i END_ENTITY: CDP pokazuje na CRL ISSUERA
            Certificate issuerCert = certificateRepository.findFirstBySubject(certificate.getIssuer());

            if (issuerCert == null) {
                throw new IllegalArgumentException(
                        "Issuer certificate not found for CRL DP: " + certificate.getSerialNumber()
                );
            }

            // URL pokazuje na CRL fajl ISSUERA (ne trenutnog sertifikata)
            String crlDpUrl = crlUrl + "/" + issuerCert.getSerialNumber() + ".crl";

            DistributionPointName distPoint = new DistributionPointName(
                    new GeneralNames(
                            new GeneralName(GeneralName.uniformResourceIdentifier, crlDpUrl)
                    )
            );

            DistributionPoint[] distPoints = new DistributionPoint[]{
                    new DistributionPoint(distPoint, null, null)
            };

            certGen.addExtension(
                    Extension.cRLDistributionPoints,
                    false,
                    new CRLDistPoint(distPoints)
            );
        }

        X509CertificateHolder certHolder = certGen.build(contentSigner);
        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");

        return certConverter.getCertificate(certHolder);
    }

    public int mapKeyUsage(KeyUsageModel model){
        return switch (model) {
            case DIGITAL_SIGNATURE -> KeyUsage.digitalSignature;
            case NON_REPUDIATION -> KeyUsage.nonRepudiation;
            case KEY_ENCIPHERMENT -> KeyUsage.keyEncipherment;
            case DATA_ENCIPHERMENT -> KeyUsage.dataEncipherment;
            case KEY_AGREEMENT -> KeyUsage.keyAgreement;
            case KEY_CERT_SIGN -> KeyUsage.keyCertSign;
            case CRL_SIGN -> KeyUsage.cRLSign;
        };
    }

    public KeyPurposeId mapExtendedKeyUsage(ExtendedKeyUsageModel model){
        return switch (model) {
            case SERVER_AUTH -> KeyPurposeId.id_kp_serverAuth;
            case CLIENT_AUTH -> KeyPurposeId.id_kp_clientAuth;
            case CODE_SIGNING -> KeyPurposeId.id_kp_codeSigning;
            case EMAIL_PROTECTION -> KeyPurposeId.id_kp_emailProtection;
            case TIME_STAMPING -> KeyPurposeId.id_kp_timeStamping;
            case OCSP_SIGNING -> KeyPurposeId.id_kp_OCSPSigning;
        };
    }

    boolean checkCertificateChainValidity(CertificateParty issuerParty, Date startDate, Date endDate)
            throws GeneralSecurityException, IOException {

        Certificate issuerCertificate = certificateRepository.findFirstBySubject(issuerParty);
        if(issuerCertificate == null)
            return false;

        X509Certificate x509IssuerCert = (X509Certificate) keyStoreReader.readCertificate(
                keyStoreFilePath, keystorePassword, issuerCertificate.getSerialNumber()
        );

        Instant start = startDate.toInstant();
        Instant end = endDate.toInstant();
        Instant certNotBefore = x509IssuerCert.getNotBefore().toInstant();
        Instant certNotAfter = x509IssuerCert.getNotAfter().toInstant();

        if(certNotBefore.isAfter(start) || certNotAfter.isBefore(end))
            return false;

        if(issuerCertificate.getType() == CertificateType.ROOT) {
            return true;
        }

        Certificate issuerOfIssuer = certificateRepository.findFirstBySubject(issuerCertificate.getIssuer());
        if(issuerOfIssuer == null)
            return false;

        try {
            x509IssuerCert.verify(issuerOfIssuer.getPublicKey());
        } catch (InvalidKeyException | SignatureException e) {
            return false;
        }

        return checkCertificateChainValidity(issuerCertificate.getIssuer(), startDate, endDate);
    }

    private void checkCaPermissions(CertificateParty issuer){
        if(!Objects.equals(userService.getPrimaryRole(), "ca"))
            return;

        List<Certificate> certificates = certificateRepository.findBySubject(issuer);
        if(certificates.isEmpty())
            throw new IllegalArgumentException("Issuer with ID " + issuer.getId() + " not found");
        Certificate certificate = certificates.get(0);
        if(getAllCaCertificates().stream().noneMatch(c -> c.getSerialNumber().equals(certificate.getSerialNumber())))
            throw new IllegalArgumentException("Issuer with ID " + issuer.getId() + " not permitted for logged user");
    }

    public List<GetCertificateDTO> getAllCaCertificates() {
        List<Certificate> certificates = new ArrayList<>();
        if(Objects.equals(userService.getPrimaryRole(), "ca")) {
            for(Certificate ownedCertificate:userService.getLoggedUser().getOwnedCertificates()){
                certificates.addAll(getAllChildCertificates(ownedCertificate));
            }
            certificates.removeIf(c -> c.getType() == CertificateType.END_ENTITY);
        } else {
            certificates = certificateRepository.findByTypeIn(
                    List.of(CertificateType.ROOT, CertificateType.INTERMEDIATE)
            );
        }

        return certificates.stream()
                .map(this::mapToGetCertificateDTO)
                .toList();
    }

    private List<Certificate> getAllChildCertificates(Certificate parent) {
        return getAllChildCertificates(parent, new HashSet<>());
    }

    private List<Certificate> getAllChildCertificates(Certificate parent, Set<String> visited) {
        List<Certificate> result = new ArrayList<>();

        if (!visited.add(parent.getSubject().getId())) {
            return result;
        }

        List<Certificate> directChildren = certificateRepository.findByIssuer(parent.getSubject());

        for (Certificate child : directChildren) {
            result.add(child);
            result.addAll(getAllChildCertificates(child, visited));
        }

        return result;
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

    public List<GetCertificateDTO> getOwnedCertificates() {
        User loggedUser = userService.getLoggedUser();

        List<Certificate> owned = new ArrayList<>(loggedUser.getOwnedCertificates());

        if (Objects.equals(userService.getPrimaryRole(), "ca")) {
            for(Certificate ownedCertificate: loggedUser.getOwnedCertificates()){
                owned.addAll(getAllChildCertificates(ownedCertificate));
            }
        }

        return owned.stream()
                .filter(distinctByKey(Certificate::getSerialNumber))
                .map(this::mapToGetCertificateDTO)
                .toList();
    }

    private GetCertificateDTO mapToGetCertificateDTO(Certificate certificate) {
        if (certificate == null) {
            return null;
        }

        CertificateParty subject = certificate.getSubject();
        CertificateParty issuer = certificate.getIssuer();
        Organization org = certificate.getOrganization();

        boolean revoked = revokedCertificateRepository.existsBySerialNumber(certificate.getSerialNumber());

        return new GetCertificateDTO(
                certificate.getSerialNumber(),
                certificate.getSubject().getId(),

                subject != null ? subject.getCommonName() : null,
                subject != null ? subject.getSurname() : null,
                subject != null ? subject.getGivenName() : null,
                subject != null ? subject.getOrganization() : null,
                subject != null ? subject.getOrganizationalUnit() : null,
                subject != null ? subject.getCountry() : null,
                subject != null ? subject.getEmail() : null,
                subject != null ? subject.getAlternativeName() : null,

                issuer != null ? issuer.getCommonName() : null,
                issuer != null ? issuer.getSurname() : null,
                issuer != null ? issuer.getGivenName() : null,
                issuer != null ? issuer.getOrganization() : null,
                issuer != null ? issuer.getOrganizationalUnit() : null,
                issuer != null ? issuer.getCountry() : null,
                issuer != null ? issuer.getEmail() : null,
                issuer != null ? issuer.getAlternativeName() : null,

                certificate.getType(),
                org != null ? org.getName() : null,
                certificate.getStartDate(),
                certificate.getEndDate(),
                revoked,
                certificate.getKeyUsages().stream().map(KeyUsageModel::name).collect(Collectors.toSet()),
                certificate.getExtendedKeyUsages().stream().map(ExtendedKeyUsageModel::name).collect(Collectors.toSet())
        );
    }

    public Certificate getCertificateBySerialNumber(String serialNumber) {
        return certificateRepository.findFirstBySerialNumber(serialNumber);
    }
}