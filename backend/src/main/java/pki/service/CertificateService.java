package pki.service;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
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
import org.springframework.stereotype.Service;
import pki.dto.*;
import org.modelmapper.ModelMapper;
import pki.model.Certificate;
import pki.model.CertificateParty;
import pki.model.CertificateType;
import pki.model.User;
import pki.repository.CertificatePartyRepository;
import pki.repository.CertificateRepository;
import pki.repository.UserRepository;
import pki.util.KeyStoreReader;
import pki.util.KeyStoreWriter;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
public class CertificateService {
    private static String keyStorePassword = "password";
    private static String keyStoreFilePath = "src/main/resources/static/certificates.jks";
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificatePartyRepository certificatePartyRepository;
    @Autowired
    private  KeyStoreReader keyStoreReader;
    @Autowired
    private KeyStoreWriter keyStoreWriter;
    @Autowired
    private UserService userService;
    @Autowired
    private UserRepository userRepository;
    private ModelMapper modelMapper = new ModelMapper();

    public CertificateService(){
        Security.addProvider(new BouncyCastleProvider());
    }

    public void issueRootCertificate(CreateRootCertificateDTO certificateDTO) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, CertIOException {
        CertificateParty subject = modelMapper.map(certificateDTO.getSubject(), CertificateParty.class);
        subject.setId(java.util.UUID.randomUUID().toString());
        KeyPair keyPair = generateKeyPair();
        subject.setPrivateKey(keyPair.getPrivate());
        subject.setPublicKey(keyPair.getPublic());
        subject = certificatePartyRepository.save(subject);

        String serialNumber = UUID.randomUUID().toString().replace("-","");
        X509Certificate x509certificate = generateCertificate(subject, subject, certificateDTO.getStartDate(), certificateDTO.getEndDate(), serialNumber, true);

        keyStoreWriter.loadKeyStore(keyStoreFilePath,  keyStorePassword.toCharArray());
        keyStoreWriter.write(serialNumber, subject.getPrivateKey(), keyStorePassword.toCharArray() , x509certificate);
        keyStoreWriter.saveKeyStore(keyStoreFilePath,  keyStorePassword.toCharArray());

        Certificate certificate = new Certificate(serialNumber, subject, subject, CertificateType.ROOT);
        certificateRepository.save(certificate);
        keyStoreReader.downloadCertificate(x509certificate);
    }

    public void issueIntermediateCertificate(CreateIntermediateCertificateDTO certificateDTO) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, IOException, KeyStoreException {
        CertificateParty issuer = certificatePartyRepository.findById(certificateDTO.getIssuerId())
                .orElseThrow(() -> new IllegalArgumentException("Issuer with ID " + certificateDTO.getIssuerId() + " not found"));

        checkCaPermissions(issuer);

        if(!checkCertificateChainValidity(issuer, certificateDTO.getStartDate(), certificateDTO.getEndDate()))
            throw new IllegalArgumentException("Error validating certificate chain");

        CertificateParty subject = modelMapper.map(certificateDTO.getSubject(), CertificateParty.class);
        subject.setId(java.util.UUID.randomUUID().toString());
        KeyPair keyPair = generateKeyPair();
        subject.setPrivateKey(keyPair.getPrivate());
        subject.setPublicKey(keyPair.getPublic());
        subject = certificatePartyRepository.save(subject);

        String serialNumber = UUID.randomUUID().toString().replace("-","");
        X509Certificate x509certificate = generateCertificate(subject, issuer, certificateDTO.getStartDate(), certificateDTO.getEndDate(), serialNumber, true);

        keyStoreWriter.loadKeyStore(keyStoreFilePath,  keyStorePassword.toCharArray());
        keyStoreWriter.write(serialNumber, subject.getPrivateKey(), keyStorePassword.toCharArray() , x509certificate);
        keyStoreWriter.saveKeyStore(keyStoreFilePath,  keyStorePassword.toCharArray());

        Certificate certificate = new Certificate(serialNumber, subject, issuer, CertificateType.INTERMEDIATE);
        certificateRepository.save(certificate);

        if(Objects.equals(userService.getPrimaryRole(), "ca")){
            User user = userService.getLoggedUser();
            user.getOwnedCertificates().add(certificate);
            userRepository.save(user);
        }
    }

    public void issueEndEntityCertificate(CreateEndEntityCertificateDTO certificateDTO) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, IOException, KeyStoreException {

        CertificateParty issuer = certificatePartyRepository.findById(certificateDTO.getIssuerId())
                .orElseThrow(() -> new IllegalArgumentException("Issuer with ID " + certificateDTO.getIssuerId() + " not found"));

        checkCaPermissions(issuer);

        if(!checkCertificateChainValidity(issuer, certificateDTO.getStartDate(), certificateDTO.getEndDate()))
            throw new IllegalArgumentException("Error validating certificate chain");

        CertificateParty subject = modelMapper.map(certificateDTO.getSubject(), CertificateParty.class);
        subject.setId(java.util.UUID.randomUUID().toString());
        KeyPair keyPair = generateKeyPair();
        subject.setPrivateKey(keyPair.getPrivate());
        subject.setPublicKey(keyPair.getPublic());
        subject = certificatePartyRepository.save(subject);

        String serialNumber = UUID.randomUUID().toString().replace("-","");
        X509Certificate x509certificate = generateCertificate(subject, issuer, certificateDTO.getStartDate(), certificateDTO.getEndDate(), serialNumber, false);

        keyStoreWriter.loadKeyStore(keyStoreFilePath,  keyStorePassword.toCharArray());
        keyStoreWriter.write(serialNumber, subject.getPrivateKey(), keyStorePassword.toCharArray() , x509certificate);
        keyStoreWriter.saveKeyStore(keyStoreFilePath,  keyStorePassword.toCharArray());

        Certificate certificate = new Certificate(serialNumber, subject, issuer, CertificateType.END_ENTITY);
        certificateRepository.save(certificate);

        keyStoreReader.downloadCertificate(x509certificate);

        if(Objects.equals(userService.getPrimaryRole(), "ca") || Objects.equals(userService.getPrimaryRole(), "user")){
            User user = userService.getLoggedUser();
            user.getOwnedCertificates().add(certificate);
            userRepository.save(user);
        }
    }

    public void processCSR(String csrContent, String issuerId, Date startDate, Date endDate) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, OperatorCreationException {
        //TODO: add extensions
        //TODO: decide if this is only for end-entity users
        PemReader pemReader = new PemReader(new StringReader(csrContent));
        byte[] content = pemReader.readPemObject().getContent();

        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(content);

        CertificateParty issuer = certificatePartyRepository.findById(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer with ID " + issuerId + " not found"));

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

        subject.setPublicKey((new JcaPKCS10CertificationRequest(csr)).getPublicKey());

        subject.setId(java.util.UUID.randomUUID().toString());
        subject = certificatePartyRepository.save(subject);

        String serialNumber = UUID.randomUUID().toString().replace("-","");
        X509Certificate x509certificate = generateCertificate(subject, issuer, startDate, endDate, serialNumber, false);

        //TODO: sent certificate to user (it isn't saved in keystore)

        Certificate certificate = new Certificate(serialNumber, subject, issuer, CertificateType.END_ENTITY);
        certificateRepository.save(certificate);

        keyStoreReader.downloadCertificate(x509certificate);
    }

    private  String getRDNValue(X500Name name, ASN1ObjectIdentifier oid) {
        RDN rdn = name.getRDNs(oid).length > 0 ? name.getRDNs(oid)[0] : null;
        return rdn != null ? rdn.getFirst().getValue().toString() : null;
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(2048, random);
        return keyGen.generateKeyPair();
    }

    private X509Certificate generateCertificate(CertificateParty subject, CertificateParty issuer, Date startDate, Date endDate, String serialNumber, boolean isCa) throws CertificateException, OperatorCreationException, CertIOException {
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        builder = builder.setProvider("BC");
        ContentSigner contentSigner = builder.build(issuer.getPrivateKey());

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuer.getX500Name(),
                new BigInteger(serialNumber, 16),
                startDate,
                endDate,
                subject.getX500Name(),
                subject.getPublicKey());

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
        }
        else {
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
        }



        X509CertificateHolder certHolder = certGen.build(contentSigner);

        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
        certConverter = certConverter.setProvider("BC");

        return certConverter.getCertificate(certHolder);
    }

    private boolean checkCertificateChainValidity(CertificateParty issuer, Date startDate, Date endDate) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException { {
        List<Certificate> certificates = certificateRepository.findBySubject(issuer);
        if(certificates.isEmpty())
            return false;
        Certificate certificate = certificates.get(0);
        X509Certificate x509Certificate = (X509Certificate) keyStoreReader.readCertificate(keyStoreFilePath, keyStorePassword, certificate.getSerialNumber());
        try {
            x509Certificate.verify(certificate.getIssuer().getPublicKey());
        } catch (InvalidKeyException | SignatureException e) {
            return false;
        }

        if(x509Certificate.getNotBefore().before(startDate) && x509Certificate.getNotAfter().after(endDate))
            if(certificate.getType()==CertificateType.ROOT)
                return true;
            else
                return checkCertificateChainValidity(certificate.getIssuer(), startDate, endDate);
        return false;
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
        if(Objects.equals(userService.getPrimaryRole(), "ca"))
            certificates = userService.getLoggedUser().getOwnedCertificates().stream().filter(c -> c.getType()!=CertificateType.END_ENTITY).toList();
        else
            certificates = certificateRepository.findByTypeIn(List.of(CertificateType.ROOT, CertificateType.INTERMEDIATE));
        return certificates.stream().map(c -> new GetCertificateDTO(c.getSerialNumber(),c.getSubject().getId(),c.getSubject().getCommonName())).toList();
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
}
