package pki.service;

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pki.dto.*;
import org.modelmapper.ModelMapper;
import pki.model.Certificate;
import pki.model.CertificateParty;
import pki.model.CertificateType;
import pki.repository.CertificatePartyRepository;
import pki.repository.CertificateRepository;
import pki.util.KeyStoreReader;
import pki.util.KeyStoreWriter;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
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
        //TODO if ca is logged in check if it has permission for issuer cert

        CertificateParty issuer = certificatePartyRepository.findById(certificateDTO.getIssuerId())
                .orElseThrow(() -> new IllegalArgumentException("Issuer with ID " + certificateDTO.getIssuerId() + " not found"));
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

        //TODO if ca user add to owned certificates
    }

    public void issueEndEntityCertificate(CreateEndEntityCertificateDTO certificateDTO) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, IOException, KeyStoreException {
        //TODO if ca is logged in check if it has permission for issuer cert

        CertificateParty issuer = certificatePartyRepository.findById(certificateDTO.getIssuerId())
                .orElseThrow(() -> new IllegalArgumentException("Issuer with ID " + certificateDTO.getIssuerId() + " not found"));
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

        //TODO if ca user add to owned certificates
        //TODO if ordinary user add to owned certificates
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
            x509Certificate.verify(issuer.getPublicKey());
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


}
