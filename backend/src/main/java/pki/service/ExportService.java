package pki.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pki.dto.certificate.DownloadCertificateDTO;
import pki.model.Certificate;
import pki.model.CertificateParty;
import pki.model.CertificateType;
import pki.model.User;
import pki.repository.CertificateRepository;
import pki.util.KeyStoreExporter;
import pki.util.KeyStoreReader;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ExportService {
    private final UserService userService;
    @Value("${app.admin-wrapped-kek}")
    private String adminWrappedKek;
    @Value("${app.certificate-keystore-path}")
    private String keyStoreFilePath;
    @Value("${app.certificate-keystore-password}")
    private String keystorePassword;

    private final String certificateAlias = "certificate";

    private final KeyService keyService;
    private final KeyStoreReader keyStoreReader;
    private final CertificateRepository certificateRepository;

    public DownloadCertificateDTO exportCertificate(String serialNumber) throws GeneralSecurityException, IOException {
        Certificate certificate = certificateRepository.findFirstBySerialNumber(serialNumber);
        if (certificate == null)
            throw new IllegalArgumentException("Certificate with serial number " + serialNumber + " not found");

        if(!checkCertificateChainValidity(certificate.getSubject(),
                certificate.getStartDate(), certificate.getEndDate()))
            throw new IllegalArgumentException("Error validating certificate chain");

        // check if user has permission to export certificate
        User user = userService.getLoggedUser();
        if (user == null)
            throw new IllegalArgumentException("Unauthorized");
        if(!userService.getPrimaryRole().equals("admin")) {
            List<Certificate> ownedCertificates = user.getOwnedCertificates();
            if (!checkCertificatePermission(certificate, ownedCertificates))
                throw new IllegalArgumentException("Forbidden");
        }

        String wrappedKek = (certificate.getUsedAdminKek() != null && certificate.getUsedAdminKek())
                ? adminWrappedKek
                : certificate.getOrganization().getWrappedKek();
        PrivateKey privateKey = keyService.unwrapPrivateKey(certificate.getWrappedPrivateKey(),
                certificate.getWrappedDek(),
                wrappedKek);
        String newPassword = generatePassword();

        java.security.cert.Certificate[] certificateChain = keyStoreReader.readCertificateChain(
                keyStoreFilePath, keystorePassword, certificate.getSerialNumber());

        byte[] pkcs12Keystore = KeyStoreExporter.createPkcs12Keystore(privateKey, certificateChain,
                certificateAlias, newPassword.toCharArray());
        String pkcs12KeystoreBase64 = Base64.getEncoder().encodeToString(pkcs12Keystore);

        return new DownloadCertificateDTO(certificateAlias, newPassword, pkcs12KeystoreBase64);
    }

    private String generatePassword() {
        SecureRandom random = new SecureRandom();
        byte[] passwordBytes = new byte[24];
        random.nextBytes(passwordBytes);
        return Base64.getEncoder().encodeToString(passwordBytes);
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

    public boolean checkCertificatePermission(Certificate certificate, List<Certificate> ownedCertificates) {
        if(ownedCertificates.stream().anyMatch(c -> c.getSerialNumber().equals(certificate.getSerialNumber())))
            return true;
        if (certificate.getType()==CertificateType.ROOT)
            return false;
        Certificate issuerCertificate = certificateRepository.findFirstBySubject(certificate.getIssuer());
        if(issuerCertificate == null)
            return false;
        return checkCertificatePermission(issuerCertificate, ownedCertificates);
    }
}
