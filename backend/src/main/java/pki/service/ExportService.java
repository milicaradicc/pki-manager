package pki.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pki.dto.certificate.DownloadCertificateDTO;
import pki.model.Certificate;
import pki.model.User;
import pki.repository.CertificateRepository;
import pki.util.KeyStoreExporter;
import pki.util.KeyStoreReader;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Base64;
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
    private final CertificateService certificateService;

    public DownloadCertificateDTO exportCertificate(String serialNumber) throws GeneralSecurityException, IOException {
        Certificate certificate = certificateRepository.findFirstBySerialNumber(serialNumber);
        if (certificate == null)
            throw new IllegalArgumentException("Certificate with serial number " + serialNumber + " not found");

        if(!certificateService.checkCertificateChainValidity(certificate.getSubject(),
                certificate.getStartDate(), certificate.getEndDate()))
            throw new IllegalArgumentException("Error validating certificate chain");

        // check if user has permission to export certificate
        User user = userService.getLoggedUser();
        if (user == null)
            throw new IllegalArgumentException("Unauthorized");
        if(!userService.getPrimaryRole().equals("admin")) {
            List<Certificate> ownedCertificates = user.getOwnedCertificates();
            if (!certificateService.checkCertificatePermission(certificate, ownedCertificates))
                throw new IllegalArgumentException("Forbidden");
        }

        String wrappedKek = certificate.getOrganization() != null ? certificate.getOrganization().getWrappedKek() : adminWrappedKek;
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
}
