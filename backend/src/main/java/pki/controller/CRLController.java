package pki.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pki.model.Certificate;
import pki.service.CertificateService;
import pki.service.RevocationService;

import java.security.PrivateKey;
import java.security.cert.X509CRL;

@RestController
@RequestMapping("/crl")
@RequiredArgsConstructor
public class CRLController {

    private final CertificateService certificateService;
    private final RevocationService revocationService;

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadCRL() throws Exception {
        // root ili intermediate sertifikat koji potpisuje CRL
        Certificate rootCert = certificateService.getRootCertificate();
        PrivateKey privateKey = certificateService.getIssuerPrivateKey(rootCert);

        X509CRL crl = revocationService.generateCRL(privateKey, rootCert.getSubject().getX500Name());
        byte[] crlBytes = crl.getEncoded();

        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"crl.crl\"")
                .body(crlBytes);
    }
}
