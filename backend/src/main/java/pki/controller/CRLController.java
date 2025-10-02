package pki.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pki.model.Certificate;
import pki.model.CertificateType;
import pki.service.CertificateService;
import pki.service.RevocationService;

import java.security.PrivateKey;
import java.security.cert.X509CRL;

@RestController
@RequestMapping("/crl")
@RequiredArgsConstructor
@Slf4j
public class CRLController {

    private final CertificateService certificateService;
    private final RevocationService revocationService;

    /**
     * Download CRL for a specific CA by serial number
     * URL format: /crl/{issuerSerialNumber}
     *
     * Example: /crl/a1b2c3d4e5f6 -> returns the CRL issued by the CA with that serial number
     */
    @GetMapping("/{issuerSerialNumber}")
    public ResponseEntity<byte[]> downloadCRLByIssuer(@PathVariable String issuerSerialNumber) {
        try {
            log.info("CRL download request for issuer serial: {}", issuerSerialNumber);

            Certificate issuerCert = certificateService.getCertificateBySerialNumber(issuerSerialNumber);

            if (issuerCert == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(("Certificate not found: " + issuerSerialNumber).getBytes());
            }

            // check if it is a CA (only CAs can have CRLs)
            if (issuerCert.getType() == CertificateType.END_ENTITY) {
                log.error("Certificate {} is not a CA certificate", issuerSerialNumber);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Only CA certificates can issue CRLs".getBytes());
            }

            PrivateKey issuerPrivateKey = certificateService.getIssuerPrivateKey(issuerCert);

            // generate CRL (or return cached)
            X509CRL crl = revocationService.generateCRL(
                    issuerPrivateKey,
                    issuerCert.getSubject().getX500Name(),
                    issuerCert.getSubject().getId(),
                    issuerCert.getPublicKey()
            );

            byte[] crlBytes = crl.getEncoded();

            log.info("CRL generated successfully for issuer: {}, size: {} bytes",
                    issuerSerialNumber, crlBytes.length);

            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\"" + issuerSerialNumber + ".crl\"")
                    .header("Content-Type", "application/pkix-crl")
                    .header("Cache-Control", "max-age=3600") // Cache for 1 hour
                    .body(crlBytes);

        } catch (Exception e) {
            log.error("Error generating CRL for issuer {}: {}", issuerSerialNumber, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error generating CRL: " + e.getMessage()).getBytes());
        }
    }

    /**
     * Download the ROOT CRL (most common use case)
     * URL: /crl/root
     */
    @GetMapping("/root")
    public ResponseEntity<byte[]> downloadRootCRL() {
        try {
            log.info("Root CRL download request");

            Certificate rootCert = certificateService.getRootCertificate();

            if (rootCert == null) {
                log.error("Root certificate not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("Root certificate not found".getBytes());
            }

            PrivateKey rootPrivateKey = certificateService.getIssuerPrivateKey(rootCert);

            X509CRL crl = revocationService.generateCRL(
                    rootPrivateKey,
                    rootCert.getSubject().getX500Name(),
                    rootCert.getSubject().getId(),
                    rootCert.getPublicKey()
            );

            byte[] crlBytes = crl.getEncoded();

            log.info("Root CRL generated successfully, size: {} bytes", crlBytes.length);

            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\"root.crl\"")
                    .header("Content-Type", "application/pkix-crl")
                    .header("Cache-Control", "max-age=3600")
                    .body(crlBytes);

        } catch (Exception e) {
            log.error("Error generating root CRL: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error generating root CRL: " + e.getMessage()).getBytes());
        }
    }
}
