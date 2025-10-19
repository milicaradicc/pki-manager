package pki.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pki.service.RevocationService;

@RestController
@RequestMapping("/api/crl")
public class CRLController {

    private RevocationService revocationService;

    @GetMapping("/{issuerSerialNumber}.crl")
    public ResponseEntity<byte[]> getCRL(@PathVariable String issuerSerialNumber) {
        try {
            byte[] crlBytes = revocationService.getOrGenerateCRL(issuerSerialNumber);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, "application/pkix-crl")
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + issuerSerialNumber + ".crl\"")
                    .body(crlBytes);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }
}