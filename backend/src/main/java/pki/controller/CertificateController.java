package pki.controller;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import pki.dto.*;
import pki.model.RevocationReason;
import pki.model.User;
import pki.service.CertificateService;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/certificates")
@RequiredArgsConstructor
public class CertificateController {
    private final CertificateService certificateService;

    @PreAuthorize("hasAuthority('ROLE_admin')")
    @PostMapping("/root")
    public ResponseEntity<Void> issueRootCertificate(@RequestBody CreateRootCertificateDTO certificateDTO) throws ParseException, GeneralSecurityException, OperatorCreationException, CertIOException {
        certificateService.issueRootCertificate(certificateDTO);
        return ResponseEntity.ok( null );
    }

    @PreAuthorize("hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @PostMapping("/intermediate")
    public ResponseEntity<Void> issueIntermediateCertificate(@RequestBody CreateIntermediateCertificateDTO certificateDTO) throws ParseException, GeneralSecurityException, OperatorCreationException, IOException {
        certificateService.issueIntermediateCertificate(certificateDTO);
        return ResponseEntity.ok( null );
    }

    @PreAuthorize("hasAuthority('ROLE_user') or hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @PostMapping("/end-entity")
    public ResponseEntity<Void> issueEndEntityCertificate(@RequestBody CreateEndEntityCertificateDTO certificateDTO) throws ParseException, GeneralSecurityException, OperatorCreationException, IOException {
        certificateService.issueEndEntityCertificate(certificateDTO);
        return ResponseEntity.ok( null );
    }

    @PreAuthorize("hasAuthority('ROLE_user') or hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @PostMapping("/csr")
    public ResponseEntity<?> processCSR(
            @RequestParam("csrFile") MultipartFile csrFile,
            @RequestParam("issuerId") String issuerId,
            @RequestParam("startDate") String startDate,
            @RequestParam("endDate") String endDate
    ) throws IOException, ParseException, GeneralSecurityException, OperatorCreationException {
        Date start = new SimpleDateFormat("yyyy-MM-dd").parse(startDate);
        Date end = new SimpleDateFormat("yyyy-MM-dd").parse(endDate);
        String csrContent = new String(csrFile.getBytes());
        certificateService.processCSR(csrContent, issuerId, start, end);
        return ResponseEntity.ok(null);
    }

    @PreAuthorize("hasAuthority('ROLE_user') or hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @GetMapping("/ca")
    public ResponseEntity<List<GetCertificateDTO>> getAllCaCertificates() throws ParseException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertIOException {
        List<GetCertificateDTO> certificates = certificateService.getAllCaCertificates();
        return ResponseEntity.ok( certificates );
    }

    @PreAuthorize("hasAuthority('ROLE_admin')")
    @PostMapping("/assign-ca-user")
    public ResponseEntity<Void> assignCaUser(@RequestBody AssignCertificateDTO assignCertificateDTO) throws ParseException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertIOException {
        certificateService.assignCaUser(assignCertificateDTO);
        return ResponseEntity.ok( null );
    }
    @PreAuthorize("hasAuthority('ROLE_admin')")
    @GetMapping
    public ResponseEntity<List<GetCertificateDTO>> getAllCertificates() {
        List<GetCertificateDTO> certificates = certificateService.getAllCertificates();
        return ResponseEntity.ok(certificates);
    }

    @PostMapping("/{serial}/revoke")
    public ResponseEntity<Void> revokeCertificate(
            @PathVariable String serial,
            @RequestBody RevokeReasonDTO dto
    ) {
        // Konvertuj string iz DTO u enum
        RevocationReason reason = RevocationReason.valueOf(dto.getREASON().toUpperCase());

        // Pozovi servis sa enumom (ako servis prima enum)
        certificateService.revokeCertificate(serial, reason);

        return ResponseEntity.ok().build();
    }
}
