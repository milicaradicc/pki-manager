package pki.controller;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import pki.dto.*;
import pki.model.User;
import pki.service.CertificateService;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/certificates")
public class CertificateController {
    @Autowired
    private CertificateService certificateService;

    @PreAuthorize("hasAuthority('ROLE_user') or hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @PostMapping("/root")
    public ResponseEntity<Void> issueRootCertificate(@RequestBody CreateRootCertificateDTO certificateDTO) throws ParseException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertIOException {
        certificateService.issueRootCertificate(certificateDTO);
        return ResponseEntity.ok( null );
    }

    @PreAuthorize("hasAuthority('ROLE_user') or hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @PostMapping("/intermediate")
    public ResponseEntity<Void> issueIntermediateCertificate(@RequestBody CreateIntermediateCertificateDTO certificateDTO) throws ParseException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, IOException, KeyStoreException {
        certificateService.issueIntermediateCertificate(certificateDTO);
        return ResponseEntity.ok( null );
    }

    @PreAuthorize("hasAuthority('ROLE_user') or hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @PostMapping("/end-entity")
    public ResponseEntity<Void> issueEndEntityCertificate(@RequestBody CreateEndEntityCertificateDTO certificateDTO) throws ParseException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertIOException {
        certificateService.issueEndEntityCertificate(certificateDTO);
        return ResponseEntity.ok( null );
    }

    @PreAuthorize("hasAuthority('ROLE_user') or hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @GetMapping("/ca")
    public ResponseEntity<List<GetCertificateDTO>> getAllCaCertificates() throws ParseException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertIOException {
        List<GetCertificateDTO> certificates = certificateService.getAllCaCertificates();
        return ResponseEntity.ok( certificates );
    }
}
