package pki.controller;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import pki.dto.CreateCertificatePartyDTO;
import pki.dto.CreateRootCertificateDTO;
import pki.model.User;
import pki.service.CertificateService;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@RestController
@RequestMapping("/certificates")
public class CertificateController {
    @Autowired
    private CertificateService certificateService;

    @PreAuthorize("hasAuthority('ROLE_user') or hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @PostMapping("/root")
    public ResponseEntity<Void> getUserProfile(@RequestBody CreateRootCertificateDTO certificateDTO) throws ParseException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertIOException {
        CreateCertificatePartyDTO party = new CreateCertificatePartyDTO();
        certificateService.issueRootCertificate(certificateDTO);
        return ResponseEntity.ok( null );
    }
}
