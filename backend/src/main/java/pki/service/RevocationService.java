package pki.service;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import pki.model.RevokedCertificate;
import pki.repository.RevokedCertificateRepository;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RevocationService {

    private final RevokedCertificateRepository revokedCertificateRepository;

    public X509CRL generateCRL(PrivateKey issuerPrivateKey, org.bouncycastle.asn1.x500.X500Name issuerX500Name) throws Exception {
        Date now = new Date();
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerX500Name, now);

        List<RevokedCertificate> revokedCertificates = revokedCertificateRepository.findAll();
        for (RevokedCertificate rc : revokedCertificates) {
            int reasonCode = rc.getReasonCode().ordinal();
            crlBuilder.addCRLEntry(new BigInteger(rc.getSerialNumber(), 16), rc.getRevokedAt(), reasonCode);
        }


        // for (RevokedCertificate rc : revokedCertificates) {
        //     BigInteger serial = new BigInteger(rc.getSerialNumber(), 16);
        //     Date revokedAt = rc.getRevokedAt();
        //     int reasonCode = rc.getReasonCode().ordinal(); // integer kod razloga
        //
        //     crlBuilder.addCRLEntry(serial, revokedAt, reasonCode); // int kod
        // }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(issuerPrivateKey);
        return new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));
    }
}
