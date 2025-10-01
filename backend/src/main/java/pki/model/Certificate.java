package pki.model;

import jakarta.persistence.*;
import lombok.*;

import java.security.PublicKey;
import java.util.Date;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Certificate {
    @Id
    private String serialNumber;
    @ManyToOne
    private CertificateParty subject;
    @ManyToOne
    private CertificateParty issuer;
    private CertificateType type;
    @ManyToOne
    private Organization organization;

    private PublicKey publicKey;
    @Column(columnDefinition = "TEXT")
    private String wrappedPrivateKey;
    private String wrappedDek;

    private Date startDate;
    private Date endDate;
}
