package pki.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.PublicKey;
import java.util.Date;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Certificate {
    @Id
    private String serialNumber;
    @ManyToOne
    private CertificateParty subject;
    @ManyToOne
    private CertificateParty issuer;
    private CertificateType type;

    private PublicKey publicKey;
    private String wrappedPrivateKey;
    private String wrappedDek;

    private Date startDate;
    private Date endDate;

//    private boolean revoked;
//    private String revocationReason;
//    private String revocationDate;
}
