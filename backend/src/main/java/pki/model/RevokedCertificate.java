package pki.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class RevokedCertificate {
    @Id
    private String id;
    private String serialNumber;

    @Enumerated(EnumType.STRING)
    private RevocationReason reasonCode;

    private Date revokedAt;
    private String issuerId;
}
