package pki.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RevocationStatusDTO {
    private String serialNumber;
    private boolean revoked;
    private Date revocationDate;
    private String reason;
}