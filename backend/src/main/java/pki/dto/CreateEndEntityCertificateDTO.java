package pki.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class CreateEndEntityCertificateDTO {
    private String issuerId;
    private CreateCertificatePartyDTO subject;
    private Date startDate;
    private Date endDate;
}
