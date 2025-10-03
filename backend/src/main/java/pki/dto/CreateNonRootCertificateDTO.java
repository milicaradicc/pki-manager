package pki.dto;

import lombok.Getter;
import lombok.Setter;
import pki.model.ExtendedKeyUsageModel;

import java.util.Date;
import java.util.List;

@Getter
@Setter
public class CreateNonRootCertificateDTO {
    private String issuerId;
    private CreateCertificatePartyDTO subject;
    private Date startDate;
    private Date endDate;
    private List<ExtendedKeyUsageModel> extendedKeyUsages;
}
