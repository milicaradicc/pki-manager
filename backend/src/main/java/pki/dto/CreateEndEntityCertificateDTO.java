package pki.dto;

import lombok.Getter;
import lombok.Setter;
import pki.model.KeyUsageModel;

import java.util.Date;
import java.util.List;

@Getter
@Setter
public class CreateEndEntityCertificateDTO extends CreateNonRootCertificateDTO {
    private List<KeyUsageModel> keyUsages;
}
