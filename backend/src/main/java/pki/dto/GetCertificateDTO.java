package pki.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class GetCertificateDTO {
    private String issuerId;
    private String issuerCommonName;
}
