package pki.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateCertificatePartyDTO {
    private String commonName;
    private String surname;
    private String givenName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;
}
