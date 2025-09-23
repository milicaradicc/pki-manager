package pki.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class GetUserDTO {
    private Integer id;
    private String keycloakId;
    private String email;
    private String firstname;
    private String lastname;
    private String organization;
}
