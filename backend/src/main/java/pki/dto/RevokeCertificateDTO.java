package pki.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import pki.model.RevocationReason;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RevokeCertificateDTO {

    @NotBlank(message = "Serial number is required")
    private String serialNumber;

    @NotNull(message = "Revocation reason is required")
    private String reason;
}