package pki.dto.certificate;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class DownloadCertificateDTO {
    private String alias;
    private String keystorePassword;
    private String pkcs12Keystore;
}
