package pki.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import pki.model.CertificateType;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GetCertificateDTO {
    private String serialNumber;
    private String subjectId;

    // CertificateParty subject
    private String subjectCommonName;
    private String subjectSurname;
    private String subjectGivenName;
    private String subjectOrganization;
    private String subjectOrganizationalUnit;
    private String subjectCountry;
    private String subjectEmail;

    // CertificateParty issuer
    private String issuerCommonName;
    private String issuerSurname;
    private String issuerGivenName;
    private String issuerOrganization;
    private String issuerOrganizationalUnit;
    private String issuerCountry;
    private String issuerEmail;

    private CertificateType type;

    // Organization
    private String organizationName;

    private Date validFrom;
    private Date validTo;

    private boolean revoked;
}
