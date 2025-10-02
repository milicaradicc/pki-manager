export interface GetCertificateDto {
  serialNumber: string;

  // Subject
  subjectCommonName: string;
  subjectSurname: string;
  subjectGivenName: string;
  subjectOrganization: string;
  subjectOrganizationalUnit: string;
  subjectCountry: string;
  subjectEmail: string;

  // Issuer
  issuerCommonName: string;
  issuerSurname: string;
  issuerGivenName: string;
  issuerOrganization: string;
  issuerOrganizationalUnit: string;
  issuerCountry: string;
  issuerEmail: string;

  type: 'ROOT' | 'INTERMEDIATE' | 'END_ENTITY';

  organizationName: string;

  validFrom: string;
  validTo: string;

  revoked: boolean;  
}
