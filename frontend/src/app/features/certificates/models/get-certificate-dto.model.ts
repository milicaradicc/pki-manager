import { ExtendedKeyUsageType } from "./ExtendedKeyUsage";

export interface GetCertificateDto {
  serialNumber: string;
  subjectId: string;

  // Subject
  subjectCommonName: string;
  subjectSurname: string;
  subjectGivenName: string;
  subjectOrganization: string;
  subjectOrganizationalUnit: string;
  subjectCountry: string;
  subjectEmail: string;
  subjectAlternativeName: string;
  

  // Issuer
  issuerCommonName: string;
  issuerSurname: string;
  issuerGivenName: string;
  issuerOrganization: string;
  issuerOrganizationalUnit: string;
  issuerCountry: string;
  issuerEmail: string;
  issuerAlternativeName: string;

  type: 'ROOT' | 'INTERMEDIATE' | 'END_ENTITY';

  organizationName: string;

  validFrom: string;
  validTo: string;

  revoked: boolean;  

  keyUsages: string[];
  extendedKeyUsages: string[];
}
