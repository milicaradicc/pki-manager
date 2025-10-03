import {CreateCertificatePartyDTO} from './create-certificate-party.model';
import {ExtendedKeyUsageType} from './ExtendedKeyUsage';

export interface CreateIntermediateCertificateDTO {
  issuerId: string;
  subject:CreateCertificatePartyDTO;
  startDate:string;
  endDate:string;
  extendedKeyUsages:ExtendedKeyUsageType[];
}
