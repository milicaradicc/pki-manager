import {CreateCertificatePartyDTO} from './create-certificate-party.model';
import {ExtendedKeyUsageType} from './ExtendedKeyUsage';
import {KeyUsageType} from './KeyUsage';

export interface CreateEndEntityCertificateDTO {
  issuerId: string;
  subject:CreateCertificatePartyDTO;
  startDate:string;
  endDate:string;
  extendedKeyUsages:ExtendedKeyUsageType[];
  keyUsages:KeyUsageType[];
}
