import {CreateCertificatePartyDTO} from './create-certificate-party.model';

export interface CreateEndEntityCertificateDTO {
  issuerId: string;
  subject:CreateCertificatePartyDTO;
  startDate:string;
  endDate:string;
}
