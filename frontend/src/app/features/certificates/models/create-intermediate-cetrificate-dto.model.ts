import {CreateCertificatePartyDTO} from './create-certificate-party.model';

export interface CreateIntermediateCertificateDTO {
  issuerId: string;
  subject:CreateCertificatePartyDTO;
  startDate:string;
  endDate:string;
}
