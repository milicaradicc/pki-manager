import {CreateCertificatePartyDTO} from './create-certificate-party.model';

export interface CreateRootCertificateDTO {
  subject:CreateCertificatePartyDTO;
  startDate:string;
  endDate:string;
}
