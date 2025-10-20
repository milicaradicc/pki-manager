import { RevocationReason } from './revocation-reason.model';

export interface RevokeCertificateDTO {
  serialNumber: string;
  reason: string;
}
