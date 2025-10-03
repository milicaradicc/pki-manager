export interface DownloadCertificateDTO {
  alias: string;
  keystorePassword: string;
  pkcs12Keystore: string;
  withPrivateKey: boolean;
  serialNumber: string;
}