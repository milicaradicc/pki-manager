import { Injectable } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {CreateRootCertificateDTO} from './models/create-root-certificate-dto.model';
import {GetCertificateDto} from './models/get-certificate-dto.model';
import {CreateIntermediateCertificateDTO} from './models/create-intermediate-cetrificate-dto.model';
import { environment } from '../../../environments/environment';
import { AssignCertificateDTO } from './models/assign-certificate.model';
import { DownloadCertificateDTO } from './models/download-certificate.model';
import { CreateEndEntityCertificateDTO } from './models/create-end-entity-dto.model';

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  private baseUrl = `${environment.backend}certificates`;

  constructor(private http: HttpClient) {}

  createRootCertificate(dto: CreateRootCertificateDTO): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/root`, dto);
  }

  createIntermediateCertificate(dto: CreateIntermediateCertificateDTO): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/intermediate`, dto);
  }

  createEndEntityCertificate(dto: CreateEndEntityCertificateDTO): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/end-entity`, dto);
  }

  sendCSR(formData: FormData): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/csr`, formData);
  }

  getAllCaCertificates(): Observable<GetCertificateDto[]> {
    return this.http.get<GetCertificateDto[]>(`${this.baseUrl}/ca`);
  }

  getAllCertificates(): Observable<GetCertificateDto[]> {
    return this.http.get<GetCertificateDto[]>(this.baseUrl);
  }

  getOwnedCertificates(includeEndEntity: boolean = true): Observable<GetCertificateDto[]> {
    return this.http.get<GetCertificateDto[]>(`${this.baseUrl}/owned?includeEndEntity=${includeEndEntity}`);
  }

  assignCertificate(dto: AssignCertificateDTO): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/assign-ca-user`, dto);
  }

  revokeCertificate(serial: string, reason: string): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/${serial}/revoke`, { reason });
  }

  downloadCertificate(serialNumber:string): Observable<DownloadCertificateDTO> {
    return this.http.get<DownloadCertificateDTO>(`${this.baseUrl}/${serialNumber}/download`);
  }
}
