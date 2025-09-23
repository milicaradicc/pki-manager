import { Injectable } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {KeycloakService} from '../../core/keycloak/keycloak.service';
import {Observable} from 'rxjs';
import {User} from '../users/user.service';
import {CreateRootCertificateDTO} from './models/create-root-certificate-dto.model';
import {GetCertificateDto} from './models/get-certificate-dto.model';
import {CreateIntermediateComponent} from './create-intermediate/create-intermediate.component';
import {CreateIntermediateCertificateDTO} from './models/create-intermediate-cetrificate-dto.model';

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  private baseUrl = 'http://localhost:8081/certificates';

  constructor(private http: HttpClient) {}

  createRootCertificate(dto:CreateRootCertificateDTO): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/root`,dto);
  }

  createIntermediateCertificate(dto:CreateIntermediateCertificateDTO): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/intermediate`,dto);
  }

  createEndEntityCertificate(dto:CreateIntermediateCertificateDTO): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/end-entity`,dto);
  }

  getAllCaCertificates(): Observable<GetCertificateDto[]> {
    return this.http.get<GetCertificateDto[]>(`${this.baseUrl}/ca`);
  }
}
