import { Injectable } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {KeycloakService} from '../../core/keycloak/keycloak.service';
import {Observable} from 'rxjs';
import {User} from '../users/user.service';
import {CreateRootCertificateDTO} from './models/create-root-certificate-dto.model';

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  private baseUrl = 'http://localhost:8081/certificates';

  constructor(private http: HttpClient) {}

  createRootCertificate(dto:CreateRootCertificateDTO): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/root`,dto);
  }
}
