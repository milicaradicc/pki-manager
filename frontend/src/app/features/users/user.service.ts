import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { KeycloakService } from '../../core/keycloak/keycloak.service';
import { of, Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { CaUserDto } from './models/ca-user.dto';

export interface User {
  id: number;
  keycloakId: string;
  email: string;
  firstname: string;
  lastname: string;
  organization?: string;
}

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private baseUrl = environment.backend + 'user';

  constructor(private http: HttpClient, private keycloak: KeycloakService) {}

  getUserProfile(): Observable<User> {
    return this.http.get<User>(`${this.baseUrl}/profile`);
  }

  getAllCaUsers(): Observable<CaUserDto[]> {
    return this.http.get<CaUserDto[]>(`${this.baseUrl}/ca`);
  }
}

