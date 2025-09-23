import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { KeycloakService } from '../../core/keycloak/keycloak.service';
import { of, Observable } from 'rxjs';

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
  private baseUrl = 'https://localhost:8443/user';

  constructor(private http: HttpClient, private keycloak: KeycloakService) {}

  getUserProfile(): Observable<User> {
    return this.http.get<User>(`${this.baseUrl}/profile`);
  }
}

