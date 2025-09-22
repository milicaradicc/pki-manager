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
  private baseUrl = 'http://localhost:8081/user';

  constructor(private http: HttpClient, private keycloak: KeycloakService) {}

  getUserProfile(): Observable<User> {
    return this.http.get<User>(`${this.baseUrl}/profile`);
  }

  getUserRole(): Observable<any> {
    if (this.keycloak.isAdmin()) return of('admin');
    if (this.keycloak.isCA()) return of('ca');
    if (this.keycloak.isUser()) return of('user');
    return of(null); 
  }
}

