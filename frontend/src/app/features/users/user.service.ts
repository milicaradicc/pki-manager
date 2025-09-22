// import { Injectable, signal } from '@angular/core';
// import { HttpClient, HttpHeaders } from '@angular/common/http';
// import { Observable } from 'rxjs';
// import { KeycloakService } from '../../core/keycloak/keycloak.service';

// export interface User {
//   id: number;
//   keycloakId: string;
//   email: string;
//   firstname: string;
//   lastname: string;
//   organization?: string;
// }

// @Injectable({
//   providedIn: 'root'
// })
// export class UserService {
//   private baseUrl = 'http://localhost:8081/user';

//   constructor(private http: HttpClient, private keycloak: KeycloakService) {}

//   getUserProfile(): Observable<User> {
//     const token = this.keycloak.getToken();
//     const headers = new HttpHeaders({
//       Authorization: `Bearer ${token}`
//     });
//     return this.http.get<User>(`${this.baseUrl}/profile`, { headers });
//   }
// }

import { Injectable, signal } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { KeycloakService } from '../../core/keycloak/keycloak.service';

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

