import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import Keycloak from 'keycloak-js';
import { Observable, from } from 'rxjs';
import { switchMap } from 'rxjs/operators';

export interface KeycloakUser {
  id?: string;
  username: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled: boolean;
  emailVerified?: boolean;
  createdTimestamp?: number;
  attributes?: { [key: string]: string[] }; 
}

export interface CreateUserRequest {
  username: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled: boolean;
  emailVerified?: boolean;
  attributes?: { [key: string]: string[] }; 
  credentials?: Array<{
    type: string;
    value: string;
    temporary: boolean;
  }>;
}

@Injectable({
  providedIn: 'root'
})
export class KeycloakService {
  private keycloak: Keycloak | undefined;
  private readonly baseUrl = 'http://localhost:8080';
  private readonly realm = 'pki';

  constructor(private http: HttpClient) { }

  init(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      this.keycloak = new Keycloak({
        url: this.baseUrl,
        realm: this.realm,
        clientId: 'frontend'
      });

      this.keycloak.init({
        onLoad: 'login-required',
        checkLoginIframe: false,
        pkceMethod: 'S256',
      })
      .then(authenticated => {
        console.log('Keycloak initialized, authenticated:', authenticated);
        if (authenticated && this.keycloak?.tokenParsed) {
          console.log('User roles:', this.getUserRoles());
        }
        resolve(authenticated);
      })
      .catch(err => {
        console.error('Keycloak initialization failed:', err);
        reject(err);
      });
    });
  }

  login() {
    this.keycloak?.login();
  }

  logout() {
    this.keycloak?.logout({ redirectUri: 'http://localhost:4200' });
  }

  isLoggedIn(): boolean {
    return this.keycloak?.authenticated ?? false;
  }

  getToken(): string | undefined {
    return this.keycloak?.token;
  }

  private hasRealmRole(role: string): boolean {
    const token = this.keycloak?.tokenParsed;
    if (token && token['realm_access']) {
      return (token['realm_access']['roles'] || []).includes(role);
    }
    return false;
  }

  private hasClientRole(clientId: string, role: string): boolean {
    const token = this.keycloak?.tokenParsed;
    if (token && token['resource_access'] && token['resource_access'][clientId]) {
      return (token['resource_access'][clientId]['roles'] || []).includes(role);
    }
    return false;
  }

  hasRealmManagementRole(): boolean {
    // Proveri da li ima realm-management client roles
    return this.hasClientRole('realm-management', 'realm-admin') ||
           this.hasClientRole('realm-management', 'manage-users') ||
           this.hasClientRole('realm-management', 'view-users');
  }

  isAdmin(): boolean {
    return this.hasRealmRole('admin') || this.hasRealmManagementRole();
  }

  isCA(): boolean {
    return this.hasRealmRole('ca');
  }

  isUser(): boolean {
    return this.hasRealmRole('user');
  }

  getUserRoles(): string[] {
    const token = this.keycloak?.tokenParsed;
    if (!token) return [];

    let roles: string[] = [];

    if (token['realm_access'] && token['realm_access']['roles']) {
      roles = [...token['realm_access']['roles']];
    }

    return roles;
  }

  private getAdminHeaders(): Observable<HttpHeaders> {
    return from(this.keycloak!.updateToken(30)).pipe(
      switchMap(() => {
        const token = this.getToken();
        return new Observable<HttpHeaders>(observer => {
          observer.next(new HttpHeaders({
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }));
          observer.complete();
        });
      })
    );
  }

  getAllUsers(): Observable<KeycloakUser[]> {
    return this.getAdminHeaders().pipe(
      switchMap(headers => 
        this.http.get<KeycloakUser[]>(
          `${this.baseUrl}/admin/realms/${this.realm}/users`,
          { headers }
        )
      )
    );
  }

  createUser(userRequest: CreateUserRequest): Observable<any> {
    console.log('Creating user:', userRequest);
    return this.getAdminHeaders().pipe(
      switchMap(headers => 
        this.http.post(
          `${this.baseUrl}/admin/realms/${this.realm}/users`,
          userRequest,
          { headers, observe: 'response' }
        )
      )
    );
  }

  deleteUser(userId: string): Observable<any> {
    return this.getAdminHeaders().pipe(
      switchMap(headers => 
        this.http.delete(
          `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}`,
          { headers }
        )
      )
    );
  }

  getUserById(userId: string): Observable<KeycloakUser> {
    return this.getAdminHeaders().pipe(
      switchMap(headers => 
        this.http.get<KeycloakUser>(
          `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}`,
          { headers }
        )
      )
    );
  }

  assignRoleToUser(userId: string, roleName: string): Observable<any> {
    return this.getAdminHeaders().pipe(
      switchMap(headers => {
        return this.http.get<any[]>(
          `${this.baseUrl}/admin/realms/${this.realm}/roles`,
          { headers }
        ).pipe(
          switchMap(roles => {
            const role = roles.find(r => r.name === roleName);
            if (!role) {
              throw new Error(`Role ${roleName} not found`);
            }
            
            return this.http.post(
              `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/role-mappings/realm`,
              [role],
              { headers }
            );
          })
        );
      })
    );
  }

  getUserRolesById(userId: string): Observable<any[]> {
    return this.getAdminHeaders().pipe(
      switchMap(headers => 
        this.http.get<any[]>(
          `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/role-mappings/realm`,
          { headers }
        )
      )
    );
  }

  getAllRoles(): Observable<any[]> {
    return this.getAdminHeaders().pipe(
      switchMap(headers => 
        this.http.get<any[]>(
          `${this.baseUrl}/admin/realms/${this.realm}/roles`,
          { headers }
        )
      )
    );
  }

  setTemporaryPassword(userId: string, password: string): Observable<any> {
    return this.getAdminHeaders().pipe(
      switchMap(headers => 
        this.http.put(
          `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/reset-password`,
          {
            type: 'password',
            value: password,
            temporary: true
          },
          { headers }
        )
      )
    );
  }
  
  sendVerificationEmail(userId: string): Observable<any> {
    return this.getAdminHeaders().pipe(
      switchMap(headers => 
        this.http.put(
          `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/execute-actions-email`,
          ['VERIFY_EMAIL'], 
          { headers }
        )
      )
    );
  }
}