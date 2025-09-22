import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import Keycloak from 'keycloak-js';
import { Observable } from 'rxjs';
import { KeycloakUser } from '../../features/users/models/key-cloakuser.model';
import { CreateUserRequest } from '../../features/users/models/create-user-request.model';
import { switchMap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class KeycloakService {
  private keycloak: Keycloak | undefined;
  private readonly baseUrl = 'https://localhost:9443';
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
        checkLoginIframe: true,
        pkceMethod: 'S256',
      })
      .then(authenticated => resolve(authenticated))
      .catch(err => reject(err));
    });
  }

  login() { this.keycloak?.login(); }
  logout() { this.keycloak?.logout({ redirectUri: 'https://localhost:4200' }); }
  isLoggedIn(): boolean { return this.keycloak?.authenticated ?? false; }
  getToken(): string | undefined { return this.keycloak?.token; }

  async updateTokenIfNeeded(): Promise<void> {
    if (!this.keycloak) return;
    await this.keycloak.updateToken(30);
  }

  getAllUsers(): Observable<KeycloakUser[]> {
    return this.http.get<KeycloakUser[]>(`${this.baseUrl}/admin/realms/${this.realm}/users`);
  }

  createUser(userRequest: CreateUserRequest): Observable<any> {
    return this.http.post(`${this.baseUrl}/admin/realms/${this.realm}/users`, userRequest, { observe: 'response' });
  }

  deleteUser(userId: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/admin/realms/${this.realm}/users/${userId}`);
  }

  getUserById(userId: string): Observable<KeycloakUser> {
    return this.http.get<KeycloakUser>(`${this.baseUrl}/admin/realms/${this.realm}/users/${userId}`);
  }

  assignRoleToUser(userId: string, roleName: string): Observable<any> {
    return this.http.get<any[]>(`${this.baseUrl}/admin/realms/${this.realm}/roles`).pipe(
      switchMap(roles => {
        const role = roles.find(r => r.name === roleName);
        if (!role) throw new Error(`Role ${roleName} not found`);
        return this.http.post(`${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/role-mappings/realm`, [role]);
      })
    );
  }

  getUserRolesById(userId: string): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/role-mappings/realm`);
  }

  getAllRoles(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/admin/realms/${this.realm}/roles`);
  }

  setTemporaryPassword(userId: string, password: string): Observable<any> {
    return this.http.put(`${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/reset-password`, {
      type: 'password',
      value: password,
      temporary: true
    });
  }

  sendVerificationEmail(userId: string): Observable<any> {
    return this.http.put(`${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/execute-actions-email`,
      ['VERIFY_EMAIL', 'UPDATE_PASSWORD']);
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

  private hasRealmManagementRole(): boolean {
    return this.hasClientRole('realm-management', 'realm-admin') ||
          this.hasClientRole('realm-management', 'manage-users') ||
          this.hasClientRole('realm-management', 'view-users');
  }
  getUserRoles(): string[] {
    const token = this.keycloak?.tokenParsed;
    if (!token) return [];

    return token['realm_access']?.roles || [];
  }
}
