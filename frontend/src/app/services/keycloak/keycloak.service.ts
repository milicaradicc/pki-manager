import { Injectable } from '@angular/core';
import Keycloak from 'keycloak-js';

@Injectable({
  providedIn: 'root'
})
export class KeycloakService {
  private keycloak: Keycloak | undefined;

  constructor() { }

  init(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      this.keycloak = new Keycloak({
        url: 'http://localhost:8080/',
        realm: 'pki',
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
          console.log('Dekodovan JWT  parsed:', this.keycloak.tokenParsed);
          console.log('Refresh parsed:', this.keycloak.refreshToken);
          console.log('Access parsed:', this.keycloak.token);
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
    console.log("Logout pozvan");
    this.keycloak?.logout({ redirectUri: 'http://localhost:4200' });
  }

  isLoggedIn(): boolean {
    return this.keycloak?.authenticated ?? false;
  }

  getToken(): string | undefined {
    return this.keycloak?.token;
  }

  hasRole(role: string): boolean {
    const token = this.keycloak?.tokenParsed;
    console.log('Checking realm role:', role, 'Token:', token);
    
    if (token && token['realm_access']) {
      const roles = token['realm_access']['roles'] || [];
      console.log('Available realm roles:', roles);
      return roles.includes(role);
    }
    return false;
  }


  isAdmin(): boolean {
    return this.hasRole('admin');
  }

  isCA(): boolean {
    return this.hasRole('ca');
  }

  isUser(): boolean {
    return this.hasRole('user');
  }

  getUserRoles(): string[] {
    const token = this.keycloak?.tokenParsed;
    let allRoles: string[] = [];
    
    if (token && token['realm_access'] && token['realm_access']['roles']) {
      allRoles = [...token['realm_access']['roles']];
    }
    
    if (token && token['resource_access']) {
      Object.keys(token['resource_access']).forEach(clientId => {
        const clientRoles = token['resource_access']?.[clientId]?.['roles'] ?? [];
        allRoles = [...allRoles, ...clientRoles.map(role => `${clientId}:${role}`)];
      });
    }
    
    return allRoles;
  }

  getKeycloak(): Keycloak | undefined {
    return this.keycloak;
  }
}