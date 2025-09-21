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
        checkLoginIframe: false
      })
      .then(authenticated => {
        console.log('Keycloak initialized, authenticated:', authenticated);
        if (authenticated && this.keycloak?.tokenParsed) {
          console.log('User roles:', this.getUserRoles());
          console.log('Token parsed:', this.keycloak.tokenParsed);
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

  getUsername(): string | undefined {
    return this.keycloak?.tokenParsed?.['preferred_username'];
  }

  hasRealmRole(role: string): boolean {
    const token = this.keycloak?.tokenParsed;
    console.log('Checking realm role:', role, 'Token:', token);
    
    if (token && token['realm_access']) {
      const roles = token['realm_access']['roles'] || [];
      console.log('Available realm roles:', roles);
      return roles.includes(role);
    }
    return false;
  }

  hasClientRole(clientId: string, role: string): boolean {
    const token = this.keycloak?.tokenParsed;
    console.log('Checking client role:', role, 'for client:', clientId);
    
    if (token && token['resource_access'] && token['resource_access'][clientId]) {
      const roles = token['resource_access'][clientId]['roles'] || [];
      console.log(`Available roles for client ${clientId}:`, roles);
      return roles.includes(role);
    }
    return false;
  }

  hasRole(role: string, clientId?: string): boolean {
    if (clientId) {
      return this.hasClientRole(clientId, role);
    } else {
      return this.hasRealmRole(role);
    }
  }

  isAdmin(): boolean {
    // Proveri različite načine kako admin role mogu biti definisane
    const realmAdmin = this.hasRealmRole('admin');
    const realmAdminRole = this.hasRealmRole('realm-admin');
    const clientAdmin = this.hasClientRole('realm-management', 'realm-admin');
    const customAdmin = this.hasRealmRole('administrator');
    
    console.log('Admin check results:', {
      realmAdmin,
      realmAdminRole, 
      clientAdmin,
      customAdmin
    });
    
    return realmAdmin || realmAdminRole || clientAdmin || customAdmin;
  }

  redirectToRegistration() {
    this.keycloak?.register();
  }

  getUserRoles(): string[] {
    const token = this.keycloak?.tokenParsed;
    let allRoles: string[] = [];
    
    // Realm roles
    if (token && token['realm_access'] && token['realm_access']['roles']) {
      allRoles = [...token['realm_access']['roles']];
    }
    
    // Client roles
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