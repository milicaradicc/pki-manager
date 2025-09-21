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
      .then(authenticated => resolve(authenticated))
      .catch(err => reject(err));
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
}
