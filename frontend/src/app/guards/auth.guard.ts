import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { KeycloakService } from '../services/keycloak/keycloak.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(private keycloakService: KeycloakService, private router: Router) {}

  canActivate(): boolean {
    if (this.keycloakService.isLoggedIn()) {
      return true;
    } else {
      this.keycloakService.login();
      return false;
    }
  }
}
