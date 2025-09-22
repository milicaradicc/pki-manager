import { Injectable } from '@angular/core';
import { CanActivate, Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { KeycloakService } from '../services/keycloak/keycloak.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(
    private keycloakService: KeycloakService,
    private router: Router
  ) {
  }

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {

    if (!this.keycloakService.isLoggedIn()) {
      this.keycloakService.login();
      return false;
    }

    if (state.url !== '/management') {
      return true;
    }

    const hasAdminRole = this.keycloakService.hasRealmRole('admin') 

    if (hasAdminRole) {
      console.log('Admin access granted');
      return true;
    }

    console.log('User does not have admin privileges');
    alert('Nemate administratorske privilegije!');
    this.router.navigate(['/']);
    return false;
  }
}
