import { Injectable } from '@angular/core';
import { CanActivate, Router, ActivatedRouteSnapshot } from '@angular/router';
import { KeycloakService } from '../services/keycloak/keycloak.service';

@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  constructor(private keycloakService: KeycloakService, private router: Router) {}

  async canActivate(route: ActivatedRouteSnapshot): Promise<boolean> {
    const isLoggedIn = await this.keycloakService.isLoggedIn();
    if (!isLoggedIn) {
      await this.keycloakService.login();
      return false;
    }

    const allowedRoles: string[] = route.data['roles'] || [];
    const userRoles = this.keycloakService.getUserRoles();

    console.log('User roles (filtered):', userRoles);

    const hasAccess = allowedRoles.some(role =>
      userRoles.some(userRole => userRole.toLowerCase() === role.toLowerCase())
    );

    if (!hasAccess) {
      alert('Nemate pristup ovoj stranici!');
      this.router.navigate(['/']);
      return false;
    }

    return true;
  }
}
