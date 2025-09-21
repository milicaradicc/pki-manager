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
    console.log('AuthGuard');
  }

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {
    console.log('AuthGuard - canActivate called for route:', state.url);
    
    if (!this.keycloakService.isLoggedIn()) {
      console.log('User not logged in, redirecting to login');
      this.keycloakService.login();
      return false;
    }

    console.log('User is logged in, checking admin privileges...');
    
    const userRoles = this.keycloakService.getUserRoles();
    console.log('All user roles:', userRoles);
    
    const hasRealmAdmin = this.keycloakService.hasRealmRole('admin');
    const hasRealmAdminRole = this.keycloakService.hasRealmRole('realm-admin');
    const hasClientRealmAdmin = this.keycloakService.hasClientRole('realm-management', 'realm-admin');
    const hasCustomAdmin = this.keycloakService.hasRealmRole('administrator');
    const isAdmin = this.keycloakService.isAdmin();

    console.log('Admin privilege checks:', {
      hasRealmAdmin,
      hasRealmAdminRole,
      hasClientRealmAdmin,
      hasCustomAdmin,
      isAdmin
    });

    if (hasRealmAdmin || hasRealmAdminRole || hasClientRealmAdmin || hasCustomAdmin) {
      console.log('Admin access granted');
      return true;
    }

    console.log('User does not have admin privileges');
    console.log('Available roles:', userRoles);
    
    alert(`Nemate administratorske privilegije!\nVaše role: ${userRoles.join(', ')}`);
    this.router.navigate(['/dashboard']);
    return false;
  }
}