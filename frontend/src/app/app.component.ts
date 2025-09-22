import { Component } from '@angular/core';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AdminNavBarComponent } from './layout/admin-nav-bar/admin-nav-bar.component';
import { CaNavBarComponent } from './layout/ca-nav-bar/ca-nav-bar.component';
import { KeycloakService } from './services/keycloak/keycloak.service';
import { UserNavBarComponent } from './layout/user-nav-bar/user-nav-bar.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    RouterModule,
    CommonModule,
    AdminNavBarComponent,
    CaNavBarComponent,
    UserNavBarComponent 
  ],
  template: `
    <div>
      <app-admin-nav-bar *ngIf="isAdmin()"></app-admin-nav-bar>
      <app-ca-nav-bar *ngIf="isCA() && !isAdmin()"></app-ca-nav-bar>
      <app-user-nav-bar *ngIf="isUser() && !isAdmin() && !isCA()"></app-user-nav-bar>
      <router-outlet></router-outlet>
    </div>
  `
})
export class AppComponent {
  constructor(private keycloakService: KeycloakService) {}

  isAdmin(): boolean {
    return this.keycloakService.isAdmin();
  }

  isCA(): boolean {
    return this.keycloakService.isCA();
  }

  isUser(): boolean {
    return this.keycloakService.isUser(); 
  }
}
