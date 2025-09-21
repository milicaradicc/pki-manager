import { Component } from '@angular/core';
import { KeycloakService } from '../services/keycloak/keycloak.service';

@Component({
  selector: 'app-home',
  template: `
    <h1>Welcome, {{ username }}</h1>
    <button (click)="logout()">Logout</button>
  `
})
export class HomeComponent {
  username: string | undefined;

  constructor(private keycloakService: KeycloakService) {
    this.username = this.keycloakService.getUsername();
  }

  logout() {
    this.keycloakService.logout();
  }
}
