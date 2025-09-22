import { Component } from '@angular/core';
import { RouterModule } from '@angular/router';
import { KeycloakService } from '../../../../core/keycloak/keycloak.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-admin-nav-bar',
  standalone: true,
  imports: [RouterModule, CommonModule],
  templateUrl: './admin-nav-bar.component.html',
  styleUrls: ['./admin-nav-bar.component.css']
})
export class AdminNavBarComponent {
  constructor(public keycloakService: KeycloakService) {}

  logout() {
    this.keycloakService.logout();
  }
}
