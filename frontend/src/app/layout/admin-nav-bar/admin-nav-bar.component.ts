import { Component } from '@angular/core';
import { RouterModule } from '@angular/router';
import { KeycloakService } from '../../services/keycloak/keycloak.service';

@Component({
  selector: 'app-admin-nav-bar',
  standalone: true,
  imports: [RouterModule],
  templateUrl: './admin-nav-bar.component.html',
  styleUrls: ['./admin-nav-bar.component.css']
})
export class AdminNavBarComponent {
  constructor(private keycloakService: KeycloakService) {}

  logout() {
    this.keycloakService.logout();
  }
}
