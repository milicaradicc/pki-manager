import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { KeycloakService } from '../services/keycloak/keycloak.service';

@Component({
  selector: 'app-management',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './management.component.html',
  styleUrls: ['./management.component.css']
})
export class ManagementComponent {
  title = 'Admin Management Panel';

  constructor(private keycloakService: KeycloakService) {}

  onLogout() {
    this.keycloakService.logout();
  }
}
