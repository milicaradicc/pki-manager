import { Component } from '@angular/core';
import { RouterModule } from '@angular/router';
import { KeycloakService } from '../../services/keycloak/keycloak.service';

@Component({
  selector: 'app-ca-nav-bar',
  standalone: true,
  imports: [RouterModule],
  templateUrl: './ca-nav-bar.component.html',
  styleUrls: ['./ca-nav-bar.component.css']
})
export class CaNavBarComponent {
  constructor(private keycloakService: KeycloakService) {}

  logout() {
    this.keycloakService.logout();
  }
}
