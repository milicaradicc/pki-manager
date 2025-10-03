import { Component, OnInit } from '@angular/core';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { KeycloakService } from '../../../../core/keycloak/keycloak.service';

@Component({
  selector: 'app-user-nav-bar',
  standalone: true,
  imports: [RouterModule, CommonModule],
  templateUrl: './user-nav-bar.component.html',
  styleUrls: ['./user-nav-bar.component.css']
})
export class UserNavBarComponent  {

  constructor(private keycloakService: KeycloakService) {}

  goToAccount() {
    const accountUrl = this.keycloakService.getAccountUrl();
    if (accountUrl) {
      window.location.href = accountUrl; 
    }
  }

  logout() {
    this.keycloakService.logout();
  }
}
