import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { UserService, User } from '../services/user/user.service';
import { KeycloakService } from '../services/keycloak/keycloak.service';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './home.component.html'
})
export class HomeComponent implements OnInit {
  user: User | undefined;

  constructor(private userService: UserService, private keycloakService: KeycloakService) {}

  ngOnInit() {
    if (this.keycloakService.isLoggedIn()) {
      this.userService.getUserProfile().subscribe({
        next: (user) => this.user = user,
        error: (err) => console.error('Failed to load profile', err)
      });
    } else {
      this.keycloakService.login();
    }
  }

  logout() {
    this.keycloakService.logout();
  }
}
