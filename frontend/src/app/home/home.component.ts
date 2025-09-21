import { Component, OnInit } from '@angular/core';
import { KeycloakService } from '../services/keycloak/keycloak.service';

@Component({
  selector: 'app-home',
  standalone: false,
  templateUrl: './home.component.html'
})
export class HomeComponent implements OnInit {
  username: string | undefined;

  constructor(private keycloakService: KeycloakService) {
    console.log("Constructor - komponenta se inicijalizuje");
  }

  ngOnInit() {
    console.log("ngOnInit - pozvan");
    console.log("KeycloakService:", this.keycloakService);
    
    // Dodaj proveru da li je servis uopšte definisan
    if (!this.keycloakService) {
      console.error("KeycloakService nije dostupan!");
      return;
    }

    // Proveri status prijave
    const isLoggedIn = this.keycloakService.isLoggedIn();
    console.log("Da li je korisnik prijavljen:", isLoggedIn);

    if (isLoggedIn) {
      console.log("Korisnik JE prijavljen - ulazi u if blok");
      console.log(" e"); // Ovaj log će se sada prikazati
      this.username = this.keycloakService.getUsername();
      console.log("Username:", this.username);
    } else {
      console.log("Korisnik NIJE prijavljen");
    }
  }

  logout() {
    console.log("Logout pozvan");
    this.keycloakService.logout();
  }
}