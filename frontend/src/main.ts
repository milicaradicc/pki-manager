import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
import { provideRouter } from '@angular/router';
import { KeycloakService } from './app/services/keycloak/keycloak.service';
import { routes } from './app/app.routing.module';

const keycloakService = new KeycloakService();

keycloakService.init()
  .then((authenticated) => {
    console.log('Keycloak initialized, authenticated:', authenticated);
    
    // Bootstrap aplikaciju bez obzira na status autentifikacije
    // AuthGuard će handle-ovati redirection
    bootstrapApplication(AppComponent, {
      providers: [
        provideRouter(routes),
        // Dodaj KeycloakService kao provider
        { provide: KeycloakService, useValue: keycloakService }
      ],
    }).catch(err => console.error('Bootstrap error:', err));
  })
  .catch(err => {
    console.error('Keycloak init failed:', err);
    // Pokušaj da bootstrap-uješ aplikaciju i bez Keycloak-a
    bootstrapApplication(AppComponent, {
      providers: [
        provideRouter(routes),
      ],
    }).catch(bootstrapErr => console.error('Bootstrap error:', bootstrapErr));
  });