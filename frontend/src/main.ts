import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
import { appConfig } from './app/app.config';
import { KeycloakService } from './app/services/keycloak/keycloak.service';

const keycloakService = new KeycloakService();

keycloakService.init()
  .then(() => {
    bootstrapApplication(AppComponent, appConfig)
      .catch(err => console.error(err));
  })
  .catch(err => console.error('Keycloak init failed', err));
