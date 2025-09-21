import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
import { provideRouter } from '@angular/router';
import { importProvidersFrom } from '@angular/core';
import { HttpClientModule } from '@angular/common/http';
import { routes } from './app/app.routing.module';
import { KeycloakService } from './app/services/keycloak/keycloak.service';

const keycloakService = new KeycloakService();

keycloakService.init()
  .then(() => {
    bootstrapApplication(AppComponent, {
      providers: [
        provideRouter(routes),
        { provide: KeycloakService, useValue: keycloakService },
        importProvidersFrom(HttpClientModule) 
      ],
    }).catch(err => console.error(err));
  })
  .catch(err => console.error('Keycloak init failed:', err));
