import { NgModule, APP_INITIALIZER } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { KeycloakService } from './services/keycloak/keycloak.service';
import { AppComponent } from './app.component';
import { AppRoutingModule } from './app.routing.module';

export function initializeKeycloak(keycloak: KeycloakService) {
  return () => keycloak.init();
}

@NgModule({
  declarations: [AppComponent],
  imports: [BrowserModule, AppRoutingModule],
  providers: [
    {
      provide: APP_INITIALIZER,
      useFactory: initializeKeycloak,
      multi: true,
      deps: [KeycloakService],
    },
  ],
  bootstrap: [AppComponent],
})
export class AppModule {}
