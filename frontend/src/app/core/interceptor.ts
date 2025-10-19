import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable, from } from 'rxjs';
import { KeycloakService } from './keycloak/keycloak.service';
import { catchError, switchMap } from 'rxjs/operators';
import { throwError } from 'rxjs';

@Injectable()
export class Interceptor implements HttpInterceptor {

  constructor(private keycloak: KeycloakService) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (!this.keycloak.isLoggedIn()) {
      return next.handle(req);
    }

    // updateToken() metoda u Keycloak adapteru 
    // automatski koristi refresh token da osveži 
    // access token kada mu uskoro ističe rok, 
    // tako da nije potrebno ručno slanje refresh tokena. 
    // Ako je i refresh token istekao, updateToken() baca 
    // grešku koju treba uhvatiti u interceptoru i 
    // tada odjaviti korisnika.
    
    return from(this.keycloak['keycloak']!.updateToken(30)).pipe(
      switchMap(() => {
        const token = this.keycloak.getToken();
        if (token) {
          const cloned = req.clone({
            setHeaders: { Authorization: `Bearer ${token}` }
          });
          return next.handle(cloned);
        }
        return next.handle(req);
      }),
      catchError(err => {
        console.error('Token refresh failed', err);
        this.keycloak.logout(); // korisnik se izloguje ako je refresh token istekao
        return throwError(() => err);
      })
    );
  }
}
