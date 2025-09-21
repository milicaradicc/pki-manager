import { TestBed } from '@angular/core/testing';
import { KeycloakService } from './keycloak.service';

describe('KeycloakService', () => {
  let service: KeycloakService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(KeycloakService);  // << koristi svoj servis
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
