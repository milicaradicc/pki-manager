import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AssignCertificateComponent } from './assign-certificate.component';

describe('AssignCertificateComponent', () => {
  let component: AssignCertificateComponent;
  let fixture: ComponentFixture<AssignCertificateComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AssignCertificateComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(AssignCertificateComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
