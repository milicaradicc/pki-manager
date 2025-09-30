import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CreateCsrComponent } from './create-csr.component';

describe('CreateCsrComponent', () => {
  let component: CreateCsrComponent;
  let fixture: ComponentFixture<CreateCsrComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CreateCsrComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CreateCsrComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
