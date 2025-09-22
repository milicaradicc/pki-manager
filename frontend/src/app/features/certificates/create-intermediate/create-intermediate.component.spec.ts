import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CreateIntermediateComponent } from './create-intermediate.component';

describe('CreateIntermediateComponent', () => {
  let component: CreateIntermediateComponent;
  let fixture: ComponentFixture<CreateIntermediateComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CreateIntermediateComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CreateIntermediateComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
