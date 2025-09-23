import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CreateEndEntityComponent } from './create-end-entity.component';

describe('CreateEndEntityComponent', () => {
  let component: CreateEndEntityComponent;
  let fixture: ComponentFixture<CreateEndEntityComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CreateEndEntityComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CreateEndEntityComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
