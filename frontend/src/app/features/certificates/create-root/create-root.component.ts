import {Component, inject, OnInit} from '@angular/core';
import {MatFormField, MatInput, MatLabel} from '@angular/material/input';
import {FormBuilder, FormGroup, ReactiveFormsModule, Validators} from '@angular/forms';
import {MatDatepicker, MatDatepickerInput, MatDatepickerToggle} from '@angular/material/datepicker';
import {CertificateService} from '../certificate.service';
import {CreateRootCertificateDTO} from '../models/create-root-certificate-dto.model';
import {CreateCertificatePartyDTO} from '../models/create-certificate-party.model';
import {MatSnackBar} from '@angular/material/snack-bar';
import {Router} from '@angular/router';
import { provideNativeDateAdapter } from '@angular/material/core';
import { MatSelectModule } from '@angular/material/select';

@Component({
  selector: 'app-create-root',
  imports: [
    MatDatepicker,
    MatDatepickerInput,
    MatDatepickerToggle,
    MatFormField,
    MatInput,
    MatLabel,
    ReactiveFormsModule,
    MatSelectModule,
  ],
  templateUrl: './create-root.component.html',
  standalone: true,
  styleUrl: './create-root.component.css',
  providers: [provideNativeDateAdapter()]
})
export class CreateRootComponent implements OnInit {
  createForm!: FormGroup;
  today = new Date();
  snackBar:MatSnackBar = inject(MatSnackBar);

  constructor(private fb: FormBuilder,
              private certificateService: CertificateService,
              private router:Router) {
  }

  ngOnInit(): void {
    this.createForm = this.fb.group({
      commonName: ['', Validators.required],
      surname: [''],
      givenName: [''],
      organization: ['', Validators.required],
      organizationalUnit: ['', Validators.required],
      country: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(2)]],
      email: ['', [Validators.required, Validators.email]],
      startDate: ['', Validators.required],
      endDate: ['', Validators.required],
    });
  }

  save() {
    if (this.createForm.valid) {
      const formValues = this.createForm.value;
      const dto: CreateRootCertificateDTO = {
        subject: {
          commonName: formValues.commonName,
          surname: formValues.surname,
          givenName: formValues.givenName,
          organization: formValues.organization,
          organizationalUnit: formValues.organizationalUnit,
          country: formValues.country,
          email: formValues.email,
        } as CreateCertificatePartyDTO,
        startDate: (new Date(formValues.startDate.getTime() - formValues.startDate.getTimezoneOffset() * 60000)).toISOString().split('T')[0],
        endDate: (new Date(formValues.endDate.getTime() - formValues.endDate.getTimezoneOffset() * 60000)).toISOString().split('T')[0],
      };
      this.certificateService.createRootCertificate(dto).subscribe({
        next: (createdEvent) => {
          this.snackBar.open('Certificate created successfully','OK',{duration:3000});
          this.router.navigate(['home']);
        },
        error: () => {
          this.snackBar.open('Error creating certificate','OK',{duration:3000});
        }
      });
    }
  }
}
