import {Component, inject, OnInit} from '@angular/core';
import {MatDatepicker, MatDatepickerInput, MatDatepickerToggle} from '@angular/material/datepicker';
import {MatFormField, MatInput, MatLabel} from '@angular/material/input';
import {FormBuilder, FormGroup, ReactiveFormsModule, Validators} from '@angular/forms';
import {MatSnackBar} from '@angular/material/snack-bar';
import {GetCertificateDto} from '../models/get-certificate-dto.model';
import {CertificateService} from '../certificate.service';
import {Router} from '@angular/router';
import {CreateIntermediateCertificateDTO} from '../models/create-intermediate-cetrificate-dto.model';
import {CreateCertificatePartyDTO} from '../models/create-certificate-party.model';
import {MatSelectModule} from '@angular/material/select';
import {MatButton} from '@angular/material/button';
import {CreateEndEntityCertificateDTO} from '../models/create-end-entity-dto.model';
import { KeycloakService } from '../../../core/keycloak/keycloak.service';
import {NgForOf} from '@angular/common';

@Component({
  selector: 'app-create-end-entity.component',
  imports: [
    MatDatepicker,
    MatDatepickerInput,
    MatDatepickerToggle,
    MatFormField,
    MatInput,
    MatLabel,
    ReactiveFormsModule,
    MatSelectModule,
    MatButton,
    NgForOf,
  ],
  templateUrl: './create-end-entity.component.html',
  standalone: true,
  styleUrl: './create-end-entity.component.css'
})
export class CreateEndEntityComponent implements OnInit{
  createForm!: FormGroup;
  today = new Date();
  snackBar:MatSnackBar = inject(MatSnackBar);
  allCertificates:GetCertificateDto[]=[];
  organization:string|undefined;
  isCaUser:boolean = false;

  keyUsageOptions: string[] = [
    'DIGITAL_SIGNATURE',
    'NON_REPUDIATION',
    'KEY_ENCIPHERMENT',
    'DATA_ENCIPHERMENT',
    'KEY_AGREEMENT',
    'KEY_CERT_SIGN',
    'CRL_SIGN',
    'ENCIPHER_ONLY',
    'DECIPHER_ONLY'
  ];

  extendedKeyUsageOptions: string[] = [
    'SERVER_AUTH',
    'CLIENT_AUTH',
    'CODE_SIGNING',
    'EMAIL_PROTECTION',
    'TIME_STAMPING',
    'OCSP_SIGNING'
  ];

  constructor(private fb: FormBuilder,
              private certificateService: CertificateService,
              private router:Router,
              private keycloakService: KeycloakService) {
  }

  ngOnInit(): void {
    this.isCaUser = this.keycloakService.isCA();
    if (this.isCaUser)
      this.organization = this.keycloakService.getUserOrganization();
    this.createForm = this.fb.group({
      issuer: ['', Validators.required],
      commonName: ['', Validators.required],
      surname: [''],
      givenName: [''],
      organization: [this.organization ?? '', Validators.required],
      organizationalUnit: ['', Validators.required],
      country: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(2)]],
      email: ['', [Validators.required, Validators.email]],
      startDate: ['', Validators.required],
      endDate: ['', Validators.required],
      keyUsages:[[]],
      extendedKeyUsages:[[]]
    });

    this.certificateService.getAllCaCertificates().subscribe({
      next: (certificates:GetCertificateDto[]) => {
        this.allCertificates = certificates;
      },
      error: (_) => {
        this.snackBar.open('Error loading event certificates','OK',{duration:3000});
      }
    });
  }

  save() {
    if (this.createForm.valid) {
      const formValues = this.createForm.value;
      const dto: CreateEndEntityCertificateDTO = {
        issuerId : formValues.issuer.subjectId,
        subject: {
          commonName: formValues.commonName,
          surname: formValues.surname,
          givenName: formValues.givenName,
          organization: this.organization ?? formValues.organization,
          organizationalUnit: formValues.organizationalUnit,
          country: formValues.country,
          email: formValues.email,
        } as CreateCertificatePartyDTO,
        startDate: (new Date(formValues.startDate.getTime() - formValues.startDate.getTimezoneOffset() * 60000)).toISOString().split('T')[0],
        endDate: (new Date(formValues.endDate.getTime() - formValues.endDate.getTimezoneOffset() * 60000)).toISOString().split('T')[0],
        keyUsages:formValues.keyUsages,
        extendedKeyUsages:formValues.extendedKeyUsages
      };
      this.certificateService.createEndEntityCertificate(dto).subscribe({
        next: () => {
          this.snackBar.open('Certificate created successfully','OK',{duration:3000});
          this.router.navigate(['home']);
        },
       error: (err) => {
          let errorMessage = err?.error || 'Unknown error';
          this.snackBar.open(errorMessage, 'OK', { duration: 5000 });
        }
      });
    }
  }
}
