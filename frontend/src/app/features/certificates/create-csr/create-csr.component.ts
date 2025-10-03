import {Component, inject, OnInit} from '@angular/core';
import {FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators} from '@angular/forms';
import {MatSnackBar} from '@angular/material/snack-bar';
import {GetCertificateDto} from '../models/get-certificate-dto.model';
import {CertificateService} from '../certificate.service';
import {Router} from '@angular/router';
import {MatFormField, MatInput, MatLabel} from '@angular/material/input';
import {MatDatepicker, MatDatepickerInput, MatDatepickerToggle} from '@angular/material/datepicker';
import {MatButton} from '@angular/material/button';
import {MatSelectModule} from '@angular/material/select';
import { MatIcon } from '@angular/material/icon';

@Component({
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
    MatIcon,
  ],
  selector: 'app-create-csr',
  standalone: true,
  styleUrl: './create-csr.component.css',
  templateUrl: './create-csr.component.html'
})
export class CreateCsrComponent implements OnInit {
  createForm!: FormGroup;
  today = new Date();
  snackBar: MatSnackBar = inject(MatSnackBar);
  allCertificates: GetCertificateDto[] = [];
  selectedFile: File | null = null;

  constructor(private fb: FormBuilder,
              private certificateService: CertificateService,
              private router: Router) {
  }

  ngOnInit(): void {
    this.createForm = this.fb.group({
      issuer: ['', Validators.required],
      startDate: ['', Validators.required],
      endDate: ['', Validators.required],
    });

    this.certificateService.getAllCaCertificates().subscribe({
      next: (certificates: GetCertificateDto[]) => {
        this.allCertificates = certificates;
      },
      error: (_) => {
        this.snackBar.open('Error loading certificates', 'OK', {duration: 3000});
      }
    });
  }

  onFileSelected(event: Event) {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.selectedFile = input.files[0];
    }
  }

  save() {
    if (!this.selectedFile) {
      this.snackBar.open('Please upload csr file', 'OK', {duration: 3000});
      return;
    }

    if (this.createForm.valid) {
      const formValues = this.createForm.value;
      const formData = new FormData();
      formData.append('csrFile', this.selectedFile);
      formData.append('issuerId',formValues.issuer.subjectId);
      formData.append('startDate',(new Date(formValues.startDate.getTime() - formValues.startDate.getTimezoneOffset() * 60000)).toISOString().split('T')[0]);
      formData.append('endDate',(new Date(formValues.endDate.getTime() - formValues.endDate.getTimezoneOffset() * 60000)).toISOString().split('T')[0]);
      this.certificateService.sendCSR(formData).subscribe({
        next: () => {
          this.snackBar.open('Certificate created successfully', 'OK', {duration: 3000});
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
