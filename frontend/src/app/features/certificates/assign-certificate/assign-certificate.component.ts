import { Component, inject } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { MatFormField, MatLabel } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { GetCertificateDto } from '../models/get-certificate-dto.model';
import { CertificateService } from '../certificate.service';
import { UserService } from '../../users/user.service';
import { CaUserDto } from '../../users/models/ca-user.dto';
import { AssignCertificateDTO } from '../models/assign-certificate.dto';
import { MatSnackBar } from '@angular/material/snack-bar';

@Component({
  selector: 'app-assign-certificate',
  standalone: true,
  imports: [
    MatFormField,
    MatLabel,
    ReactiveFormsModule,
    MatSelectModule,
  ],
  templateUrl: './assign-certificate.component.html',
  styleUrl: './assign-certificate.component.css'
})
export class AssignCertificateComponent {
  assignForm!: FormGroup;

  allCertificates: GetCertificateDto[] = [];
  caUsers: CaUserDto[] = [];

  certificateServise = inject(CertificateService);
  userService = inject(UserService);
  snackBar = inject(MatSnackBar);

  constructor() {
    this.assignForm = new FormGroup({
      certificate: new FormControl(''),
      caUser: new FormControl(''),
    });
  }

  ngOnInit(): void {
    this.fetchCertificates();
    this.fetchCaUsers();
  }

  fetchCertificates(): void {
    this.certificateServise.getAllCaCertificates().subscribe({
      next: (certificates: GetCertificateDto[]) => {
        console.log(certificates);
        this.allCertificates = certificates;
      },
      error: () => {
        console.log('Error loading certificates');
      }
    });
  }

  fetchCaUsers(): void {
    this.userService.getAllCaUsers().subscribe({
      next: (users: CaUserDto[]) => {
        this.caUsers = users;
      },
      error: () => {
        console.log('Error loading CA users');
      }
    });
  }

  save() {
    if (this.assignForm.valid) {
      const formValues = this.assignForm.value;
      const dto: AssignCertificateDTO = {
        certificateSerialNumber: formValues.certificate.serialNumber,
        caUserEmail: formValues.caUser.email,
      };
      this.certificateServise.assignCertificate(dto).subscribe({
        next: () => {
          this.snackBar.open('Certificate assigned successfully','OK',{duration:3000});
        },
        error: () => {
          this.snackBar.open('Error assigning certificate','OK',{duration:3000});
        }
      });
    }
  }
}
