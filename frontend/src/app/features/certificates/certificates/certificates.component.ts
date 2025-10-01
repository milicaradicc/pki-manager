import { Component, OnInit } from '@angular/core';
import { GetCertificateDto } from '../models/get-certificate-dto.model';
import { CertificateService } from '../certificate.service';
import { KeycloakService } from '../../../core/keycloak/keycloak.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-certificates',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './certificates.component.html',
  styleUrls: ['./certificates.component.css']
})
export class CertificatesComponent implements OnInit {
  certificates: GetCertificateDto[] = [];
  selectedCertificate: GetCertificateDto | null = null;
  role!: string;
  loading = false;
  error = '';
  success = '';

  constructor(
    private certificateService: CertificateService,
    private keycloakService: KeycloakService
  ) {}

  ngOnInit(): void {
    this.role = this.keycloakService.getUserRole(); 
    this.loadCertificates();
  }

  loadCertificates(): void {
    this.loading = true;
    this.clearMessages();

    if (this.role === 'admin') {
      this.certificateService.getAllCertificates().subscribe({
        next: (data) => {
          this.certificates = data;
          this.loading = false;
        },
        error: (err) => {
          this.error = 'Failed to load certificates';
          this.loading = false;
        }
      });
    } else if (this.role === 'ca') {
      this.certificateService.getAllCaCertificates().subscribe({
        next: (data) => {
          this.certificates = data;
          this.loading = false;
        },
        error: (err) => {
          this.error = 'Failed to load certificates';
          this.loading = false;
        }
      });
    } else if (this.role === 'user') {
      this.certificateService.getOwnedCertificates().subscribe({
        next: (data) => {
          this.certificates = data;
          this.loading = false;
        },
        error: (err) => {
          this.error = 'Failed to load certificates';
          this.loading = false;
        }
      });
    }
  }

  download(serial: string): void {
    this.loading = true;
    this.clearMessages();
    this.certificateService.downloadCertificate(serial);
    this.success = 'Certificate download initiated';
    this.loading = false;
  }

  revoke(serial: string): void {
    const reason = prompt("Reason for revocation:");
    if (reason) {
      this.loading = true;
      this.clearMessages();
      this.certificateService.revokeCertificate(serial, reason)
        .subscribe({
          next: () => {
            this.success = 'Certificate revoked successfully';
            this.loading = false;
            this.loadCertificates(); 
          },
          error: (err) => {
            this.error = 'Failed to revoke certificate';
            this.loading = false;
          }
        });
    }
  }

  viewDetails(cert: GetCertificateDto): void {
    this.selectedCertificate = cert;
  }

  closeDetails(): void {
    this.selectedCertificate = null;
  }

  isValid(cert: GetCertificateDto): boolean {
    const now = new Date();
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    return now >= validFrom && now <= validTo;
  }

  clearMessages(): void {
    this.error = '';
    this.success = '';
  }
}

