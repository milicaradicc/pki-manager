import { Component, OnInit } from '@angular/core';
import { GetCertificateDto } from '../models/get-certificate-dto.model';
import { CertificateService } from '../certificate.service';
import { KeycloakService } from '../../../core/keycloak/keycloak.service';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RevocationReason } from '../models/revocation-reason.model';

@Component({
  selector: 'app-certificates',
  standalone: true,
  imports: [CommonModule, FormsModule],
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

  revocationReasons = Object.values(RevocationReason);
  showRevocationPopup = false;
  revokingCertificateSerial: string | null = null;
  selectedReason: RevocationReason | null = null;

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

    let obs$;
    if (this.role === 'admin') {
      obs$ = this.certificateService.getAllCertificates();
    } else if (this.role === 'ca') {
      obs$ = this.certificateService.getAllCaCertificates();
    } else {
      obs$ = this.certificateService.getOwnedCertificates();
    }

    obs$.subscribe({
      next: (data) => {
        this.certificates = data;
        this.loading = false;
      },
      error: () => {
        this.error = 'Failed to load certificates';
        this.loading = false;
      }
    });
  }

  download(serial: string): void {
    this.loading = true;
    this.clearMessages();
    this.certificateService.downloadCertificate(serial);
    this.success = 'Certificate download initiated';
    this.loading = false;
  }

  revoke(serial: string): void {
    this.revokingCertificateSerial = serial;
    this.selectedReason = null;
    this.showRevocationPopup = true;
  }

  cancelRevocation(): void {
    this.showRevocationPopup = false;
    this.revokingCertificateSerial = null;
    this.selectedReason = null;
  }

  confirmRevocation(): void {
    if (this.selectedReason && this.revokingCertificateSerial) {
      this.loading = true;
      this.clearMessages();
      this.certificateService
        .revokeCertificate(this.revokingCertificateSerial, this.selectedReason)
        .subscribe({
          next: () => {
            this.success = 'Certificate revoked successfully';
            this.loading = false;
            this.showRevocationPopup = false;
            this.revokingCertificateSerial = null;
            this.selectedReason = null;
            this.loadCertificates(); // refresh tabele
          },
          error: () => {
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
    if (cert.revoked) return false;  // Revoked certificates are not valid
    const now = new Date();
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    return now >= validFrom && now <= validTo;
  }

  getStatus(cert: GetCertificateDto): string {
    if (cert.revoked) return 'Revoked';
    const now = new Date();
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    
    if (now < validFrom) return 'Not Yet Valid';
    if (now > validTo) return 'Expired';
    return 'Valid';
  }

  getStatusClass(cert: GetCertificateDto): string {
    if (cert.revoked) return 'status-revoked';
    const now = new Date();
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    
    if (now < validFrom) return 'status-pending';
    if (now > validTo) return 'status-expired';
    return 'status-valid';
  }

  clearMessages(): void {
    this.error = '';
    this.success = '';
  }

  formatRevocationReason(reason: RevocationReason): string {
    return reason
      .replace(/_/g, ' ')
      .toLowerCase()
      .replace(/\b\w/g, char => char.toUpperCase());
  }
}
