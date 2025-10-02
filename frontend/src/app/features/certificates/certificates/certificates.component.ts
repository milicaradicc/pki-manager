import { Component, OnInit } from '@angular/core';
import { GetCertificateDto } from '../models/get-certificate-dto.model';
import { CertificateService } from '../certificate.service';
import { KeycloakService } from '../../../core/keycloak/keycloak.service';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RevocationReason } from '../models/revocation-reason.model';

interface CertificateNode {
  certificate: GetCertificateDto;
  children: CertificateNode[];
  expanded: boolean;
  level: number;
  hasRevokedParent: boolean;
}

@Component({
  selector: 'app-certificates',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './certificates.component.html',
  styleUrls: ['./certificates.component.css']
})
export class CertificatesComponent implements OnInit {
  certificates: GetCertificateDto[] = [];
  certificateTree: CertificateNode[] = [];
  flattenedTree: CertificateNode[] = [];
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
        this.buildCertificateTree();
        this.updateFlattenedTree();
        this.loading = false;
      },
      error: () => {
        this.error = 'Failed to load certificates';
        this.loading = false;
      }
    });
  }

  buildCertificateTree(): void {
    const certMap = new Map<string, CertificateNode>();

    // Create nodes for all certificates
    this.certificates.forEach(cert => {
      certMap.set(cert.serialNumber, {
        certificate: cert,
        children: [],
        expanded: false,
        level: 0,
        hasRevokedParent: false
      });
    });

    const roots: CertificateNode[] = [];

    this.certificates.forEach(cert => {
      const node = certMap.get(cert.serialNumber)!;

      // Try to find parent using issuer info
      const parent = this.certificates.find(c =>
        c.subjectCommonName === cert.issuerCommonName &&
        c.subjectOrganization === cert.issuerOrganization &&
        c.serialNumber !== cert.serialNumber
      );

      if (parent) {
        const parentNode = certMap.get(parent.serialNumber)!;
        parentNode.children.push(node);
      } else {
        roots.push(node); // Root cert (self-signed or no parent found)
      }
    });

    // Set levels and check for revoked parents
    const setLevelsAndCheckRevocation = (node: CertificateNode, level: number, parentRevoked: boolean) => {
      node.level = level;
      node.hasRevokedParent = parentRevoked || node.certificate.revoked;
      node.children.forEach(child =>
        setLevelsAndCheckRevocation(child, level + 1, node.hasRevokedParent)
      );
    };

    roots.forEach(root => setLevelsAndCheckRevocation(root, 0, false));
    this.certificateTree = roots;
  }

  updateFlattenedTree(): void {
    this.flattenedTree = [];
    const flatten = (node: CertificateNode) => {
      this.flattenedTree.push(node);
      if (node.expanded) {
        node.children.forEach(child => flatten(child));
      }
    };
    this.certificateTree.forEach(root => flatten(root));
  }

  toggleExpand(node: CertificateNode): void {
    node.expanded = !node.expanded;
    this.updateFlattenedTree();
  }

  canCreateCertificate(node: CertificateNode): boolean {
    // Cannot create if this cert or any parent is revoked
    if (node.hasRevokedParent) return false;
    
    // Cannot create if this cert is expired
    const now = new Date();
    const validTo = new Date(node.certificate.validTo);
    if (now > validTo) return false;
    
    // Only ROOT and INTERMEDIATE can issue certificates
    return node.certificate.type === 'ROOT' || node.certificate.type === 'INTERMEDIATE';
  }

  createCertificate(issuerSerial: string): void {
    // TODO: Implement navigation to certificate creation page
    // Example: this.router.navigate(['/create-certificate'], { queryParams: { issuer: issuerSerial } });
    console.log('Create certificate for issuer:', issuerSerial);
    this.success = `Navigate to create certificate with issuer: ${issuerSerial}`;
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
            this.loadCertificates();
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