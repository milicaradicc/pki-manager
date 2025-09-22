import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { KeycloakService, KeycloakUser, CreateUserRequest } from '../services/keycloak/keycloak.service';

@Component({
  selector: 'app-management',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './management.component.html',
  styleUrls: ['./management.component.css']
})
export class ManagementComponent implements OnInit {
  title = 'Admin Management Panel';
  users: KeycloakUser[] = [];
  roles: any[] = [];
  loading = false;
  error: string | null = null;
  success: string | null = null;

  showCreateForm = false;
  newUser: CreateUserRequest = {
    username: '',
    email: '',
    firstName: '',
    lastName: '',
    enabled: true,
    attributes: {}, 
    credentials: [],
    emailVerified: false
  };
  newUserPassword = '';
  selectedRole = '';
  newUserOrganization = '';

  constructor(private keycloakService: KeycloakService) {}

  ngOnInit() {
    if (this.keycloakService.isAdmin()) {
      this.loadUsers();
      this.loadRoles();
    } else {
      this.error = 'Nemate dozvolu za pristup admin panelu.';
    }
  }

  loadUsers() {
    this.loading = true;
    this.error = null;
    
    this.keycloakService.getAllUsers().subscribe({
      next: (users) => {
        this.users = users;
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Greška pri učitavanju korisnika: ' + err.message;
        this.loading = false;
        console.error('Error loading users:', err);
      }
    });
  }

  loadRoles() {
    this.keycloakService.getAllRoles().subscribe({
      next: (roles) => {
        console.log('Loaded roles from API:', roles);
        // filter roles
        this.roles = roles.filter(role => 
          ['admin', 'ca', 'user'].includes(role.name)
        );
      }
    });
  }

  toggleCreateForm() {
    this.showCreateForm = !this.showCreateForm;
    if (!this.showCreateForm) {
      this.resetCreateForm();
    }
  }

  resetCreateForm() {
    this.newUser = {
      username: '',
      email: '',
      firstName: '',
      lastName: '',
      enabled: true,
      attributes: {},
      credentials: []
    };
    this.newUserPassword = '';
    this.newUserOrganization = ''; 
    this.selectedRole = '';
    this.error = null;
    this.success = null;
  }

createUser() {
  if (!this.newUser.username.trim()) {
    this.error = 'Korisničko ime je obavezno';
    return;
  }

  if (!this.newUserPassword.trim()) {
    this.error = 'Lozinka je obavezna';
    return;
  }

  this.loading = true;
  this.error = null;

  const userRequest: CreateUserRequest = {
      ...this.newUser,
      attributes: {
        ...(this.newUserOrganization.trim() && { 
          organization: [this.newUserOrganization.trim()] 
        })
      },
      credentials: [{
        type: 'password',
        value: this.newUserPassword,
        temporary: true
      }],
      emailVerified: false
    };

    this.keycloakService.createUser(userRequest).subscribe({
        next: (response) => {
            const locationHeader = response.headers.get('Location');
            if (locationHeader) {
            const userId = locationHeader.split('/').pop();
            if (userId) {

                // 1️⃣ Pošalji email za verifikaciju
                this.keycloakService.sendVerificationEmail(userId).subscribe({
                next: () => {
                    console.log('Verification email sent');
                },
                error: (err) => {
                    console.error('Error sending verification email:', err);
                }
                });

                // 2️⃣ Dodeli ulogu ako je izabrana
                if (this.selectedRole) {
                this.keycloakService.assignRoleToUser(userId, this.selectedRole).subscribe({
                    next: () => {
                    this.success = 'Korisnik je uspešno kreiran sa ulogom ' + this.selectedRole;
                    this.loadUsers();
                    this.resetCreateForm();
                    this.showCreateForm = false;
                    this.loading = false;
                    },
                    error: (err) => {
                    this.error = 'Korisnik je kreiran, ali uloga nije dodeljena: ' + err.message;
                    this.loadUsers();
                    this.loading = false;
                    }
                });
                return;
                }
            }
            }

            this.success = 'Korisnik je uspešno kreiran';
            this.loadUsers();
            this.resetCreateForm();
            this.showCreateForm = false;
            this.loading = false;
        },
        error: (err) => {
            console.error('Full error object:', err);
            this.error = 'Greška pri kreiranju korisnika: ' + (err.error?.errorMessage || err.message);
            this.loading = false;
        }
    });
  }

  deleteUser(userId: string, username: string) {
    if (confirm(`Da li ste sigurni da želite da obrišete korisnika "${username}"?`)) {
      this.loading = true;
      
      this.keycloakService.deleteUser(userId).subscribe({
        next: () => {
          this.success = `Korisnik "${username}" je uspešno obrisan`;
          this.loadUsers();
        },
        error: (err) => {
          this.error = 'Greška pri brisanju korisnika: ' + err.message;
          this.loading = false;
          console.error('Error deleting user:', err);
        }
      });
    }
  }

  getUserRoles(userId: string): void {
    this.keycloakService.getUserRolesById(userId).subscribe({
      next: (roles) => {
        console.log('User roles:', roles);
      },
      error: (err) => {
        console.error('Error getting user roles:', err);
      }
    });
  }

  onLogout() {
    this.keycloakService.logout();
  }

  clearMessages() {
    this.error = null;
    this.success = null;
  }
  
  getUserOrganization(user: KeycloakUser): string {
    return user.attributes?.['organization']?.[0] || '';
  }
}