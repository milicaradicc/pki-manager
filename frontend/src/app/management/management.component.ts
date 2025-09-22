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
      this.error = 'Cannot access admin panel.';
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
        this.error = 'Error: ' + err.message;
        this.loading = false;
      }
    });
  }

  loadRoles() {
    this.keycloakService.getAllRoles().subscribe({
      next: (roles) => {
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
    this.error = 'User name required';
    return;
  }

  if (!this.newUserPassword.trim()) {
    this.error = 'Password required';
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

                this.keycloakService.sendVerificationEmail(userId).subscribe({
                next: () => {
                    console.log('Verification email sent');
                },
                error: (err) => {
                    console.error('Error sending verification email:', err);
                }
                });

                if (this.selectedRole) {
                this.keycloakService.assignRoleToUser(userId, this.selectedRole).subscribe({
                    next: () => {
                    this.success = 'User created with role ' + this.selectedRole;
                    this.loadUsers();
                    this.resetCreateForm();
                    this.showCreateForm = false;
                    this.loading = false;
                    },
                    error: (err) => {
                    this.error = 'User created, role error: ' + err.message;
                    this.loadUsers();
                    this.loading = false;
                    }
                });
                return;
                }
            }
            }

            this.success = 'User created';
            this.loadUsers();
            this.resetCreateForm();
            this.showCreateForm = false;
            this.loading = false;
        },
        error: (err) => {
            this.error = 'Error creating user: ' + (err.error?.errorMessage || err.message);
            this.loading = false;
        }
    });
  }

  deleteUser(userId: string, username: string) {
    if (confirm(`Are you sure you want to delete user "${username}"?`)) {
      this.loading = true;
      
      this.keycloakService.deleteUser(userId).subscribe({
        next: () => {
          this.success = `User "${username}" deleted`;
          this.loadUsers();
        },
        error: (err) => {
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