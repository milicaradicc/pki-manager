import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { UserNavBarComponent } from './layout/user-nav-bar/user-nav-bar.component';
import { ManagementComponent } from './management/management.component';
import { UserService } from './user.service';
import { AdminNavBarComponent } from './layout/admin-nav-bar/admin-nav-bar.component';

@NgModule({
  declarations: [],
  imports: [
    CommonModule,
    FormsModule,
    RouterModule,
    HomeComponent,
    UserNavBarComponent,
    AdminNavBarComponent,
    ManagementComponent
  ],
  providers: [UserService]
})
export class UserModule {}
