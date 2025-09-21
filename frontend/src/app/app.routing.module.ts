import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { ManagementComponent } from './management/management.component';
import { AuthGuard } from './guards/auth.guard';

export const routes: Routes = [
  { path: '', component: ManagementComponent, canActivate: [AuthGuard] }, // admin main if needed
  { path: '', component: HomeComponent },
  { path: '**', redirectTo: '' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule {}
