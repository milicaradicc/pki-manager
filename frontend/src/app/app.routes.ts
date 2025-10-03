import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './features/users/home/home.component';
import { ManagementComponent } from './features/users/management/management.component';
import { AuthGuard } from './core/auth.guard';
import {CreateRootComponent} from './features/certificates/create-root/create-root.component';
import {CreateIntermediateComponent} from './features/certificates/create-intermediate/create-intermediate.component';
import {
  CreateEndEntityComponent
} from './features/certificates/create-end-entity.component/create-end-entity.component';
import { AssignCertificateComponent } from './features/certificates/assign-certificate/assign-certificate.component';
import {CreateCsrComponent} from './features/certificates/create-csr/create-csr.component';
import { CertificatesComponent } from './features/certificates/certificates/certificates.component';

export const routes: Routes = [
  {
    path: '',
    component: HomeComponent,
    canActivate: [AuthGuard] ,
    data: { roles: ['admin', 'user', 'ca'] }
  },
  {
    path: 'management',
    component: ManagementComponent,
    canActivate: [AuthGuard],
    data: { roles: ['admin'] }
  },
  {
    path: 'create-root',
    component: CreateRootComponent,
    canActivate: [AuthGuard],
    data: { roles: ['admin'] }
  },
  {
    path: 'create-intermediate',
    component: CreateIntermediateComponent,
    canActivate: [AuthGuard],
    data: { roles: ['admin','ca'] }
  },
  {
    path: 'create-end-entity',
    component: CreateEndEntityComponent,
    canActivate: [AuthGuard],
    data: { roles: ['admin','ca','user'] }
  },
  {
    path: 'assign-certificates',
    component: AssignCertificateComponent,
    canActivate: [AuthGuard],
    data: { roles: ['admin'] }
  },
  {
    path: 'upload-csr',
    component: CreateCsrComponent,
    canActivate: [AuthGuard],
    data: { roles: ['user'] }
  },
  {
    path: 'certificates',
    component: CertificatesComponent,
    canActivate: [AuthGuard],
    data: { roles: ['admin','ca','user'] }
  },
  { path: '**', redirectTo: '' }
];


@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule {}
