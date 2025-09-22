import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './features/users/home/home.component';
import { ManagementComponent } from './features/users/management/management.component';
import { AuthGuard } from './core/auth.guard';
import {CreateRootComponent} from './features/certificates/create-root/create-root.component';
import {CreateIntermediateComponent} from './features/certificates/create-intermediate/create-intermediate.component';

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
  { path: '**', redirectTo: '' }
];


@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule {}
