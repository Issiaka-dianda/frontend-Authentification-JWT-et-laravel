import { Routes } from '@angular/router';
import { UserList } from './userlist';
import { UserCreate } from './usercreate';
import { PermissionListComponent } from './permission-list/permission-list.component';
import { RoleListComponent } from './role-list/role-list.component';
import { UserListComponent } from './user-list/user-list.component';
import { PermissionFormComponent } from './permission-list/permission-form/permission-form.component';
import { UserFormComponent } from './user-list/user-form/user-form.component';
import { UserDetailsComponent } from './user-list/user-details/user-details.component';
import { RoleFormComponent } from './role-list/role-form/role-form.component';

import { RoleGuard } from '@/services/role.guard';
import { AuthGuard } from '@/services/auth.guard';

export default [
   
    // Permissions
    
    { path: 'permissions', component: PermissionListComponent, canActivate: [AuthGuard] },
    { path: 'permissions/create', component: PermissionFormComponent },
    { path: 'permissions/edit/:id', component: PermissionFormComponent },
    // Users
    { path: 'users', component: UserListComponent, canActivate: [AuthGuard] },
    { path: 'users/create', component: UserFormComponent },
    { path: 'users/edit/:id', component: UserFormComponent },
    { path: 'users/detail/:id', component: UserDetailsComponent },
    //{ path: '', redirectTo: 'list', pathMatch: 'full' },
    // Roles
    { path: 'roles', component: RoleListComponent, canActivate: [AuthGuard] },
    { path: 'roles/create', component: RoleFormComponent },
    { path: 'roles/edit/:id', component: RoleFormComponent },
    // Users
    { path: 'list', data: { breadcrumb: 'List' }, component: UserListComponent},
    { path: 'create', data: { breadcrumb: 'Create' }, component: UserCreate, canActivate: [AuthGuard] }
] as Routes;
