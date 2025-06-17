import { Routes } from '@angular/router';
import { Documentation } from './documentation/documentation';
import { Crud } from './crud/crud';
import { Empty } from './empty/empty';
import { Invoice } from './invoice/invoice';
import { AboutUs } from './aboutus/aboutus';
import { Help } from './help/help';
import { Faq } from './faq/faq';
import { ContactUs } from './contactus/contactus';
import { AuthGuard } from '@/services/auth.guard';

import { RoleGuard } from '@/services/role.guard';

export default [
    { path: 'documentation', component: Documentation , canActivate: [AuthGuard] },
    { path: 'crud', component: Crud ,canActivate: [AuthGuard, RoleGuard],
        data: { roles: ['admin']}
    },
    { path: 'empty', component: Empty ,canActivate: [AuthGuard]},
    { path: 'invoice', component: Invoice ,canActivate: [AuthGuard]},
    { path: 'aboutus', component: AboutUs ,canActivate: [AuthGuard]},
    { path: 'help', component: Help ,canActivate: [AuthGuard]},
    { path: 'faq', component: Faq ,canActivate: [AuthGuard]},
    { path: 'contact', component: ContactUs ,canActivate: [AuthGuard]},
    { path: '**', redirectTo: '/notfound' }
] as Routes;
