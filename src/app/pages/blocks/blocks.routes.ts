import {Routes} from '@angular/router';
import {Blocks} from '@/pages/blocks/blocks';
import { AuthGuard } from '@/services/auth.guard';

export default [{ path: '', data: { breadcrumb: 'Free Blocks' ,canActivate: [AuthGuard]}, component: Blocks ,canActivate: [AuthGuard]}] as Routes;
