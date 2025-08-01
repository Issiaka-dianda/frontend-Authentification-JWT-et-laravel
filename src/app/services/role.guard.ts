import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { AuthService } from './auth.service';
@Injectable({
  providedIn: 'root'
})
export class RoleGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) { }
  canActivate(
    next: ActivatedRouteSnapshot,
    state: RouterStateSnapshot): boolean {
    const requiredRoles = next.data['roles'] as Array<string>;
    if (this.authService.isLoggedIn() && requiredRoles.some(role => this.authService.hasRole(role))) {
      return true;
    }
    this.router.navigate(['/unauthorized']);
    return false;
  }
}