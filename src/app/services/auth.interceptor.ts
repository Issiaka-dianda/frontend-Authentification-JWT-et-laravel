import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse
} from '@angular/common/http';
import { catchError, Observable, throwError } from 'rxjs';
import { AuthService } from './auth.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private authService: AuthService) {}

  intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    // With HTTP-only cookies, we don't need to manually add the token
    // We just need to ensure cookies are sent with the request
    if (this.shouldIncludeCookies(request)) {
      const authRequest = request.clone({
        withCredentials: true
      });
      return next.handle(authRequest).pipe(
        catchError((error: HttpErrorResponse) => {
          if (error.status === 401) {
            // Token expired or invalid, log out the user
            this.authService.logout();
          }
          return throwError(() => error);
        })
      );
    }

    return next.handle(request);
  }

  private shouldIncludeCookies(request: HttpRequest<any>): boolean {
    // Don't include credentials for public routes
    const publicRoutes = ['/login', '/register'];
    return !publicRoutes.some(route => request.url.includes(route));
  }
}