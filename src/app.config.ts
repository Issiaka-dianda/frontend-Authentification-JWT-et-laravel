import { HTTP_INTERCEPTORS, provideHttpClient, withFetch, withInterceptors, withInterceptorsFromDi } from '@angular/common/http';
import { ApplicationConfig, importProvidersFrom } from '@angular/core';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideRouter, withEnabledBlockingInitialNavigation, withInMemoryScrolling } from '@angular/router';
import Aura from '@primeng/themes/aura';
import { providePrimeNG } from 'primeng/config';
import { appRoutes } from './app.routes';
import { AuthInterceptor } from './app/services/auth.interceptor';
import { JwtModule } from '@auth0/angular-jwt';

export function tokenGetter() {
  return localStorage.getItem('token');
}

export const appConfig: ApplicationConfig = {
    providers: [
        provideRouter(appRoutes, withInMemoryScrolling({ anchorScrolling: 'enabled', scrollPositionRestoration: 'enabled' }), withEnabledBlockingInitialNavigation()),
        provideHttpClient(withFetch(), withInterceptorsFromDi()),
        provideAnimationsAsync(),
    
        { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true },
        providePrimeNG({ theme: { preset: Aura, options: { darkModeSelector: '.app-dark' } } }),

        // Utiliser importProvidersFrom pour JwtModule
        importProvidersFrom(
            JwtModule.forRoot({
                config: {
                    tokenGetter: tokenGetter,
                    allowedDomains: ['localhost:8000'],
                    disallowedRoutes: ['localhost:8000/api/login', 'localhost:8000/api/register']
                }
            })
        )
    ]
};