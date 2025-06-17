import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { BehaviorSubject, Observable, throwError } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { Router } from '@angular/router';
import * as CryptoJS from 'crypto-js';

interface User {
  id: number;
  name: string;
  email: string;
  roles: string[];
  permissions: string[];
}

interface AuthResponse {
  user: User;
  roles: string[];
  permissions: string[];
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:8000/api';
  private currentUserSubject: BehaviorSubject<User | null>;
  public currentUser: Observable<User | null>;
  private secretKey = 'VOTRE_CLE_SECRETE_FORTE'; // À personnaliser

  constructor(private http: HttpClient, private router: Router) {
    // Récupère l'utilisateur du sessionStorage
    const encryptedUser = sessionStorage.getItem('currentUser');
    let user: User | null = null;
    if (encryptedUser) {
      try {
        user = this.decryptData(encryptedUser);
      } catch (e) {
        user = null;
      }
    }
    this.currentUserSubject = new BehaviorSubject<User | null>(user);
    this.currentUser = this.currentUserSubject.asObservable();
  }

  private encryptData(data: any): string {
    return CryptoJS.AES.encrypt(JSON.stringify(data), this.secretKey).toString();
  }

  private decryptData(data: string): any {
    const bytes = CryptoJS.AES.decrypt(data, this.secretKey);
    return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
  }

  public get currentUserValue(): User | null {
    return this.currentUserSubject.value;
  }

  // With HTTP-only cookies, we don't need to manage the token ourselves
  public isLoggedIn(): boolean {
    return !!this.currentUserValue;
  }

  public logout(): void {
    this.http.post(`${this.apiUrl}/logout`, {}, { withCredentials: true })
      .subscribe({
        next: () => {
          this.clearAuthData();
        },
        error: () => {
          this.clearAuthData();
        }
      });
  }

  private clearAuthData(): void {
    sessionStorage.removeItem('currentUser');
    this.currentUserSubject.next(null);
    this.router.navigate(['/login']);
  }

  login(email: string, password: string): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(
      `${this.apiUrl}/login`, 
      { email, password },
      { withCredentials: true } // Important: allows cookies to be sent/received
    ).pipe(
      tap(response => {
        const user = {
          ...response.user,
          roles: response.roles,
          permissions: response.permissions
        };
        sessionStorage.setItem('currentUser', this.encryptData(user));
        this.currentUserSubject.next(user);
      })
    );
  }

  // We need to check if the user is authenticated by making an API call
  public checkAuthStatus(): Observable<User> {
    return this.http.get<User>(`${this.apiUrl}/user`, { withCredentials: true }).pipe(
      tap(user => {
        sessionStorage.setItem('currentUser', this.encryptData(user));
        this.currentUserSubject.next(user);
      }),
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401) {
          this.clearAuthData();
        }
        return throwError(() => error);
      })
    );
  }

  hasRole(role: string): boolean {
    const user = this.currentUserValue;
    return user ? user.roles.includes(role) : false;
  }

  hasPermission(permission: string): boolean {
    const user = this.currentUserValue;
    return user ? user.permissions.includes(permission) : false;
  }
}   