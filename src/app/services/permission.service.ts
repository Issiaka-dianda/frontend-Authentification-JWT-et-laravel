import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

interface Permission {
  id: number;
  name: string;
}

@Injectable({
  providedIn: 'root'
})
export class PermissionService {
  private apiUrl = 'http://localhost:8000/api/permissions';

  constructor(private http: HttpClient) {}

  getPermissions(): Observable<Permission[]> {
    return this.http.get<Permission[]>(this.apiUrl, { withCredentials: true });
  }

  createPermission(permission: { name: string }): Observable<Permission> {
    return this.http.post<Permission>(this.apiUrl, permission, { withCredentials: true });
  }

  updatePermission(id: number, permission: { name: string }): Observable<Permission> {
    return this.http.put<Permission>(`${this.apiUrl}/${id}`, permission, { withCredentials: true });
  }

  deletePermission(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`, { withCredentials: true });
  }
}