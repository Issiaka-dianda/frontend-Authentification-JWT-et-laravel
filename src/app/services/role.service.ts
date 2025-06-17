import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

interface Role {
  id: number;
  name: string;
  permissions: string[];
}

@Injectable({
  providedIn: 'root'
})
export class RoleService {
  private apiUrl = 'http://localhost:8000/api/roles';
  constructor(private http: HttpClient) { }

  getRoles(): Observable<any> {
    return this.http.get<any>(this.apiUrl);
  }

  createRole(role: { name: string, permissions: string[] }): Observable<Role> {
    return this.http.post<Role>(this.apiUrl, role);
  }

  updateRole(id: number, role: { name: string, permissions: string[] }): Observable<Role> {
    return this.http.put<Role>(`${this.apiUrl}/${id}`, role);
  }

  deleteRole(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }
  
  assignPermissions(roleId: number, permissions: string[]): Observable<Role> {
    return this.http.post<Role>(`${this.apiUrl}/${roleId}/assign-permissions`, { permissions });
  }
}