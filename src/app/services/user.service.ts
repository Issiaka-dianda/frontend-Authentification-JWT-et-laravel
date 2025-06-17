import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { throwError } from 'rxjs';
import { User } from "../model/user.model";


@Injectable({
  providedIn: 'root'
})
export class UserService {
  private apiUrl = 'http://localhost:8000/api/users';
  constructor(private http: HttpClient) { }
  getUsers(): Observable<any> {
    return this.http.get<any>(this.apiUrl).pipe(
      catchError(error => {
        return throwError(error);
      })
    );
  }

  
  createUser(user: any): Observable<User> {
    return this.http.post<User>(this.apiUrl, user);
  }
  updateUser(id: number, user: any): Observable<User> {
    return this.http.put<User>(`${this.apiUrl}/${id}`, user);
  }
  deleteUser(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }
  assignRoles(userId: number, roles: string[]): Observable<User> {
    return this.http.post<User>(`${this.apiUrl}/${userId}/assign-roles`, { roles });
  }
}
