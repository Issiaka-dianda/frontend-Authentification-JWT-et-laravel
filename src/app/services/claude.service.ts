import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';


@Injectable({
  providedIn: 'root'
})
export class ClaudeService {
  private apiUrl = `http://localhost:8000/api/ask-claude`;

  constructor(private http: HttpClient) { }

  // Correction: une seule méthode generateResponse
  generateResponse(message: string): Observable<any> {
    return this.http.post(this.apiUrl, { message });
  }
}