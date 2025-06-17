import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class OpenAIService {
  private apiUrl = `http://localhost:8000/api/ask-openai`;

  constructor(private http: HttpClient) { }

  generateResponse(message: string): Observable<any> {
    return this.http.post(this.apiUrl, { message });
  }
}