export interface User {
    id: number;
    name: string;
    email: string;
    roles: string[];
    permissions: string[];
  }
  
  export interface AuthResponse {
    token: string;
    token_type: string;
    user: User;
    roles: string[];
    permissions: string[];
  }
  
  export interface LoginRequest {
    email: string;
    password: string;
  }