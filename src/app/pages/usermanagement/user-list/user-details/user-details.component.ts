// src/app/modules/user/components/user-detail/user-detail.component.ts
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { MessageService } from 'primeng/api';
import { UserService } from '../../../../services/user.service';
import { User } from '../../../../model/user.model';
import { ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

// PrimeNG Imports
import { CardModule } from 'primeng/card';
import { ToastModule } from 'primeng/toast';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { DividerModule } from 'primeng/divider';
import { ToolbarModule } from 'primeng/toolbar';
import { MultiSelectModule } from 'primeng/multiselect';

@Component({
  selector: 'app-user-detail',
  templateUrl: './user-details.component.html',
  providers: [MessageService],
  standalone: true,
  imports: [
    CommonModule,
    ReactiveFormsModule,
    CardModule,
    ToastModule,
    ProgressSpinnerModule,
    DividerModule,
    ToolbarModule,
    MultiSelectModule
  ]
})
export class UserDetailsComponent implements OnInit {
  user: User | null = null;
  loading: boolean = true;
  userId: number = 0;

  constructor(
    private userService: UserService,
    private route: ActivatedRoute,
    private router: Router,
    private messageService: MessageService
  ) { }

  ngOnInit(): void {
    this.route.params.subscribe(params => {
      if (params['id']) {
        this.userId = +params['id'];
        this.loadUser(this.userId);
      } else {
        this.router.navigate(['/profile/users']);
      }
    });
  }

  loadUser(id: number): void {
    this.loading = true;
    this.userService.getUsers().subscribe({
      next: (data) => {
        const users = data.users as User[];
        this.user = users.find(u => u.id === id) || null;
        
        if (!this.user) {
          this.messageService.add({
            severity: 'error',
            summary: 'Erreur',
            detail: 'Utilisateur non trouvé'
          });
          setTimeout(() => this.router.navigate(['/profile/users']), 1500);
        }
        
        this.loading = false;
      },
      error: (error) => {
        this.messageService.add({
          severity: 'error',
          summary: 'Erreur',
          detail: 'Impossible de charger les informations de l\'utilisateur'
        });
        this.loading = false;
      }
    });
  }

  editUser(): void {
    this.router.navigate(['/profile/users/edit', this.userId]);
  }

  goBack(): void {
    this.router.navigate(['/profile/users']);
  }
}