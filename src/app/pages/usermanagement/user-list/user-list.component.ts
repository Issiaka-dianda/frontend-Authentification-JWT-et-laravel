// src/app/modules/user/components/user-list/user-list.component.ts
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { ConfirmationService, MessageService } from 'primeng/api';
import { UserService } from '../../../services/user.service';
import { User } from '../../../model/user.model';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms';
import { TableModule } from 'primeng/table';
import { ButtonModule } from 'primeng/button';
import { InputTextModule } from 'primeng/inputtext';
import { CardModule } from 'primeng/card';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { DialogModule } from 'primeng/dialog';
import { InputSwitchModule } from 'primeng/inputswitch';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { MessagesModule } from 'primeng/messages';
import { MessageModule } from 'primeng/message';
import { DividerModule } from 'primeng/divider';
import { ToolbarModule } from 'primeng/toolbar';
import { HasRoleDirective } from '../../../services/has-role.directive';

@Component({
  selector: 'app-user-list',
  templateUrl: './user-list.component.html',
  providers: [ConfirmationService, MessageService],
  standalone: true,
  imports: [
    TableModule,
    ButtonModule,
    InputTextModule,
    CardModule,
    ToastModule,
    ConfirmDialogModule,
    DialogModule,
    InputSwitchModule,
    ProgressSpinnerModule,
    MessagesModule,
    MessageModule,
    DividerModule,
    ToolbarModule,
    ReactiveFormsModule,
    CommonModule,
    HasRoleDirective,
  ]
})
export class UserListComponent implements OnInit {
  users: User[] = []; // Initialiser comme tableau vide au lieu de null
  loading: boolean = true;

  constructor(
    private userService: UserService,
    private router: Router,
    private confirmationService: ConfirmationService,
    private messageService: MessageService,
   
  ) { }

  ngOnInit(): void {
    this.loadUsers();
  }

  loadUsers(): void {
    this.loading = true;
    this.userService.getUsers().subscribe({
      next: (data) => {
        // S'assurer que data est un tableau avant de l'assigner à la table
        this.users = data.users;
        this.loading = false;
      },
      error: (error) => {
        this.messageService.add({
          severity: 'error',
          summary: 'Erreur',
          detail: 'Impossible de charger les utilisateurs'
        });
        this.users = []; // Réinitialiser à un tableau vide en cas d'erreur
        this.loading = false;
      }
    });

   
  }

  editUser(user: User): void {
    this.router.navigate(['profile/users/edit', user.id]);
  }

  viewUser(user: User): void {
    this.router.navigate(['profile/users/detail', user.id]);
  }

  confirmDelete(user: User): void {
    this.confirmationService.confirm({
      message: `Êtes-vous sûr de vouloir supprimer l'utilisateur ${user.name} ?`,
      header: 'Confirmation de suppression',
      icon: 'pi pi-exclamation-triangle',
      accept: () => this.deleteUser(user.id)
    });
  }

  deleteUser(id: number): void {
    this.userService.deleteUser(id).subscribe({
      next: () => {
        this.messageService.add({
          severity: 'success',
          summary: 'Succès',
          detail: 'Utilisateur supprimé avec succès'
        });
        this.loadUsers();
      },
      error: (error) => {
        this.messageService.add({
          severity: 'error',
          summary: 'Erreur',
          detail: 'Impossible de supprimer l\'utilisateur'
        });
      }
    });
  }

  createUser(): void {
    this.router.navigate(['/profile/users/create']);
  }
}