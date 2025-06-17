// src/app/modules/role/components/role-list/role-list.component.ts
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { ConfirmationService, MessageService } from 'primeng/api';
import { RoleService } from '../../../services/role.service';
import { Role } from '../../../model/role.model';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormsModule } from '@angular/forms';
// PrimeNG Imports
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
import { MultiSelectModule } from 'primeng/multiselect';
import { TagModule } from 'primeng/tag';

@Component({
  selector: 'app-role-list',
  templateUrl: './role-list.component.html',
  providers: [ConfirmationService, MessageService],
  standalone: true,
  imports: [
    ProgressSpinnerModule,
    TableModule,
    ButtonModule,
    DialogModule,
    InputTextModule,
    MultiSelectModule,
    ConfirmDialogModule,
    CardModule,
    TagModule,
    ToastModule,
    MessagesModule,
    MessageModule,
    DividerModule,
    ToolbarModule,
    InputSwitchModule,
    ProgressSpinnerModule,
    ReactiveFormsModule,
    CommonModule,
    FormsModule
  ]
})
export class RoleListComponent implements OnInit {
  roles: Role[] = [];
  filteredRoles: Role[] = [];
  loading: boolean = true;
  searchTerm: string = '';

  constructor(
    private roleService: RoleService,
    private router: Router,
    private confirmationService: ConfirmationService,
    private messageService: MessageService
  ) { }

  ngOnInit(): void {
    this.loadRoles();
  }

  onSearch(event: Event): void {
    const query = (event.target as HTMLInputElement).value.toLowerCase();
    this.filteredRoles = this.roles.filter(role => 
      role.name.toLowerCase().includes(query) ||
      role.id.toString().includes(query)
    );
  }

  loadRoles(): void {
    this.loading = true;
    this.roleService.getRoles().subscribe({
      next: (data) => {
        this.roles = data.roles;
        this.filteredRoles = [...this.roles];
        this.loading = false;
      },
      error: (error) => {
        this.messageService.add({
          severity: 'error',
          summary: 'Erreur',
          detail: 'Impossible de charger les rôles'
        });
        this.loading = false;
      }
    });
  }

  createRole(): void {
    this.router.navigate(['profile/roles/create']);
  }

  editRole(role: Role): void {
    this.router.navigate(['profile/roles/edit', role.id]);
  }

  confirmDelete(role: Role): void {
    this.confirmationService.confirm({
      message: `Êtes-vous sûr de vouloir supprimer le rôle "${role.name}" ?`,
      header: 'Confirmation de suppression',
      icon: 'pi pi-exclamation-triangle',
      accept: () => this.deleteRole(role.id)
    });
  }

  deleteRole(id: number): void {
    this.roleService.deleteRole(id).subscribe({
      next: () => {
        this.messageService.add({
          severity: 'success',
          summary: 'Succès',
          detail: 'Rôle supprimé avec succès'
        });
        this.loadRoles();
      },
      error: (error) => {
        this.messageService.add({
          severity: 'error',
          summary: 'Erreur',
          detail: 'Impossible de supprimer le rôle'
        });
      }
    });
  }
}