
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { ConfirmationService, MessageService } from 'primeng/api';
import { PermissionService } from '../../../services/permission.service';
import { Permission } from '../../../model/permission.model';

// PrimeNG Imports
import { TableModule } from 'primeng/table';
import { ButtonModule } from 'primeng/button';
import { InputTextModule } from 'primeng/inputtext';
import { CardModule } from 'primeng/card';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { DialogModule } from 'primeng/dialog';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { MessagesModule } from 'primeng/messages';
import { MessageModule } from 'primeng/message';
import { ToolbarModule } from 'primeng/toolbar';

@Component({
  selector: 'app-permission-list',
  templateUrl: './permission-list.component.html',
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
    ProgressSpinnerModule,
    MessagesModule,
    MessageModule,
    ToolbarModule
  ]
})
export class PermissionListComponent implements OnInit {
  permissions: Permission[] = [];
  loading: boolean = true;

  constructor(
    private permissionService: PermissionService,
    private router: Router,
    private confirmationService: ConfirmationService,
    private messageService: MessageService
  ) { }

  ngOnInit(): void {
    this.loadPermissions();
  }

  loadPermissions(): void {
    this.loading = true;
    this.permissionService.getPermissions().subscribe({
      next: (data) => {
        this.permissions = data;
        this.loading = false;
      },
      error: (error) => {
        this.messageService.add({
          severity: 'error',
          summary: 'Erreur',
          detail: 'Impossible de charger les permissions'
        });
        this.loading = false;
      }
    });
  }

  createPermission(): void {
    this.router.navigate(['/profile/permissions/create']);
  }

  editPermission(permission: Permission): void {
    this.router.navigate(['/profile/permissions/edit', permission.id]);
  }

  confirmDelete(permission: Permission): void {
    this.confirmationService.confirm({
      message: `Êtes-vous sûr de vouloir supprimer la permission "${permission.name}" ?`,
      header: 'Confirmation de suppression',
      icon: 'pi pi-exclamation-triangle',
      accept: () => this.deletePermission(permission.id)
    });
  }

  deletePermission(id: number): void {
    this.permissionService.deletePermission(id).subscribe({
      next: () => {
        this.messageService.add({
          severity: 'success',
          summary: 'Succès',
          detail: 'Permission supprimée avec succès'
        });
        this.loadPermissions();
      },
      error: (error) => {
        this.messageService.add({
          severity: 'error',
          summary: 'Erreur',
          detail: 'Impossible de supprimer la permission'
        });
      }
    });
  }
}