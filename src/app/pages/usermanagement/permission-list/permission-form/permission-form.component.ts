// src/app/modules/permission/components/permission-form/permission-form.component.ts
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { MessageService } from 'primeng/api';
import { PermissionService } from '../../../../services/permission.service';
import { Permission } from '../../../../model/permission.model';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms';

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
  selector: 'app-permission-form',
  templateUrl: './permission-form.component.html',
  providers: [MessageService],
  standalone: true,
  imports: [
    CommonModule,
    ReactiveFormsModule,
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
export class PermissionFormComponent implements OnInit {
  permissionForm!: FormGroup;
  isEditMode: boolean = false;
  permissionId: number | null = null;
  submitting: boolean = false;
  loading: boolean = false;

  constructor(
    private fb: FormBuilder,
    private permissionService: PermissionService,
    private route: ActivatedRoute,
    private router: Router,
    private messageService: MessageService
  ) { }

  ngOnInit(): void {
    this.initForm();
    
    this.route.params.subscribe(params => {
      if (params['id']) {
        this.isEditMode = true;
        this.permissionId = +params['id'];
        this.loadPermission(this.permissionId);
      }
    });
  }

  initForm(): void {
    this.permissionForm = this.fb.group({
      name: ['', [Validators.required]]
    });
  }

  loadPermission(id: number): void {
    this.loading = true;
    this.permissionService.getPermissions().subscribe({
      next: (data) => {
        const permission = data.find((p: Permission) => p.id === id);
        
        if (permission) {
          this.permissionForm.patchValue({
            name: permission.name
          });
        } else {
          this.messageService.add({
            severity: 'error',
            summary: 'Erreur',
            detail: 'Permission non trouvée'
          });
          setTimeout(() => this.router.navigate(['/profile/permissions']), 1500);
        }
        this.loading = false;
      },
      error: (error) => {
        this.messageService.add({
          severity: 'error',
          summary: 'Erreur',
          detail: 'Impossible de charger la permission'
        });
        this.loading = false;
      }
    });
  }

  onSubmit(): void {
    if (this.permissionForm.invalid) {
      this.permissionForm.markAllAsTouched();
      this.messageService.add({
        severity: 'error',
        summary: 'Erreur',
        detail: 'Veuillez corriger les erreurs dans le formulaire'
      });
      return;
    }

    this.submitting = true;
    const formData = this.permissionForm.value;

    if (this.isEditMode && this.permissionId) {
      // Mise à jour de la permission
      this.permissionService.updatePermission(this.permissionId, formData).subscribe({
        next: () => {
          this.messageService.add({
            severity: 'success',
            summary: 'Succès',
            detail: 'Permission mise à jour avec succès'
          });
          setTimeout(() => this.router.navigate(['/profile/permissions']), 1500);
        },
        error: (error) => {
          this.messageService.add({
            severity: 'error',
            summary: 'Erreur',
            detail: error.error?.message || 'Erreur lors de la mise à jour de la permission'
          });
          this.submitting = false;
        }
      });
    } else {
      // Création d'une nouvelle permission
      this.permissionService.createPermission(formData).subscribe({
        next: () => {
          this.messageService.add({
            severity: 'success',
            summary: 'Succès',
            detail: 'Permission créée avec succès'
          });
          setTimeout(() => this.router.navigate(['/profile/permissions']), 1500);
        },
        error: (error) => {
          this.messageService.add({
            severity: 'error',
            summary: 'Erreur',
            detail: error.error?.message || 'Erreur lors de la création de la permission'
          });
          this.submitting = false;
        }
      });
    }
  }

  cancel(): void {
    this.router.navigate(['/profile/permissions']);
  }
}