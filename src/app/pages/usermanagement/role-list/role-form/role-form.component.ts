// src/app/modules/role/components/role-form/role-form.component.ts
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { MessageService } from 'primeng/api';
import { RoleService } from '../../../../services/role.service';
import { PermissionService } from '../../../../services/permission.service';
import { Role } from '../../../../model/role.model';
import { Permission } from '../../../../model/permission.model';
import { forkJoin } from 'rxjs';
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
import { InputSwitchModule } from 'primeng/inputswitch';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-role-form',
  templateUrl: './role-form.component.html',
  providers: [MessageService],
  standalone: true,
  imports: [   
    FormsModule,
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
    ToolbarModule,
    InputSwitchModule
  ]
})
export class RoleFormComponent implements OnInit {
  roleForm!: FormGroup;
  isEditMode: boolean = false;
  roleId: number | null = null;
  permissions: Permission[] = [];
  rolePermissions: { [key: number]: boolean } = {};
  submitting: boolean = false;
  loading: boolean = false;

  constructor(
    private fb: FormBuilder,
    private roleService: RoleService,
    private permissionService: PermissionService,
    private route: ActivatedRoute,
    private router: Router,
    private messageService: MessageService
  ) { }

  ngOnInit(): void {
    this.initForm();
    this.loadPermissions();
    
    this.route.params.subscribe(params => {
      if (params['id']) {
        this.isEditMode = true;
        this.roleId = +params['id'];
        this.loadRole(this.roleId);
      }
    });
  }

  initForm(): void {
    this.roleForm = this.fb.group({
      name: ['', [Validators.required]]
    });
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

  loadRole(id: number): void {
    this.loading = true;
    this.roleService.getRoles().subscribe({
      next: (data) => {
        const roles = data.roles as Role[];
        const role = roles.find(r => r.id === id);
        
        if (role) {
          this.roleForm.patchValue({ name: role.name });

          // Initialiser les permissions du rôle
          this.rolePermissions = {};
          role.permissions.forEach(permission => {
            this.rolePermissions[permission.id] = true;
          });
        }
        this.loading = false;
      },
      error: (error) => {
        this.messageService.add({
          severity: 'error',
          summary: 'Erreur',
          detail: 'Impossible de charger les informations du rôle'
        });
        this.loading = false;
      }
    });
  }

  onPermissionToggle(permissionId: number, checked: boolean): void {
    this.rolePermissions[permissionId] = checked;
  }

  onSubmit(): void {
    if (this.roleForm.invalid) {
      this.roleForm.markAllAsTouched();
      this.messageService.add({
        severity: 'error',
        summary: 'Erreur',
        detail: 'Veuillez corriger les erreurs dans le formulaire'
      });
      return;
    }

    this.submitting = true;
    const formData = this.roleForm.value;
    const selectedPermissionNames = Object.entries(this.rolePermissions)
      .filter(([_, isSelected]) => isSelected)
      .map(([id]) => this.permissions.find(p => p.id === Number(id))?.name || '');

    if (this.isEditMode && this.roleId) {
      // Mise à jour du rôle
      const updateRole = this.roleService.updateRole(this.roleId, {
        name: formData.name,
        permissions: selectedPermissionNames
      });

      const assignPermissions = this.roleService.assignPermissions(this.roleId, selectedPermissionNames);

      forkJoin([updateRole, assignPermissions]).subscribe({
        next: () => {
          this.messageService.add({
            severity: 'success',
            summary: 'Succès',
            detail: 'Rôle mis à jour avec succès'
          });
          setTimeout(() => this.router.navigate(['/profile/roles']), 1500);
        },
        error: (error) => {
          this.messageService.add({
            severity: 'error',
            summary: 'Erreur',
            detail: error.error?.message || 'Erreur lors de la mise à jour du rôle'
          });
          this.submitting = false;
        }
      });
    } else {
      // Création d'un nouveau rôle
      this.roleService.createRole({
        name: formData.name,
        permissions: selectedPermissionNames
      }).subscribe({
        next: (role) => {
          this.messageService.add({
            severity: 'success',
            summary: 'Succès',
            detail: 'Rôle créé avec succès'
          });
          setTimeout(() => this.router.navigate(['/profile/roles']), 1500);
        },
        error: (error) => {
          this.messageService.add({
            severity: 'error',
            summary: 'Erreur',
            detail: error.error?.message || 'Erreur lors de la création du rôle'
          });
          this.submitting = false;
        }
      });
    }
  }

  cancel(): void {
    this.router.navigate(['/profile/roles']);
  }
}