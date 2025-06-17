// src/app/modules/user/components/user-form/user-form.component.ts
import { Component, OnInit } from '@angular/core';
import { ReactiveFormsModule, FormBuilder, FormGroup, Validators  } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { MessageService } from 'primeng/api';
import { UserService } from '../../../../services/user.service';
import { RoleService } from '../../../../services/role.service';
import { User } from '../../../../model/user.model';
import { Role } from '../../../../model/role.model';
import { forkJoin } from 'rxjs';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
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

@Component({
  selector: 'app-user-form',
  templateUrl: './user-form.component.html',
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
    InputSwitchModule,
    ProgressSpinnerModule,
    MessagesModule,
    MessageModule,
    DividerModule,
    ToolbarModule,
    MultiSelectModule,
    FormsModule
  ]
})
export class UserFormComponent implements OnInit {
  userForm!: FormGroup;
  isEditMode: boolean = false;
  userId: number | null = null;
  roles: Role[] = [];
  userRoles: { [key: number]: boolean } = {};
  submitting: boolean = false;
  loading: boolean = false;

  constructor(
    private fb: FormBuilder,
    private userService: UserService,
    private roleService: RoleService,
    private route: ActivatedRoute,
    private router: Router,
    private messageService: MessageService
  ) { }

  ngOnInit(): void {
    this.initForm();
    this.loadRoles();
    
    this.route.params.subscribe(params => {
      if (params['id']) {
        this.isEditMode = true;
        this.userId = +params['id'];
        this.loadUser(this.userId);
      }
    });
  }

  initForm(): void {
    this.userForm = this.fb.group({
      name: ['', [Validators.required]],
      email: ['', [Validators.required, Validators.email]],
      password: ['', this.isEditMode ? [] : [Validators.required, Validators.minLength(8)]]
    });
  }

  loadRoles(): void {
    this.loading = true;
    this.roleService.getRoles().subscribe({
      next: (data) => {
        this.roles = data.roles;
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

  loadUser(id: number): void {
    this.loading = true;
    this.userService.getUsers().subscribe({
      next: (data) => {
        const users = data.users as User[];
        const user = users.find(u => u.id === id);
        
        if (user) {
          this.userForm.patchValue({
            name: user.name,
            email: user.email
          });

          // Initialiser les rôles de l'utilisateur
          this.userRoles = {};
          user.roles.forEach(role => {
            this.userRoles[role.id] = true;
          });
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

  onRoleToggle(roleId: number, checked: boolean): void {
    this.userRoles[roleId] = checked;
  }

  onSubmit(): void {
    if (this.userForm.invalid) {
      this.userForm.markAllAsTouched();
      this.messageService.add({
        severity: 'error',
        summary: 'Erreur',
        detail: 'Veuillez corriger les erreurs dans le formulaire'
      });
      return;
    }

    this.submitting = true;
    const formData = this.userForm.value;

    const selectedRoleNames = Object.keys(this.userRoles)
      .filter(id => this.userRoles[+id])
      .map(id => this.roles.find(r => r.id === Number(id))?.name || '');

    if (this.isEditMode && this.userId) {
      // Mise à jour de l'utilisateur
      const updateUser = this.userService.updateUser(this.userId, {
        name: formData.name,
        email: formData.email,
        ...(formData.password ? { password: formData.password } : {})
      });

      const assignRoles = this.userService.assignRoles(this.userId, selectedRoleNames);

      forkJoin([updateUser, assignRoles]).subscribe({
        next: ([userData, _]) => {
          this.messageService.add({
            severity: 'success',
            summary: 'Succès',
            detail: 'Utilisateur mis à jour avec succès'
          });
          setTimeout(() => this.router.navigate(['/profile/users']), 1500);
        },
        error: (error) => {
          this.messageService.add({
            severity: 'error',
            summary: 'Erreur',
            detail: error.error?.message || 'Erreur lors de la mise à jour de l\'utilisateur'
          });
          this.submitting = false;
        }
      });
    } else {
      // Création d'un nouvel utilisateur
      this.userService.createUser({
        name: formData.name,
        email: formData.email,
        password: formData.password
      }).subscribe({
        next: (user) => {
          if (selectedRoleNames.length > 0) {
            this.userService.assignRoles(user.id, selectedRoleNames).subscribe({
              next: () => {
                this.messageService.add({
                  severity: 'success',
                  summary: 'Succès',
                  detail: 'Utilisateur créé avec succès'
                });
                setTimeout(() => this.router.navigate(['/profile/users']), 1500);
              },
              error: (error) => {
                this.messageService.add({
                  severity: 'warning',
                  summary: 'Attention',
                  detail: 'Utilisateur créé mais problème lors de l\'assignation des rôles'
                });
                setTimeout(() => this.router.navigate(['/profile/users']), 1500);
              }
            });
          } else {
            this.messageService.add({
              severity: 'success',
              summary: 'Succès',
              detail: 'Utilisateur créé avec succès'
            });
            setTimeout(() => this.router.navigate(['/profile/users']), 1500);
          }
        },
        error: (error) => {
          this.messageService.add({
            severity: 'error',
            summary: 'Erreur',
            detail: error.error?.message || 'Erreur lors de la création de l\'utilisateur'
          });
          this.submitting = false;
        }
      });
    }
  }

  cancel(): void {
    this.router.navigate([' /profile/list']);
  }
}