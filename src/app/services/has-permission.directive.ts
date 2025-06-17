import { Directive, Input, TemplateRef, ViewContainerRef } from '@angular/core';
import { AuthService } from './auth.service';

/**
 * Directive structurelle permettant d'afficher ou masquer un élément du DOM
 * selon qu'un utilisateur possède une permission donnée.
 * Usage : <div *appHasPermission="'PERMISSION_NAME'"> ... </div>
 */
@Directive({
  selector: '[appHasPermission]'
})
export class HasPermissionDirective {
  /**
   * Setter appelé à chaque changement de la valeur passée à appHasPermission.
   * Si l'utilisateur possède la permission, le contenu est affiché, sinon il est masqué.
   */
  @Input() set appHasPermission(permission: string) {
    if (this.authService.hasPermission(permission)) {
      // Affiche le contenu si la permission est présente
      this.viewContainer.createEmbeddedView(this.templateRef);
    } else {
      // Sinon, masque le contenu
      this.viewContainer.clear();
    }
  }

  /**
   * @param templateRef Référence au template HTML ciblé
   * @param viewContainer Conteneur pour insérer/supprimer le template dans le DOM
   * @param authService Service d'authentification pour vérifier les permissions
   */
  constructor(
    private templateRef: TemplateRef<any>,
    private viewContainer: ViewContainerRef,
    private authService: AuthService
  ) { }
}