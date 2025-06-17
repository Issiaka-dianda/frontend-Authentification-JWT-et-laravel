import { Directive, Input, TemplateRef, ViewContainerRef } from '@angular/core';
import { AuthService } from './auth.service';
@Directive({
  selector: '[appHasRole]'
})
export class HasRoleDirective {


  @Input() set appHasRole(role: string) {

    if (this.authService.hasRole(role)) {
      this.viewContainer.createEmbeddedView(this.templateRef);
    } else {
      
      this.viewContainer.clear();
    }
  }
  constructor(
    private templateRef: TemplateRef<any>,
    private viewContainer: ViewContainerRef,
    private authService: AuthService
  ) { }
}