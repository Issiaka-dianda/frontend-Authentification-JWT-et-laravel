import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AppMenuitem } from './app.menuitem';

@Component({
    selector: 'app-menu',
    standalone: true,
    imports: [CommonModule, AppMenuitem, RouterModule],
    template: `<ul class="layout-menu">
        <ng-container *ngFor="let item of model; let i = index">
            <li
                app-menuitem
                *ngIf="!item.separator"
                [item]="item"
                [index]="i"
                [root]="true"
            ></li>
            <li *ngIf="item.separator" class="menu-separator"></li>
        </ng-container>
    </ul> `,
})
export class AppMenu {
    model: any[] = [];

    ngOnInit() {
        this.model = [
            {
                label: 'Dashboards',
                icon: 'pi pi-home',
                items: [
                    {
                        label: 'E-Commerce',
                        icon: 'pi pi-fw pi-home',
                        routerLink: ['/'],
                    },
                    {
                        label: 'Banking',
                        icon: 'pi pi-fw pi-image',
                        routerLink: ['/dashboard-banking'],
                    },
                ],
            },
        
            {
                label: 'User Management',
                icon: 'pi pi-fw pi-user',
                items: [
                    {
                        label: 'List',
                        icon: 'pi pi-fw pi-list',
                        routerLink: ['profile/list'],
                    },
                    {
                        label: 'Create',
                        icon: 'pi pi-fw pi-plus',
                        routerLink: ['profile/create'],
                    },
                    {
                        label: 'Permission',
                        icon: 'pi pi-fw pi-lock',
                        routerLink: ['profile/permissions'],
                    },
                    {
                        label: 'Role',
                        icon: 'pi pi-fw pi-user',
                        routerLink: ['profile/roles'],
                    },
                ],
            },
           
        ];
    }
}
