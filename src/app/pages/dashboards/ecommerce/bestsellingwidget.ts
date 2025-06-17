import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { ClaudeService } from '../../../services/claude.service';

// PrimeNG imports
import { CardModule } from 'primeng/card';
import { InputTextModule } from 'primeng/inputtext';
import { ButtonModule } from 'primeng/button';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { ScrollPanelModule } from 'primeng/scrollpanel';

@Component({
    selector: 'app-ecommerce-dashboard',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        // PrimeNG modules
        CardModule,
        InputTextModule,
        ButtonModule,
        ProgressSpinnerModule,
        ScrollPanelModule
    ],
    template: `
       <div class="chat-container">
          <p-card header="Claude AI Assistant" [style]="{ 'max-width': '800px', 'margin': '0 auto' }">
              <div class="messages">
                  <p-scrollPanel [style]="{ width: '100%', height: '300px' }">
                      <div *ngIf="responseText" class="response p-3">{{ responseText }}</div>
                  </p-scrollPanel>
              </div>

              <div class="input-area p-fluid mt-3">
                  <div class="p-inputgroup">
                      <input 
                          type="text" 
                          pInputText 
                          [(ngModel)]="userMessage" 
                          placeholder="Posez une question à Claude..." 
                          (keyup.enter)="sendMessage()"
                      />
                      <p-button 
                          icon="pi pi-send" 
                          (click)="sendMessage()" 
                          [disabled]="isLoading || !userMessage.trim()"
                          [loading]="isLoading"
                      ></p-button>
                  </div>
              </div>
          </p-card>
       </div>
    `,
    styles: [`
        .chat-container {
            padding: 20px;
        }
        .messages {
            margin-bottom: 20px;
        }
        .response {
            white-space: pre-wrap;
            line-height: 1.5;
        }
    `]
})
export class EcommerceDashboard {
    userMessage = '';
    responseText = ''; // Pour l'affichage
    isLoading = false;

    constructor(private claudeService: ClaudeService) { }

    async sendMessage() {
        if (!this.userMessage.trim()) return;

        this.isLoading = true;
        try {
            const response = await this.claudeService.generateResponse(this.userMessage);

            // Traiter la réponse comme un any pour éviter les problèmes de type
            // puis extraire le texte
            const responseData = response as any;
            if (responseData && 
                Array.isArray(responseData) && 
                responseData.length > 0 && 
                responseData[0].type === 'text') {
                this.responseText = responseData[0].text;
            } else {
                this.responseText = 'Réponse reçue sans texte';
            }
        } catch (error) {
            console.error('Erreur:', error);
            this.responseText = 'Une erreur est survenue lors de la communication avec Claude.';
        } finally {
            this.isLoading = false;
        }
    }
}