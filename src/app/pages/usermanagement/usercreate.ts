import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { OpenAIService } from '../../services/open-ai.service';

// PrimeNG imports
import { CardModule } from 'primeng/card';
import { InputTextModule } from 'primeng/inputtext';
import { ButtonModule } from 'primeng/button';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { ScrollPanelModule } from 'primeng/scrollpanel';

@Component({
    selector: 'app-openai-chat',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        CardModule,
        InputTextModule,
        ButtonModule,
        ProgressSpinnerModule,
        ScrollPanelModule
    ],
    template: `
    <div class="chat-container">
        <p-card header="OpenAI Assistant" [style]="{ 'max-width': '800px', 'margin': '0 auto' }">
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
                        placeholder="Posez une question à GPT-4..." 
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
    </div>`,
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
export class UserCreate  {
    userMessage = '';
    responseText = '';
    isLoading = false;

    constructor(private openaiService: OpenAIService) { }

    sendMessage() {
        if (!this.userMessage.trim()) return;

        this.isLoading = true;
        this.openaiService.generateResponse(this.userMessage)
            .subscribe({
                next: (response) => {
                    // Extraction du contenu depuis la réponse de l'API OpenAI
                    if (response && response.choices && response.choices.length > 0) {
                        this.responseText = response.choices[0].message.content;
                    } else {
                        this.responseText = 'Format de réponse inattendu';
                    }
                    this.userMessage = ''; // Vider le champ après envoi
                },
                error: (error) => {
                    console.error('Erreur:', error);
                    this.responseText = 'Une erreur est survenue lors de la communication avec OpenAI.';
                },
                complete: () => {
                    this.isLoading = false;
                }
            });
    }
}