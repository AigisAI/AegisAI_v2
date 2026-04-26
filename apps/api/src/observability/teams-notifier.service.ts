import { Injectable, Logger } from '@nestjs/common';

import { ConfigService } from '../config/config.service';

export interface TeamsRuntimeErrorPayload {
  status: number;
  errorCode: string;
  message: string;
  method: string;
  path: string;
  timestamp: string;
}

@Injectable()
export class TeamsNotifierService {
  private readonly logger = new Logger(TeamsNotifierService.name);

  constructor(private readonly config: ConfigService) {}

  async notifyRuntimeError(payload: TeamsRuntimeErrorPayload): Promise<void> {
    const webhookUrl = this.config.getOptional('TEAMS_WEBHOOK_URL');

    if (!webhookUrl) {
      return;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3_000);

    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'content-type': 'application/json'
        },
        body: JSON.stringify(this.buildMessageCard(payload)),
        signal: controller.signal
      });

      if (!response.ok) {
        this.logger.warn(
          `Teams webhook responded with ${response.status} ${response.statusText} for ${payload.errorCode}.`
        );
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown Teams webhook error.';
      this.logger.warn(`Failed to deliver Teams runtime error notification: ${message}`);
    } finally {
      clearTimeout(timeout);
    }
  }

  private buildMessageCard(payload: TeamsRuntimeErrorPayload) {
    return {
      '@type': 'MessageCard',
      '@context': 'https://schema.org/extensions',
      themeColor: 'E81123',
      summary: `AegisAI runtime error: ${payload.errorCode}`,
      title: 'AegisAI production API error',
      sections: [
        {
          facts: [
            { name: 'Status', value: String(payload.status) },
            { name: 'Error code', value: payload.errorCode },
            { name: 'Method', value: payload.method },
            { name: 'Path', value: payload.path },
            { name: 'Timestamp', value: payload.timestamp }
          ],
          text: payload.message
        }
      ]
    };
  }
}
