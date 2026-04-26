import { Injectable } from '@nestjs/common';

import type { ILanguageHandler } from './language-handler.interface';

@Injectable()
export class LanguageHandlerRegistry {
  private readonly handlers = new Map<string, ILanguageHandler>();

  register(handler: ILanguageHandler): void {
    this.handlers.set(handler.getLanguage(), handler);
  }

  get(language: string): ILanguageHandler {
    const handler = this.handlers.get(language);

    if (!handler) {
      throw new Error(`Unsupported language: ${language}`);
    }

    return handler;
  }
}
