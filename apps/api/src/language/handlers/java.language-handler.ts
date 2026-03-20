import { Injectable } from '@nestjs/common';

import type { ILanguageHandler } from '../language-handler.interface';

@Injectable()
export class JavaLanguageHandler implements ILanguageHandler {
  getLanguage(): string {
    return 'java';
  }

  getFileExtensions(): string[] {
    return ['.java'];
  }

  getExcludePatterns(): string[] {
    return [
      '**/test/**',
      '**/generated/**',
      '**/build/**',
      '**/target/**',
      '**/node_modules/**',
      '**/vendor/**'
    ];
  }

  getMaxFileSize(): number {
    return 100 * 1024;
  }

  supports(path: string): boolean {
    return this.getFileExtensions().some((extension) => path.endsWith(extension));
  }
}
