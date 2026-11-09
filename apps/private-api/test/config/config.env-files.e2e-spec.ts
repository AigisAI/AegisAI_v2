import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { ENV_FILE_PATHS } from '../../src/config/config.paths';

describe('Config environment files', () => {
  it('uses replace-me placeholders for TOKEN_ENCRYPTION_KEY in example env files', () => {
    const examplePaths = [
      resolve(__dirname, '../../.env.example'),
      resolve(__dirname, '../../../../.env.example')
    ];

    for (const examplePath of examplePaths) {
      const contents = readFileSync(examplePath, 'utf8');
      const tokenLine = contents
        .split(/\r?\n/)
        .find((line) => line.startsWith('TOKEN_ENCRYPTION_KEY='));

      expect(tokenLine).toBeDefined();
      expect(tokenLine).toContain('REPLACE_WITH');
      expect(tokenLine).not.toMatch(/TOKEN_ENCRYPTION_KEY=[0-9a-fA-F]{64}$/);
    }
  });

  it('loads env files from deterministic workspace and api locations', () => {
    expect(ENV_FILE_PATHS).toEqual([
      resolve(__dirname, '../../../../.env'),
      resolve(__dirname, '../../.env')
    ]);
  });
});
