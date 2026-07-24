import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { ENV_FILE_PATHS } from '../../src/config/config.paths';
import { ENVIRONMENT_VALIDATION_SCHEMA } from '../../src/config/config.schema';

describe('Config environment files', () => {
  it('uses distinct replace-me placeholders for every encryption and attestation key', () => {
    const examplePaths = [
      resolve(__dirname, '../../.env.example'),
      resolve(__dirname, '../../../../.env.example'),
      resolve(__dirname, '../../../../deploy/oracle/.env.example')
    ];

    for (const examplePath of examplePaths) {
      const contents = readFileSync(examplePath, 'utf8');
      const placeholderValues: string[] = [];
      for (const key of [
        'TOKEN_ENCRYPTION_KEY',
        'WORKLOAD_ATTESTATION_KEY',
        'PREFLIGHT_ATTESTATION_KEY'
      ]) {
        const keyLine = contents
          .split(/\r?\n/)
          .find((line) => line.startsWith(`${key}=`));

        expect(keyLine).toBeDefined();
        expect(keyLine).toContain('REPLACE_WITH');
        expect(keyLine).not.toMatch(new RegExp(`${key}=[0-9a-fA-F]{64}$`));
        placeholderValues.push(keyLine?.slice(key.length + 1) ?? '');
      }
      expect(new Set(placeholderValues).size).toBe(placeholderValues.length);
    }
  });

  it('rejects reuse across encryption and attestation keys', () => {
    const environment = {
      NODE_ENV: 'development',
      DATABASE_URL: 'postgresql://postgres:postgres@localhost:5432/aegisai',
      REDIS_URL: 'redis://localhost:6379',
      SESSION_SECRET: 's'.repeat(32),
      CSRF_SECRET: 'c'.repeat(32),
      GITHUB_CLIENT_ID: 'github-client',
      GITHUB_CLIENT_SECRET: 'github-secret',
      GITLAB_CLIENT_ID: 'gitlab-client',
      GITLAB_CLIENT_SECRET: 'gitlab-secret',
      APP_URL: 'http://localhost:3000',
      FRONTEND_URL: 'http://localhost:5173',
      TOKEN_ENCRYPTION_KEY: 'c'.repeat(64),
      WORKLOAD_ATTESTATION_KEY: 'a'.repeat(64),
      PREFLIGHT_ATTESTATION_KEY: 'b'.repeat(64)
    };

    expect(ENVIRONMENT_VALIDATION_SCHEMA.validate(environment).error).toBeUndefined();
    expect(
      ENVIRONMENT_VALIDATION_SCHEMA.validate({
        ...environment,
        WORKLOAD_ATTESTATION_KEY: environment.TOKEN_ENCRYPTION_KEY
      }).error
    ).toBeDefined();
    expect(
      ENVIRONMENT_VALIDATION_SCHEMA.validate({
        ...environment,
        PREFLIGHT_ATTESTATION_KEY: environment.TOKEN_ENCRYPTION_KEY
      }).error
    ).toBeDefined();
    expect(
      ENVIRONMENT_VALIDATION_SCHEMA.validate({
        ...environment,
        PREFLIGHT_ATTESTATION_KEY: environment.WORKLOAD_ATTESTATION_KEY
      }).error
    ).toBeDefined();
    expect(
      ENVIRONMENT_VALIDATION_SCHEMA.validate({
        ...environment,
        TOKEN_ENCRYPTION_KEY: environment.WORKLOAD_ATTESTATION_KEY.toUpperCase()
      }).error
    ).toBeDefined();
  });

  it('loads env files from deterministic workspace and api locations', () => {
    expect(ENV_FILE_PATHS).toEqual([
      resolve(__dirname, '../../../../.env'),
      resolve(__dirname, '../../.env')
    ]);
  });
});
