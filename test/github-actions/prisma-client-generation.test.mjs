import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const apiPackagePath = new URL('../../apps/api/package.json', import.meta.url);

test('api scripts generate the Prisma client through corepack before TypeScript-dependent commands run', () => {
  const apiPackage = JSON.parse(readFileSync(apiPackagePath, 'utf8'));
  const scripts = apiPackage.scripts ?? {};

  for (const scriptName of ['build', 'dev', 'test', 'test:e2e', 'typecheck']) {
    assert.match(
      scripts[scriptName] ?? '',
      /corepack pnpm prisma:generate/,
      `Expected apps/api package script "${scriptName}" to generate Prisma client through corepack first`
    );
  }
});
