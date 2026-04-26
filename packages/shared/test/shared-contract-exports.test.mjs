import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const files = {
  common: new URL('../src/types/common.ts', import.meta.url),
  auth: new URL('../src/types/auth.ts', import.meta.url),
  repo: new URL('../src/types/repo.ts', import.meta.url),
  scan: new URL('../src/types/scan.ts', import.meta.url),
  vulnerability: new URL('../src/types/vulnerability.ts', import.meta.url),
  dashboard: new URL('../src/types/dashboard.ts', import.meta.url),
  report: new URL('../src/types/report.ts', import.meta.url),
  index: new URL('../src/index.ts', import.meta.url)
};

test('shared contract modules exist and are re-exported from the package root', () => {
  for (const [name, fileUrl] of Object.entries(files)) {
    assert.equal(existsSync(fileUrl), true, `Expected ${name} file to exist at ${fileUrl.pathname}`);
  }

  const indexContent = readFileSync(files.index, 'utf8');

  for (const moduleName of ['common', 'auth', 'repo', 'scan', 'vulnerability', 'dashboard', 'report']) {
    assert.match(
      indexContent,
      new RegExp(`export \\* from './types/${moduleName}'`),
      `Expected packages/shared/src/index.ts to re-export ./types/${moduleName}`
    );
  }
});
