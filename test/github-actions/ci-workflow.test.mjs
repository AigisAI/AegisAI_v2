import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const workflowPath = new URL('../../.github/workflows/ci.yml', import.meta.url);

test('ci workflow exists and runs the expected workspace verification commands', () => {
  assert.equal(existsSync(workflowPath), true, 'Expected .github/workflows/ci.yml to exist');

  const workflow = readFileSync(workflowPath, 'utf8');

  assert.match(workflow, /^name:\s*CI/m);
  assert.match(workflow, /^on:\s*$/m);
  assert.match(workflow, /pull_request:\s*[\s\S]*branches:\s*[\s\S]*- dev[\s\S]*- main/m);
  assert.match(workflow, /push:\s*[\s\S]*branches:\s*[\s\S]*- dev[\s\S]*- main/m);
  assert.match(workflow, /actions\/checkout@v4/);
  assert.match(workflow, /pnpm\/action-setup@v4/);
  assert.match(workflow, /actions\/setup-node@v4/);
  assert.match(workflow, /corepack pnpm install --frozen-lockfile/);
  assert.match(workflow, /corepack pnpm lint/);
  assert.match(workflow, /corepack pnpm test/);
  assert.match(workflow, /corepack pnpm typecheck/);
  assert.match(workflow, /corepack pnpm build/);
});
