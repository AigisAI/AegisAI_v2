import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const files = {
  agents: new URL('../../AGENTS.md', import.meta.url),
  readme: new URL('../../README.md', import.meta.url),
  conventions: new URL('../../docs/github-conventions.md', import.meta.url),
  ci: new URL('../../.github/workflows/ci.yml', import.meta.url),
  quickstart: new URL('../../specs/002-production-scan-architecture/quickstart.md', import.meta.url),
  spec: new URL('../../specs/002-production-scan-architecture/spec.md', import.meta.url),
  plan: new URL('../../specs/002-production-scan-architecture/plan.md', import.meta.url),
  research: new URL('../../specs/002-production-scan-architecture/research.md', import.meta.url),
  dataModel: new URL('../../specs/002-production-scan-architecture/data-model.md', import.meta.url),
  tasks: new URL('../../specs/002-production-scan-architecture/tasks.md', import.meta.url),
  contract: new URL('../../specs/002-production-scan-architecture/contracts/scan-architecture.md', import.meta.url),
  checklist: new URL('../../specs/002-production-scan-architecture/checklists/requirements.md', import.meta.url)
};

const readNormalizedText = (fileUrl) => readFileSync(fileUrl, 'utf8').replace(/\r\n/g, '\n');

test('production scan architecture is the active feature package', () => {
  for (const [name, fileUrl] of Object.entries(files)) {
    assert.equal(existsSync(fileUrl), true, `Expected ${name} file to exist at ${fileUrl.pathname}`);
  }

  const agents = readNormalizedText(files.agents);
  const readme = readNormalizedText(files.readme);
  const conventions = readNormalizedText(files.conventions);
  const quickstart = readNormalizedText(files.quickstart);
  const spec = readNormalizedText(files.spec);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);

  assert.match(agents, /002-production-scan-architecture/);
  assert.match(agents, /Security Scan SaaS Final Specification\.docx/);
  assert.match(readme, /002-production-scan-architecture/);
  assert.match(conventions, /SPECIFY_FEATURE = "002-production-scan-architecture"/);

  assert.match(quickstart, /Security Scan SaaS Final Specification\.docx/);
  assert.match(quickstart, /Control Plane/);
  assert.match(quickstart, /Scan Plane/);
  assert.match(quickstart, /AI Plane/);
  assert.match(quickstart, /Data and Security Plane/);
  assert.match(quickstart, /Oracle VPS.*dev\/demo/i);

  assert.match(spec, /GitHub App/);
  assert.match(spec, /GitLab Cloud/);
  assert.match(spec, /deterministic scanner/i);
  assert.match(spec, /MUST NOT execute customer code/);

  assert.match(plan, /scanner-first pipeline/i);
  assert.match(plan, /Token Broker/);
  assert.match(plan, /policy-as-code/i);

  assert.match(contract, /CanonicalScanKey/);
  assert.match(contract, /EvidencePack/);
  assert.match(contract, /PolicyDecision/);
});

test('production scan architecture completion gate stays synchronized between quickstart and CI', () => {
  const readme = readNormalizedText(files.readme);
  const ci = readNormalizedText(files.ci);
  const quickstart = readNormalizedText(files.quickstart);
  const tasks = readNormalizedText(files.tasks);

  const requiredCommands = [
    'corepack pnpm lint',
    'corepack pnpm test',
    'corepack pnpm typecheck',
    'corepack pnpm build',
    'corepack pnpm --filter @aegisai/api prisma:validate',
    'git diff --check'
  ];

  for (const command of requiredCommands) {
    assert.match(quickstart, new RegExp(command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.match(ci, new RegExp(command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }

  assert.match(readme, /specs\/002-production-scan-architecture\/quickstart\.md/);
  assert.match(readme, /\.github\/workflows\/ci\.yml/);
  assert.doesNotMatch(readme, /`corepack pnpm/);
  assert.doesNotMatch(tasks, /Mirror the 002 completion gate in README/);
  assert.match(tasks, /Point README completion guidance at the 002 quickstart and CI workflow without duplicating command checklists/);
  assert.match(ci, /DATABASE_URL:\s*postgresql:\/\/postgres:postgres@localhost:5432\/aegisai/);
});

test('production scan architecture first milestone has no open non-deferred tasks', () => {
  const tasks = readNormalizedText(files.tasks);
  const checklist = readNormalizedText(files.checklist);
  const deferredSection = tasks.split('\n## Deferred\n')[1] ?? '';
  const activeTaskSection = tasks.split('\n## Deferred\n')[0];

  const openActiveTasks = activeTaskSection
    .split('\n')
    .filter((line) => /^- \[ \]/.test(line));
  assert.deepEqual(openActiveTasks, []);

  assert.match(tasks, /## Phase 46: Production Architecture First Milestone Completion Guardrail Slice/);
  assert.match(tasks, /T182 Add active feature tests that fail when non-deferred 002 tasks are unchecked/);
  assert.match(tasks, /T183 Verify the 002 requirements checklist remains fully checked/);
  assert.match(tasks, /T184 Keep trained production AI inference as the only deferred milestone item/);

  const openChecklistItems = checklist
    .split('\n')
    .filter((line) => /^- \[ \]/.test(line));
  assert.deepEqual(openChecklistItems, []);

  assert.match(deferredSection, /- \[ \] Implement trained production AI detector\/planner model inference/);
  assert.equal(
    deferredSection
      .split('\n')
      .filter((line) => /^- \[ \]/.test(line)).length,
    1
  );
});
