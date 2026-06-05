import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const files = {
  agents: new URL('../../AGENTS.md', import.meta.url),
  readme: new URL('../../README.md', import.meta.url),
  conventions: new URL('../../docs/github-conventions.md', import.meta.url),
  ci: new URL('../../.github/workflows/ci.yml', import.meta.url),
  quickstart: new URL('../../specs/005-production-deployment-operations/quickstart.md', import.meta.url),
  spec: new URL('../../specs/005-production-deployment-operations/spec.md', import.meta.url),
  plan: new URL('../../specs/005-production-deployment-operations/plan.md', import.meta.url),
  research: new URL('../../specs/005-production-deployment-operations/research.md', import.meta.url),
  dataModel: new URL('../../specs/005-production-deployment-operations/data-model.md', import.meta.url),
  tasks: new URL('../../specs/005-production-deployment-operations/tasks.md', import.meta.url),
  contract: new URL('../../specs/005-production-deployment-operations/contracts/deployment-operations.md', import.meta.url),
  checklist: new URL('../../specs/005-production-deployment-operations/checklists/requirements.md', import.meta.url),
  completedRuntimeQuickstart: new URL('../../specs/004-production-runtime-infrastructure/quickstart.md', import.meta.url),
  completedRuntimeTasks: new URL('../../specs/004-production-runtime-infrastructure/tasks.md', import.meta.url),
  completedRuntimeChecklist: new URL('../../specs/004-production-runtime-infrastructure/checklists/requirements.md', import.meta.url),
  completedAiQuickstart: new URL('../../specs/003-production-ai-inference-runtime/quickstart.md', import.meta.url),
  completedAiTasks: new URL('../../specs/003-production-ai-inference-runtime/tasks.md', import.meta.url),
  completedAiChecklist: new URL('../../specs/003-production-ai-inference-runtime/checklists/requirements.md', import.meta.url),
  completedArchitectureQuickstart: new URL('../../specs/002-production-scan-architecture/quickstart.md', import.meta.url),
  completedArchitectureTasks: new URL('../../specs/002-production-scan-architecture/tasks.md', import.meta.url),
  completedArchitectureChecklist: new URL('../../specs/002-production-scan-architecture/checklists/requirements.md', import.meta.url)
};

const readNormalizedText = (fileUrl) => readFileSync(fileUrl, 'utf8').replace(/\r\n/g, '\n');

test('production deployment operations is the active feature package', () => {
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

  assert.match(agents, /005-production-deployment-operations/);
  assert.match(agents, /Security Scan SaaS Final Specification\.docx/);
  assert.match(readme, /005-production-deployment-operations/);
  assert.match(conventions, /SPECIFY_FEATURE = "005-production-deployment-operations"/);

  assert.match(quickstart, /Security Scan SaaS Final Specification\.docx/);
  assert.match(quickstart, /live production Kubernetes cluster provisioning/i);
  assert.match(quickstart, /provider-specific microVM platform rollout/i);
  assert.match(quickstart, /no local development defaults/i);
  assert.match(quickstart, /004-production-runtime-infrastructure/);
  assert.match(quickstart, /003-production-ai-inference-runtime/);
  assert.match(quickstart, /002-production-scan-architecture/);

  assert.match(spec, /production cluster provisioning/i);
  assert.match(spec, /provider-specific microVM platform rollout/i);
  assert.match(spec, /MUST NOT introduce provider credentials as local development defaults/i);

  assert.match(plan, /deployment operations/i);
  assert.match(plan, /provider credential boundary/i);
  assert.match(plan, /operational rollout/i);

  assert.match(contract, /ProductionClusterProvisioning/);
  assert.match(contract, /MicroVmPlatformRollout/);
  assert.match(contract, /DeploymentCredentialBoundary/);
});

test('production deployment operations completion gate stays synchronized between quickstart and CI', () => {
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

  assert.match(readme, /specs\/005-production-deployment-operations\/quickstart\.md/);
  assert.match(readme, /\.github\/workflows\/ci\.yml/);
  assert.doesNotMatch(readme, /`corepack pnpm/);
  assert.doesNotMatch(tasks, /Mirror the 005 completion gate in README/);
  assert.match(tasks, /Point README completion guidance at the 005 quickstart and CI workflow without duplicating command checklists/);
  assert.match(ci, /DATABASE_URL:\s*postgresql:\/\/postgres:postgres@localhost:5432\/aegisai/);
});

test('completed production runtime infrastructure baseline hands live rollout follow-up to 005', () => {
  const tasks = readNormalizedText(files.completedRuntimeTasks);
  const checklist = readNormalizedText(files.completedRuntimeChecklist);
  const quickstart = readNormalizedText(files.completedRuntimeQuickstart);
  const activeTaskSection = tasks.split('\n## Deferred')[0];

  const openActiveTasks = activeTaskSection
    .split('\n')
    .filter((line) => /^- \[ \]/.test(line));
  assert.deepEqual(openActiveTasks, []);

  const openChecklistItems = checklist
    .split('\n')
    .filter((line) => /^- \[ \]/.test(line));
  assert.deepEqual(openChecklistItems, []);

  assert.match(quickstart, /005-production-deployment-operations/);
  assert.match(tasks, /Live production Kubernetes cluster provisioning moved to `005-production-deployment-operations`/);
  assert.match(tasks, /Provider-specific microVM platform rollout moved to `005-production-deployment-operations`/);
});

test('completed production AI inference baseline hands infrastructure follow-up to 004', () => {
  const tasks = readNormalizedText(files.completedAiTasks);
  const checklist = readNormalizedText(files.completedAiChecklist);
  const quickstart = readNormalizedText(files.completedAiQuickstart);
  const activeTaskSection = tasks.split('\n## Deferred')[0];

  const openActiveTasks = activeTaskSection
    .split('\n')
    .filter((line) => /^- \[ \]/.test(line));
  assert.deepEqual(openActiveTasks, []);

  const openChecklistItems = checklist
    .split('\n')
    .filter((line) => /^- \[ \]/.test(line));
  assert.deepEqual(openChecklistItems, []);

  assert.match(quickstart, /004-production-runtime-infrastructure/);
  assert.match(tasks, /Kubernetes production AI Plane deployment manifests and runtime autoscaling moved to `004-production-runtime-infrastructure`/);
  assert.match(tasks, /microVM-backed scanner provisioning moved to `004-production-runtime-infrastructure`/);
});

test('completed production scan architecture baseline keeps only the AI inference follow-up deferred', () => {
  const tasks = readNormalizedText(files.completedArchitectureTasks);
  const checklist = readNormalizedText(files.completedArchitectureChecklist);
  const quickstart = readNormalizedText(files.completedArchitectureQuickstart);
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

  assert.match(quickstart, /supersedes `001-aegisai-mvp-foundation`/);
  assert.match(deferredSection, /- \[ \] Implement trained production AI detector\/planner model inference/);
  assert.equal(
    deferredSection
      .split('\n')
      .filter((line) => /^- \[ \]/.test(line)).length,
    1
  );
});
