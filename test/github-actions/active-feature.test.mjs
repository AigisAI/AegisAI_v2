import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const files = {
  agents: new URL('../../AGENTS.md', import.meta.url),
  readme: new URL('../../README.md', import.meta.url),
  conventions: new URL('../../docs/github-conventions.md', import.meta.url),
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
