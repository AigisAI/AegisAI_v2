import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const files = {
  agents: new URL('../../AGENTS.md', import.meta.url),
  readme: new URL('../../README.md', import.meta.url),
  conventions: new URL('../../docs/github-conventions.md', import.meta.url),
  ci: new URL('../../.github/workflows/ci.yml', import.meta.url),
  quickstart: new URL('../../specs/006-production-sast-runtime-design/quickstart.md', import.meta.url),
  spec: new URL('../../specs/006-production-sast-runtime-design/spec.md', import.meta.url),
  plan: new URL('../../specs/006-production-sast-runtime-design/plan.md', import.meta.url),
  research: new URL('../../specs/006-production-sast-runtime-design/research.md', import.meta.url),
  dataModel: new URL('../../specs/006-production-sast-runtime-design/data-model.md', import.meta.url),
  tasks: new URL('../../specs/006-production-sast-runtime-design/tasks.md', import.meta.url),
  contract: new URL('../../specs/006-production-sast-runtime-design/contracts/sast-runtime.md', import.meta.url),
  threatModel: new URL('../../specs/006-production-sast-runtime-design/threat-model.md', import.meta.url),
  ruleGovernance: new URL('../../specs/006-production-sast-runtime-design/rule-governance.md', import.meta.url),
  qualityGates: new URL('../../specs/006-production-sast-runtime-design/quality-gates.md', import.meta.url),
  languageProfileExtension: new URL('../../specs/006-production-sast-runtime-design/language-profile-extension.md', import.meta.url),
  checklist: new URL('../../specs/006-production-sast-runtime-design/checklists/requirements.md', import.meta.url),
  sharedIndex: new URL('../../packages/shared/src/index.ts', import.meta.url),
  sharedSastRuntime: new URL('../../packages/shared/src/types/sast-runtime.ts', import.meta.url),
  sharedSastTest: new URL('../../packages/shared/test/sast-runtime.test.mjs', import.meta.url),
  sharedSastBehaviorTest: new URL('../../packages/shared/test/sast-runtime-behavior.test.mjs', import.meta.url),
  sharedSastPlanning: new URL('../../packages/shared/src/types/sast-planning.ts', import.meta.url),
  sharedSastPlanningTest: new URL('../../packages/shared/test/sast-planning.test.mjs', import.meta.url),
  sharedSastNormalization: new URL('../../packages/shared/src/types/sast-normalization.ts', import.meta.url),
  sharedSastNormalizationTest: new URL('../../packages/shared/test/sast-normalization.test.mjs', import.meta.url),
  sharedSastTrivyNormalization: new URL('../../packages/shared/src/types/sast-trivy-normalization.ts', import.meta.url),
  sharedSastTrivyNormalizationTest: new URL('../../packages/shared/test/sast-trivy-normalization.test.mjs', import.meta.url),
  sharedSastSbomInventory: new URL('../../packages/shared/src/types/sast-sbom-inventory.ts', import.meta.url),
  sharedSastSbomInventoryTest: new URL('../../packages/shared/test/sast-sbom-inventory.test.mjs', import.meta.url),
  sharedSastSecretRedaction: new URL('../../packages/shared/src/types/sast-secret-redaction.ts', import.meta.url),
  sharedSastSecretRedactionTest: new URL('../../packages/shared/test/sast-secret-redaction.test.mjs', import.meta.url),
  apiSastPlanner: new URL('../../apps/api/src/control-plane/sast-scan-planner.service.ts', import.meta.url),
  apiSastQueueAdmission: new URL('../../apps/api/src/control-plane/sast-queue-admission.service.ts', import.meta.url),
  apiSastPlanningController: new URL('../../apps/api/src/control-plane/sast-planning.controller.ts', import.meta.url),
  apiSastPlannerTest: new URL('../../apps/api/test/control-plane/sast-scan-planner.service.e2e-spec.ts', import.meta.url),
  apiOpenGrepNormalizer: new URL('../../apps/api/src/scan-plane/opengrep-sarif-normalizer.ts', import.meta.url),
  apiOpenGrepNormalizerTest: new URL('../../apps/api/test/scan-plane/opengrep-sarif-normalizer.e2e-spec.ts', import.meta.url),
  openGrepGoldenFixture: new URL('../../apps/api/test/fixtures/opengrep-sarif/upstream-compatible.sarif.json', import.meta.url),
  apiTrivyNormalizer: new URL('../../apps/api/src/scan-plane/trivy-json-normalizer.ts', import.meta.url),
  apiTrivyNormalizerTest: new URL('../../apps/api/test/scan-plane/trivy-json-normalizer.e2e-spec.ts', import.meta.url),
  trivyGoldenFixture: new URL('../../apps/api/test/fixtures/trivy-json/upstream-compatible.trivy.json', import.meta.url),
  trivyExpectedFixture: new URL('../../apps/api/test/fixtures/trivy-json/upstream-compatible.expected.json', import.meta.url),
  trivyMaliciousFixture: new URL('../../apps/api/test/fixtures/trivy-json/malicious-modified-license.trivy.json', import.meta.url),
  apiSyftCycloneDxIngestor: new URL('../../apps/api/src/scan-plane/syft-cyclonedx-inventory-ingestor.ts', import.meta.url),
  apiSpdxLicenseList: new URL('../../apps/api/src/scan-plane/spdx-license-list-3.28.ts', import.meta.url),
  apiSyftCycloneDxIngestorTest: new URL('../../apps/api/test/scan-plane/syft-cyclonedx-inventory-ingestor.e2e-spec.ts', import.meta.url),
  syftCycloneDxGoldenFixture: new URL('../../apps/api/test/fixtures/syft-cyclonedx/upstream-compatible.cdx.json', import.meta.url),
  syftCycloneDxExpectedFixture: new URL('../../apps/api/test/fixtures/syft-cyclonedx/upstream-compatible.expected.json', import.meta.url),
  apiSastSecretRedaction: new URL('../../apps/api/src/scan-plane/sast-secret-redaction.service.ts', import.meta.url),
  apiSastSecretRedactionTest: new URL('../../apps/api/test/scan-plane/sast-secret-redaction.e2e-spec.ts', import.meta.url),
  apiScanPlaneModule: new URL('../../apps/api/src/scan-plane/scan-plane.module.ts', import.meta.url),
  completedDeploymentQuickstart: new URL('../../specs/005-production-deployment-operations/quickstart.md', import.meta.url),
  completedDeploymentTasks: new URL('../../specs/005-production-deployment-operations/tasks.md', import.meta.url),
  completedDeploymentChecklist: new URL('../../specs/005-production-deployment-operations/checklists/requirements.md', import.meta.url),
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

const assertNoOpenItemsBeforeDeferred = (contents) => {
  const activeSection = contents.split('\n## Deferred')[0];
  const openItems = activeSection.split('\n').filter((line) => /^- \[ \]/.test(line));
  assert.deepEqual(openItems, []);
};

const assertChecklistComplete = (contents) => {
  const openItems = contents.split('\n').filter((line) => /^- \[ \]/.test(line));
  assert.deepEqual(openItems, []);
};

test('production SAST runtime design is the active feature package', () => {
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

  assert.match(agents, /Feature id: `006-production-sast-runtime-design`/);
  assert.match(agents, /Security Scan SaaS Final Specification\.docx/);
  assert.doesNotMatch(agents, /C:\\Users\\/);
  assert.match(readme, /Active milestone \| \[`006-production-sast-runtime-design`/);
  assert.doesNotMatch(readme, /C:\\Users\\/);
  assert.match(conventions, /SPECIFY_FEATURE = "006-production-sast-runtime-design"/);

  assert.match(quickstart, /Security Scan SaaS Final Specification\.docx/);
  assert.match(quickstart, /OpenGrep is authoritative only for source-code SAST/);
  assert.match(quickstart, /Trivy is authoritative for dependency vulnerability, secret, and IaC/);
  assert.match(quickstart, /Syft is authoritative for source-workspace SBOM/);
  assert.match(quickstart, /005-production-deployment-operations/);
  assert.match(quickstart, /004-production-runtime-infrastructure/);
  assert.match(quickstart, /003-production-ai-inference-runtime/);
  assert.match(quickstart, /002-production-scan-architecture/);
  assert.doesNotMatch(quickstart, /C:\\Users\\/);

  assert.match(spec, /JAVA_FAST_V1/);
  assert.match(spec, /JAVA_DEEP_V1/);
  assert.match(spec, /COMMON_DEEP_V1/);
  assert.match(spec, /Stable finding identity MUST exclude branch, commit SHA, and line numbers/);
  assert.match(spec, /AI output MUST remain advisory/);

  assert.match(plan, /hostile-input preflight/i);
  assert.match(plan, /mock scanner remains a test fixture only/i);
  assert.match(contract, /Repository Fetch Contract/);
  assert.match(contract, /Result Ingress Contract/);
  assert.match(contract, /Stable Fingerprint Contract/);
  assert.match(contract, /Coverage Contract/);
  assert.match(contract, /Cleanup Contract/);
});

test('SAST threat, rule, and quantitative quality decisions are explicit', () => {
  const threatModel = readNormalizedText(files.threatModel);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);
  const qualityGates = readNormalizedText(files.qualityGates);
  const languageProfileExtension = readNormalizedText(files.languageProfileExtension);
  const dataModel = readNormalizedText(files.dataModel);
  const research = readNormalizedText(files.research);

  assert.match(threatModel, /symlink escape/i);
  assert.match(threatModel, /output bomb/i);
  assert.match(threatModel, /prompt-injection strings/i);
  assert.match(ruleGovernance, /DRAFT -> VALIDATED -> CANARY -> ACTIVE/);
  assert.match(ruleGovernance, /platform-secret keyed hash/);
  for (const requiredScope of [
    'scanner version',
    'bundle digest',
    'semantic rule ID',
    'tenant',
    'repository binding',
    'capability',
    'profile',
    'external publication',
    'global SAST runtime'
  ]) {
    assert.match(ruleGovernance, new RegExp(requiredScope, 'i'));
  }
  assert.match(ruleGovernance, /last-known-good digest/);
  assert.match(qualityGates, /Must-detect recall \| >= 95%/);
  assert.match(qualityGates, /Critical\/High precision \| >= 90%/);
  assert.match(qualityGates, /Cross-tenant\/secret\/sandbox\/stale-publication events \| exactly 0/);
  assert.match(qualityGates, /Fast\/Deep scans through queue, result ingress, policy, evidence, and cleanup/);
  assert.match(dataModel, /RuleBundlePromotionEvidence/);
  assert.match(dataModel, /SastQualityEvaluation/);
  assert.match(research, /Split Scanner Responsibilities/);
  assert.match(research, /No Build-Assisted Analysis in v1/);
  assert.match(languageProfileExtension, /COMMON_DEEP_V1/);
  assert.match(languageProfileExtension, /Polyglot multi-profile execution is a future contract/);
  assert.match(languageProfileExtension, /UI\/API\/policy wording cannot overstate SAST coverage/);
});

test('shared SAST contracts encode fail-closed production invariants', () => {
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const sharedSastRuntime = readNormalizedText(files.sharedSastRuntime);
  const sharedSastTest = readNormalizedText(files.sharedSastTest);
  const sharedSastBehaviorTest = readNormalizedText(files.sharedSastBehaviorTest);

  assert.match(sharedIndex, /export \* from '.\/types\/sast-runtime';/);
  assert.match(sharedSastRuntime, /SAST_SCANNER_RESPONSIBILITIES/);
  assert.match(sharedSastRuntime, /JAVA_FAST_V1/);
  assert.match(sharedSastRuntime, /CUSTOMER_CODE_EXECUTION/);
  assert.match(sharedSastRuntime, /buildFindingFingerprintPreimage/);
  assert.match(sharedSastRuntime, /evaluateSastCoverage/);
  assert.match(sharedSastRuntime, /isSastEvidencePolicySafe/);
  assert.match(sharedSastRuntime, /isRuleBundlePromotionReady/);
  assert.match(sharedSastRuntime, /areSastProductionQualityGatesSatisfied/);
  assert.match(sharedSastTest, /finding fingerprints exclude unstable line, branch, and commit coordinates/);
  assert.match(sharedSastTest, /coverage decisions suppress publication for partial, stale, or security-blocked scans/);
  assert.match(sharedSastBehaviorTest, /coverage is complete only for accepted authoritative required capabilities/);
  assert.match(sharedSastBehaviorTest, /promotion, canary, and production gates enforce samples, approvals, and zero tolerance/);
});

test('SAST Phase 4 planner runtime is implemented and guarded by executable tests', () => {
  const sharedSastPlanning = readNormalizedText(files.sharedSastPlanning);
  const sharedSastPlanningTest = readNormalizedText(files.sharedSastPlanningTest);
  const apiSastPlanner = readNormalizedText(files.apiSastPlanner);
  const apiSastQueueAdmission = readNormalizedText(files.apiSastQueueAdmission);
  const apiSastPlanningController = readNormalizedText(files.apiSastPlanningController);
  const apiSastPlannerTest = readNormalizedText(files.apiSastPlannerTest);
  const tasks = readNormalizedText(files.tasks);

  assert.match(sharedSastPlanning, /TrustedSastRepositoryMetadata/);
  assert.match(sharedSastPlanning, /buildSastCanonicalScanKeyPreimage/);
  assert.match(sharedSastPlanning, /TENANT_ROUND_ROBIN/);
  assert.match(sharedSastPlanning, /UNSUPPORTED_POLYGLOT_PROFILE/);
  assert.match(apiSastPlanner, /class SastScanPlannerService/);
  assert.match(apiSastPlanner, /isSastScanPlanValid/);
  assert.match(apiSastQueueAdmission, /class SastQueueAdmissionService/);
  assert.match(apiSastQueueAdmission, /snapshotVersion/);
  assert.match(apiSastQueueAdmission, /QUEUE_USAGE_STALE/);
  assert.match(apiSastPlanningController, /InternalServiceGuard/);
  assert.match(apiSastPlanningController, /SastScanPlannerService/);
  assert.match(sharedSastPlanningTest, /canonical scan identity includes fixed source and every executable artifact digest/);
  assert.match(apiSastPlannerTest, /binds every execution artifact digest into the canonical scan key/);
  assert.match(apiSastPlannerTest, /orders one lane by deterministic tenant round-robin fairness/);
  assert.match(apiSastPlannerTest, /atomically reserves queue capacity/);

  for (const taskId of ['T018', 'T019', 'T020', 'T021']) {
    assert.match(tasks, new RegExp(`- \\[x\\] ${taskId}\\b`));
  }
});

test('SAST T032 OpenGrep normalization is versioned, transient, and fixture-guarded', () => {
  const sharedNormalization = readNormalizedText(files.sharedSastNormalization);
  const sharedNormalizationTest = readNormalizedText(
    files.sharedSastNormalizationTest
  );
  const normalizer = readNormalizedText(files.apiOpenGrepNormalizer);
  const normalizerTest = readNormalizedText(files.apiOpenGrepNormalizerTest);
  const fixture = readNormalizedText(files.openGrepGoldenFixture);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const contract = readNormalizedText(files.contract);
  const spec = readNormalizedText(files.spec);
  const plan = readNormalizedText(files.plan);
  const research = readNormalizedText(files.research);
  const dataModel = readNormalizedText(files.dataModel);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);

  assert.match(sharedNormalization, /opengrep-sarif-normalizer-v1/);
  assert.match(sharedNormalization, /durablePersistenceAllowed:\s*false/);
  assert.doesNotMatch(sharedNormalization, /\bstableFingerprint\b/u);
  assert.match(sharedNormalizationTest, /without inventing durable finding state/);
  assert.match(normalizer, /class OpenGrepSarifNormalizer/);
  assert.match(normalizer, /Opengrep OSS/);
  assert.match(normalizer, /matchBasedId\/v1/);
  assert.match(normalizer, /buildSastScanPlanDigestPreimage/);
  assert.match(normalizer, /bundleRulesById/);
  assert.match(normalizerTest, /byte-exactly across chunking/);
  assert.match(normalizerTest, /not\.toContain\('super-secret'\)/);
  assert.match(
    normalizerTest,
    /isOpenGrepSarifNormalizationBatchShapeValid/
  );
  assert.match(fixture, /"uriBaseId": "%SRCROOT%"/);
  assert.match(tasks, /- \[x\] T032\b/);
  assert.match(quickstart, /T032 produces only canonical/);
  assert.match(quickstart, /immutable plan digest/);
  assert.match(contract, /OpenGrep SARIF adapter v1/);
  assert.match(contract, /129 or more rejects the complete batch/);
  assert.match(
    spec,
    /OpenGrep, Trivy secret, and Trivy IaC semantic identity\s+MUST resolve from signed bundle metadata/
  );
  assert.match(plan, /signed rule-bundle manifest/);
  assert.match(research, /signed bundle\s+manifest projection/);
  assert.match(dataModel, /immutable `planDigest`/);
  assert.match(threatModel, /Rule identity forgery/);
  assert.match(qualityGates, /semantic-rule\/revision resolution/);
  assert.match(
    ruleGovernance,
    /normalizers must resolve\s+`ruleRevision`/i
  );
});

test('SAST T033 Trivy normalization is capability-safe, non-authoritative, and fixture-guarded', () => {
  const sharedNormalization = readNormalizedText(files.sharedSastNormalization);
  const sharedTrivyNormalization = readNormalizedText(
    files.sharedSastTrivyNormalization
  );
  const sharedTrivyNormalizationTest = readNormalizedText(
    files.sharedSastTrivyNormalizationTest
  );
  const normalizer = readNormalizedText(files.apiTrivyNormalizer);
  const normalizerTest = readNormalizedText(files.apiTrivyNormalizerTest);
  const fixture = readNormalizedText(files.trivyGoldenFixture);
  const expected = readNormalizedText(files.trivyExpectedFixture);
  const maliciousFixture = readNormalizedText(files.trivyMaliciousFixture);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const contract = readNormalizedText(files.contract);
  const spec = readNormalizedText(files.spec);
  const plan = readNormalizedText(files.plan);
  const research = readNormalizedText(files.research);
  const dataModel = readNormalizedText(files.dataModel);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(sharedTrivyNormalization, /trivy-json-normalizer-v1/);
  assert.match(
    sharedTrivyNormalization,
    /vulnerabilityDatabaseDigest/
  );
  assert.match(sharedTrivyNormalization, /durablePersistenceAllowed:\s*false/);
  assert.match(sharedNormalization, /platformPolicyAuthority:\s*false/);
  assert.match(sharedNormalization, /secretPayloadDiscarded:\s*true/);
  assert.match(sharedNormalization, /VULNERABILITY_DATABASE/);
  assert.match(
    sharedTrivyNormalizationTest,
    /denies scanner policy authority/
  );
  assert.match(normalizer, /class TrivyJsonNormalizer/);
  assert.match(normalizer, /ExperimentalModifiedFindings/);
  assert.match(normalizer, /platformPolicyAuthority:\s*false/);
  assert.match(normalizer, /SCANNER_LOCATION_OMITTED/);
  assert.match(
    normalizerTest,
    /normalizes vulnerability, IaC, direct secret, and modified secret records byte-exactly across chunking/
  );
  assert.match(
    normalizerTest,
    /retains modified scanner status only as non-authoritative provenance/
  );
  assert.match(
    normalizerTest,
    /expect\(serialized\)\.not\.toContain\(forbidden\)/
  );
  assert.match(normalizerTest, /AKIA_SYNTHETIC_NEVER_COPY/);
  assert.match(fixture, /"ExperimentalModifiedFindings"/);
  assert.match(expected, /"platformPolicyAuthority": false/);
  assert.match(maliciousFixture, /"Type": "license"/);
  assert.match(tasks, /- \[x\] T033\b/);
  assert.match(
    quickstart,
    /T033 golden and malicious fixtures prove chunk-invariant/
  );
  assert.match(contract, /Trivy JSON adapter v1/);
  assert.match(contract, /secret `Match`, `Code`/);
  assert.match(spec, /FR-031a/);
  assert.match(plan, /scanner disposition remains non-authoritative/);
  assert.match(research, /Normalize the Pinned Trivy JSON Producer/);
  assert.match(dataModel, /`scannerDisposition` with `DIRECT\|MODIFIED`/);
  assert.match(threatModel, /Trivy disposition smuggling/);
  assert.match(qualityGates, /Trivy golden-fixture equality/);
});

test('SAST T034 Syft CycloneDX ingestion is inventory-only, transient, and fixture-guarded', () => {
  const sharedInventory = readNormalizedText(
    files.sharedSastSbomInventory
  );
  const sharedInventoryTest = readNormalizedText(
    files.sharedSastSbomInventoryTest
  );
  const ingestor = readNormalizedText(files.apiSyftCycloneDxIngestor);
  const spdxLicenseList = readNormalizedText(
    files.apiSpdxLicenseList
  );
  const ingestorTest = readNormalizedText(
    files.apiSyftCycloneDxIngestorTest
  );
  const fixture = readNormalizedText(files.syftCycloneDxGoldenFixture);
  const expected = readNormalizedText(
    files.syftCycloneDxExpectedFixture
  );
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const contract = readNormalizedText(files.contract);
  const spec = readNormalizedText(files.spec);
  const plan = readNormalizedText(files.plan);
  const research = readNormalizedText(files.research);
  const dataModel = readNormalizedText(files.dataModel);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(
    sharedInventory,
    /syft-cyclonedx-inventory-ingestor-v1/
  );
  assert.match(sharedInventory, /SYFT_CYCLONEDX_PRODUCER_VERSION = '1\.44\.0'/);
  assert.match(sharedInventory, /mayCreateFindings:\s*false/);
  assert.match(sharedInventory, /aiPayloadEligible:\s*false/);
  assert.match(sharedInventory, /durablePersistenceAllowed:\s*false/);
  assert.match(
    sharedInventoryTest,
    /canonical transient Syft CycloneDX inventory contract/
  );
  assert.match(ingestor, /class SyftCycloneDxInventoryIngestor/);
  assert.match(ingestor, /SastNormalizationJsonStreamSession/);
  assert.match(
    spdxLicenseList,
    /SPDX_LICENSE_LIST_VERSION = '3\.28\.0'/
  );
  assert.match(
    spdxLicenseList,
    /SPDX_LICENSE_IDENTIFIER_COUNT = 727/
  );
  assert.match(
    spdxLicenseList,
    /SPDX_LICENSE_EXCEPTION_IDENTIFIER_COUNT = 84/
  );
  assert.match(
    ingestorTest,
    /inventory byte-exactly across chunking/
  );
  assert.match(
    ingestorTest,
    /rejects an unreviewed Syft producer upgrade before reading artifact bytes/
  );
  assert.match(
    ingestorTest,
    /component and scoped PURL name mismatch/
  );
  assert.match(
    ingestorTest,
    /validates and canonicalizes SPDX 3\.28\.0 expression/
  );
  assert.match(
    ingestorTest,
    /NIST CPE 2\.3 quoted punctuation and language tags/
  );
  assert.match(ingestorTest, /expect\(serialized\)\.not\.toContain\(forbidden\)/);
  assert.match(fixture, /"version": "1\.44\.0"/);
  assert.match(fixture, /"type": "build-meta"/);
  assert.match(fixture, /"type": "vcs"/);
  assert.match(expected, /"rawPropertiesStored": false/);
  assert.match(expected, /"sourceLocationsStored": false/);
  assert.match(tasks, /- \[x\] T034\b/);
  assert.match(
    quickstart,
    /T035 secret redaction is complete/
  );
  assert.match(contract, /Syft CycloneDX inventory adapter v1/);
  assert.match(spec, /FR-031b/);
  assert.match(plan, /T034's Syft adapter pins the v1\.44\.0/);
  assert.match(
    research,
    /Ingest the Pinned Syft Directory Producer, Not Generic CycloneDX/
  );
  assert.match(dataModel, /SyftCycloneDxInventoryBatch/);
  assert.match(threatModel, /CycloneDX inventory cannot smuggle finding/);
  assert.match(qualityGates, /Syft v1\.44\.0 CycloneDX JSON 1\.6/);
});

test('SAST T035 secret redaction is deterministic, fail-closed, and still non-durable', () => {
  const sharedRedaction = readNormalizedText(
    files.sharedSastSecretRedaction
  );
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const sharedRedactionTest = readNormalizedText(
    files.sharedSastSecretRedactionTest
  );
  const service = readNormalizedText(files.apiSastSecretRedaction);
  const serviceTest = readNormalizedText(
    files.apiSastSecretRedactionTest
  );
  const scanPlaneModule = readNormalizedText(files.apiScanPlaneModule);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const contract = readNormalizedText(files.contract);
  const spec = readNormalizedText(files.spec);
  const plan = readNormalizedText(files.plan);
  const research = readNormalizedText(files.research);
  const dataModel = readNormalizedText(files.dataModel);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(
    sharedRedaction,
    /SAST_SECRET_REDACTION_VERSION\s*=[\s\S]*'sast-secret-redaction-v1'/
  );
  assert.match(
    sharedIndex,
    /export \* from '.\/types\/sast-secret-redaction';/
  );
  assert.match(
    sharedRedaction,
    /SAST_SECRET_REDACTION_TOKEN\s*=\s*'\[REDACTED\]'/
  );
  assert.match(sharedRedaction, /matchedValueDigestStored:\s*false/);
  assert.match(sharedRedaction, /sourceCandidateDigestStored:\s*false/);
  assert.match(sharedRedaction, /durablePersistenceAllowed:\s*false/);
  assert.match(
    sharedRedactionTest,
    /canonical transient redacted-candidate batch/
  );
  assert.match(service, /class SastSecretRedactionService/);
  assert.match(service, /SECRET_REDACTION_IDENTITY_FIELD_BLOCKED/);
  assert.match(service, /mergeSpans/);
  assert.match(service, /shannonEntropy/);
  assert.match(service, /async redact\(/);
  assert.match(service, /protected async yieldEventLoop/);
  assert.match(service, /await this\.yieldEventLoop\(\)/);
  assert.match(service, /await yieldToEventLoop\(\)/);
  assert.match(service, /hasInspectionWorkWithinLimit/);
  assert.match(
    sharedRedaction,
    /maximumInspectedCodeUnits:\s*8_000_000/
  );
  assert.match(sharedRedaction, /canonicalDigestMatches/);
  assert.doesNotMatch(service, /\bLogger\b|\bconsole\./u);
  assert.match(
    serviceTest,
    /known-format, entropy, and registered-value corpus/
  );
  assert.match(
    serviceTest,
    /rejects secret-bearing batch bindings even when there are no findings/
  );
  assert.match(
    serviceTest,
    /expect\(serialized\)\.not\.toContain\(secret\)/
  );

  const exportsBlock = scanPlaneModule.match(
    /exports:\s*\[([\s\S]*?)\]\s*\}\)\s*export class/
  )?.[1];
  assert.ok(
    exportsBlock,
    'Expected to locate the ScanPlaneModule exports array'
  );
  assert.match(exportsBlock, /SastSecretRedactionService/);
  assert.doesNotMatch(exportsBlock, /OpenGrepSarifNormalizer/);
  assert.doesNotMatch(exportsBlock, /TrivyJsonNormalizer/);

  assert.match(tasks, /- \[x\] T035\b/);
  assert.match(quickstart, /T036 `sast-fingerprint-v1` identity construction/);
  assert.match(contract, /Secret redaction gate v1/);
  assert.match(spec, /FR-031c/);
  assert.match(plan, /`sast-secret-redaction-v1` gate/);
  assert.match(
    research,
    /Redact Display Text and Reject Secret-Bearing Identity/
  );
  assert.match(dataModel, /SastSecretRedactionBatch/);
  assert.match(threatModel, /Identity redaction collision/);
  assert.match(
    qualityGates,
    /Exactly zero matched values, matched-value digests/
  );
  const canonicalIdentityRejection =
    /scanner\s+version\/match\s+identity,[\s\S]{0,200}rule\s+provenance\s+identifier\/revision,[\s\S]{0,250}secret\s+category,[\s\S]{0,120}IaC\s+check\s+type\/AVD\s+identity/;
  for (const document of [
    contract,
    spec,
    plan,
    research,
    dataModel,
    threatModel,
    qualityGates,
    quickstart
  ]) {
    assert.match(document, canonicalIdentityRejection);
  }
  assert.doesNotMatch(dataModel, /\bdurable handoff\b/);
});

test('SAST design completion gate stays synchronized between quickstart and CI', () => {
  const readme = readNormalizedText(files.readme);
  const ci = readNormalizedText(files.ci);
  const quickstart = readNormalizedText(files.quickstart);
  const tasks = readNormalizedText(files.tasks);
  const checklist = readNormalizedText(files.checklist);

  const requiredCommands = [
    'corepack pnpm lint',
    'corepack pnpm test',
    'corepack pnpm typecheck',
    'corepack pnpm build',
    'corepack pnpm --filter @aegisai/api prisma:validate',
    'node --test test/runtime/*.test.mjs',
    'git diff --check'
  ];

  for (const command of requiredCommands) {
    const escaped = command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    assert.match(quickstart, new RegExp(escaped));
    assert.match(ci, new RegExp(escaped));
  }

  assert.match(readme, /specs\/006-production-sast-runtime-design\/quickstart\.md/);
  assert.match(readme, /Before claiming the 006 milestone complete/);
  assert.match(readme, /\.github\/workflows\/ci\.yml/);
  assert.match(tasks, /Point AGENTS, README, and GitHub conventions at the 006 quickstart/);
  assert.match(ci, /DATABASE_URL:\s*postgresql:\/\/postgres:postgres@localhost:5432\/aegisai_ci/);

  const completedDesignScope = tasks.split('\n## Phase 4:')[0];
  const openDesignTasks = completedDesignScope
    .split('\n')
    .filter((line) => /^- \[ \]/.test(line));
  const openChecklistItems = checklist
    .split('\n')
    .filter((line) => /^- \[ \]/.test(line));
  assert.deepEqual(openDesignTasks, []);
  assert.deepEqual(openChecklistItems, []);
});

test('completed deployment operations baseline hands SAST detail to 006', () => {
  const tasks = readNormalizedText(files.completedDeploymentTasks);
  const checklist = readNormalizedText(files.completedDeploymentChecklist);
  const quickstart = readNormalizedText(files.completedDeploymentQuickstart);

  assertNoOpenItemsBeforeDeferred(tasks);
  assertChecklistComplete(checklist);
  assert.match(quickstart, /completed provider-neutral contract baseline/);
  assert.match(quickstart, /006-production-sast-runtime-design/);
  assert.match(tasks, /Hand the SAST runtime and rule-governance follow-up to `006-production-sast-runtime-design`/);
  assert.match(tasks, /Execute live production Kubernetes cluster provisioning/);
  assert.match(tasks, /Execute provider-specific microVM platform rollout/);
});

test('completed production runtime infrastructure baseline hands live rollout follow-up to 005', () => {
  const tasks = readNormalizedText(files.completedRuntimeTasks);
  const checklist = readNormalizedText(files.completedRuntimeChecklist);
  const quickstart = readNormalizedText(files.completedRuntimeQuickstart);

  assertNoOpenItemsBeforeDeferred(tasks);
  assertChecklistComplete(checklist);
  assert.match(quickstart, /005-production-deployment-operations/);
  assert.match(tasks, /Live production Kubernetes cluster provisioning moved to `005-production-deployment-operations`/);
  assert.match(tasks, /Provider-specific microVM platform rollout moved to `005-production-deployment-operations`/);
});

test('completed production AI inference baseline hands infrastructure follow-up to 004', () => {
  const tasks = readNormalizedText(files.completedAiTasks);
  const checklist = readNormalizedText(files.completedAiChecklist);
  const quickstart = readNormalizedText(files.completedAiQuickstart);

  assertNoOpenItemsBeforeDeferred(tasks);
  assertChecklistComplete(checklist);
  assert.match(quickstart, /004-production-runtime-infrastructure/);
  assert.match(tasks, /Kubernetes production AI Plane deployment manifests and runtime autoscaling moved to `004-production-runtime-infrastructure`/);
  assert.match(tasks, /microVM-backed scanner provisioning moved to `004-production-runtime-infrastructure`/);
});

test('completed production scan architecture baseline keeps only the AI inference follow-up deferred', () => {
  const tasks = readNormalizedText(files.completedArchitectureTasks);
  const checklist = readNormalizedText(files.completedArchitectureChecklist);
  const quickstart = readNormalizedText(files.completedArchitectureQuickstart);
  const deferredSection = tasks.split('\n## Deferred\n')[1] ?? '';

  assertNoOpenItemsBeforeDeferred(tasks);
  assertChecklistComplete(checklist);
  assert.match(quickstart, /supersedes `001-aegisai-mvp-foundation`/);
  assert.match(tasks, /## Phase 46: Production Architecture First Milestone Completion Guardrail Slice/);
  assert.match(deferredSection, /- \[ \] Implement trained production AI detector\/planner model inference/);
  assert.equal(deferredSection.split('\n').filter((line) => /^- \[ \]/.test(line)).length, 1);
});
