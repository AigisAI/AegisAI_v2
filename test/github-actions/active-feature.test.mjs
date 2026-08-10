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
  sharedSastFindingIdentity: new URL('../../packages/shared/src/types/sast-finding-identity.ts', import.meta.url),
  sharedSastFindingIdentityTest: new URL('../../packages/shared/test/sast-finding-identity.test.mjs', import.meta.url),
  sharedSastFindingLineage: new URL('../../packages/shared/src/types/sast-finding-lineage.ts', import.meta.url),
  sharedSastFindingLineageTest: new URL('../../packages/shared/test/sast-finding-lineage.test.mjs', import.meta.url),
  sharedSastFindingCorrelation: new URL('../../packages/shared/src/types/sast-finding-correlation.ts', import.meta.url),
  sharedSastFindingCorrelationTest: new URL('../../packages/shared/test/sast-finding-correlation.test.mjs', import.meta.url),
  sharedSastScanCoverage: new URL('../../packages/shared/src/types/sast-scan-coverage.ts', import.meta.url),
  sharedSastScanCoverageTest: new URL('../../packages/shared/test/sast-scan-coverage.test.mjs', import.meta.url),
  sharedSastScanFreshness: new URL('../../packages/shared/src/types/sast-scan-freshness.ts', import.meta.url),
  sharedSastScanFreshnessTest: new URL('../../packages/shared/test/sast-scan-freshness.test.mjs', import.meta.url),
  sharedSastAcceptedEvidence: new URL('../../packages/shared/src/types/sast-accepted-evidence.ts', import.meta.url),
  sharedSastAcceptedEvidenceTest: new URL('../../packages/shared/test/sast-accepted-evidence.test.mjs', import.meta.url),
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
  apiSastFindingIdentity: new URL('../../apps/api/src/scan-plane/sast-finding-identity.service.ts', import.meta.url),
  apiSastFindingIdentityTest: new URL('../../apps/api/test/scan-plane/sast-finding-identity.e2e-spec.ts', import.meta.url),
  apiSastFindingLineage: new URL('../../apps/api/src/scan-plane/sast-finding-lineage.service.ts', import.meta.url),
  apiSastFindingLineageStore: new URL('../../apps/api/src/scan-plane/prisma-sast-finding-lineage.store.ts', import.meta.url),
  apiSastFindingRenameVerifier: new URL('../../apps/api/src/scan-plane/sast-finding-rename-attestation.verifier.ts', import.meta.url),
  apiSastFindingCoverageGate: new URL('../../apps/api/src/scan-plane/sast-finding-lifecycle-coverage.gate.ts', import.meta.url),
  apiSastFindingLineageTest: new URL('../../apps/api/test/scan-plane/sast-finding-lineage.e2e-spec.ts', import.meta.url),
  apiSastFindingLineagePersistenceTest: new URL('../../apps/api/test/scan-plane/sast-finding-lineage-persistence.e2e-spec.ts', import.meta.url),
  apiSastFindingCorrelation: new URL('../../apps/api/src/scan-plane/sast-finding-correlation.service.ts', import.meta.url),
  apiSastFindingCorrelationStore: new URL('../../apps/api/src/scan-plane/prisma-sast-finding-correlation.store.ts', import.meta.url),
  apiSastFindingCorrelationTest: new URL('../../apps/api/test/scan-plane/sast-finding-correlation.e2e-spec.ts', import.meta.url),
  apiSastFindingCorrelationPersistenceTest: new URL('../../apps/api/test/scan-plane/sast-finding-correlation-persistence.e2e-spec.ts', import.meta.url),
  apiSastScanCoverage: new URL('../../apps/api/src/scan-plane/sast-scan-coverage.service.ts', import.meta.url),
  apiSastScanCoverageStore: new URL('../../apps/api/src/scan-plane/prisma-sast-scan-coverage.store.ts', import.meta.url),
  apiSastScanCoverageTest: new URL('../../apps/api/test/scan-plane/sast-scan-coverage.e2e-spec.ts', import.meta.url),
  apiSastScanCoveragePrismaTest: new URL('../../apps/api/test/scan-plane/prisma-sast-scan-coverage.store.e2e-spec.ts', import.meta.url),
  apiSastScanCoveragePersistenceTest: new URL('../../apps/api/test/scan-plane/sast-scan-coverage-persistence.e2e-spec.ts', import.meta.url),
  apiSastScanFreshness: new URL('../../apps/api/src/scan-plane/sast-scan-freshness.service.ts', import.meta.url),
  apiSastScanFreshnessStore: new URL('../../apps/api/src/scan-plane/prisma-sast-scan-freshness.store.ts', import.meta.url),
  apiSastScanFreshnessTest: new URL('../../apps/api/test/scan-plane/sast-scan-freshness.e2e-spec.ts', import.meta.url),
  apiSastScanFreshnessPersistenceTest: new URL('../../apps/api/test/scan-plane/sast-scan-freshness-persistence.e2e-spec.ts', import.meta.url),
  apiSastAcceptedEvidence: new URL('../../apps/api/src/scan-plane/sast-accepted-evidence.service.ts', import.meta.url),
  apiSastAcceptedEvidenceStore: new URL('../../apps/api/src/scan-plane/prisma-sast-accepted-evidence.store.ts', import.meta.url),
  apiSastAcceptedEvidenceTest: new URL('../../apps/api/test/scan-plane/sast-accepted-evidence.e2e-spec.ts', import.meta.url),
  apiSastAcceptedEvidencePersistenceTest: new URL('../../apps/api/test/scan-plane/sast-accepted-evidence-persistence.e2e-spec.ts', import.meta.url),
  apiPrismaSchema: new URL('../../apps/api/prisma/schema.prisma', import.meta.url),
  apiOnlineSastRuntimeSchema: new URL('../../apps/api/scripts/apply-online-sast-runtime-schema.mjs', import.meta.url),
  apiSastFindingLineageMigration: new URL('../../apps/api/prisma/migrations/20260730160000_sast_finding_lineage_lifecycle/migration.sql', import.meta.url),
  apiSastFindingCorrelationMigration: new URL('../../apps/api/prisma/migrations/20260802120000_sast_finding_correlation/migration.sql', import.meta.url),
  apiSastScanCoverageMigration: new URL('../../apps/api/prisma/migrations/20260802150000_sast_scan_coverage/migration.sql', import.meta.url),
  apiSastScanFreshnessMigration: new URL('../../apps/api/prisma/migrations/20260810030000_sast_scan_freshness_retry/migration.sql', import.meta.url),
  apiSastAcceptedEvidenceMigration: new URL('../../apps/api/prisma/migrations/20260810043000_sast_accepted_evidence/migration.sql', import.meta.url),
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

const assertScanPlaneExports = (scanPlaneModule) => {
  const exportsBlock = scanPlaneModule.match(
    /exports:\s*\[([\s\S]*?)\]\s*\}\)\s*export class/
  )?.[1];
  assert.ok(
    exportsBlock,
    'Expected to locate the ScanPlaneModule exports array'
  );
  assert.match(exportsBlock, /SastAcceptedEvidenceService/);
  assert.doesNotMatch(exportsBlock, /SastScanFreshnessService/);
  assert.doesNotMatch(exportsBlock, /SastScanCoverageService/);
  assert.doesNotMatch(exportsBlock, /SastFindingCorrelationService/);
  assert.doesNotMatch(exportsBlock, /SastFindingLineageService/);
  assert.doesNotMatch(exportsBlock, /SastFindingIdentityService/);
  assert.doesNotMatch(exportsBlock, /SastSecretRedactionService/);
  assert.doesNotMatch(exportsBlock, /OpenGrepSarifNormalizer/);
  assert.doesNotMatch(exportsBlock, /TrivyJsonNormalizer/);
  assert.doesNotMatch(exportsBlock, /SyftCycloneDxInventoryIngestor/);
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
    /T035 secret redaction,[\s\S]{0,720}T041 bounded[\s\S]{0,180}are complete/
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

  assertScanPlaneExports(scanPlaneModule);

  assert.match(tasks, /- \[x\] T035\b/);
  assert.match(
    quickstart,
    /T035 secret redaction,[\s\S]{0,720}T041 bounded[\s\S]{0,180}are complete/
  );
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
  assert.match(dataModel, /SastSecretRedactionBatch/);
});

test('SAST T036 constructs byte-exact stable identity and no downstream authority', () => {
  const sharedIdentity = readNormalizedText(
    files.sharedSastFindingIdentity
  );
  const sharedIdentityTest = readNormalizedText(
    files.sharedSastFindingIdentityTest
  );
  const sharedRuntime = readNormalizedText(files.sharedSastRuntime);
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiSastFindingIdentity);
  const serviceTest = readNormalizedText(
    files.apiSastFindingIdentityTest
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
    sharedIdentity,
    /SAST_FINDING_IDENTITY_VERSION\s*=[^;]*'sast-finding-identity-v1'/
  );
  assert.match(
    sharedRuntime,
    /SAST_FINDING_FINGERPRINT_VERSION\s*=[^;]*'sast-fingerprint-v1'/
  );
  assert.match(
    sharedRuntime,
    /SAST_FINDING_FINGERPRINT_FIELDS\s*=[^;]*repositoryBindingId[^;]*capability[^;]*ruleSemanticId[^;]*normalizedPath[^;]*symbolAnchor[^;]*sinkKind[^;]*structuralHash[^;]*;/
  );
  assert.match(
    sharedIndex,
    /export \* from '.\/types\/sast-finding-identity';/
  );
  assert.match(
    sharedIdentity,
    /SAST_FINDING_UNKNOWN_NORMALIZED_PATH\s*=\s*''/
  );
  assert.match(sharedIdentity, /maximumFindings:\s*25_000/);
  assert.match(sharedIdentity, /yieldFindingInterval:\s*64/);
  assert.match(sharedIdentity, /normalizedFindingPersistenceEligible:\s*true/);
  assert.match(sharedIdentity, /occurrenceAuthority:\s*false/);
  assert.match(sharedIdentity, /publicationAuthority:\s*false/);
  assert.match(sharedIdentity, /aiPayloadEligible:\s*false/);
  assert.match(sharedIdentity, /fingerprintPreimageStored:\s*false/);
  assert.match(sharedIdentity, /durablePersistenceAllowed:\s*true/);
  assert.match(sharedIdentityTest, /byte-exact sast-fingerprint-v1 field contract/);
  assert.match(
    sharedIdentityTest,
    /projects UNKNOWN location to an explicit empty path/
  );

  assert.match(service, /class SastFindingIdentityService/);
  assert.match(service, /async construct\(/);
  assert.match(
    service,
    /isSastSecretRedactionBatchShapeValid\(input\?\.batch,\s*digest\)/
  );
  assert.match(service, /FINDING_IDENTITY_FINGERPRINT_COLLISION/);
  assert.match(service, /secondReferenceTime < firstReferenceTime/);
  assert.match(service, /await this\.yieldEventLoop\(\)/);
  assert.match(service, /await yieldToEventLoop\(\)/);
  assert.doesNotMatch(service, /\bLogger\b|\bconsole\./u);
  assert.match(
    serviceTest,
    /excludes unstable observation and display fields from stable identity/
  );
  assert.match(
    serviceTest,
    /preserves Trivy capability and database provenance/
  );
  assert.match(
    serviceTest,
    /rejects a digest collision across different preimages/
  );
  assert.match(
    serviceTest,
    /handles an empty batch deterministically and yields during bounded large batches/
  );

  assertScanPlaneExports(scanPlaneModule);

  assert.match(tasks, /- \[x\] T036\b/);
  assert.match(
    quickstart,
    /T038 authority-aware cross-tool correlation[\s\S]{0,320}T041 bounded[\s\S]{0,180}are complete; T042/
  );
  assert.match(contract, /Finding identity construction gate v1/);
  assert.match(spec, /FR-034a/);
  assert.match(plan, /T036 now recomputes the exact T035 handoff/);
  assert.match(
    research,
    /Decision 18: Construct Stable Identity Only from the Verified Sanitized Handoff/
  );
  assert.match(dataModel, /SastFingerprintedFindingBatch/);
  assert.match(threatModel, /Stable fingerprint collision/);
  assert.match(
    qualityGates,
    /100% `sast-finding-identity-v1` source-batch/
  );
});

test('SAST T037 persists complete occurrence lineage and fail-closed lifecycle transitions', () => {
  const sharedLineage = readNormalizedText(
    files.sharedSastFindingLineage
  );
  const sharedLineageTest = readNormalizedText(
    files.sharedSastFindingLineageTest
  );
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiSastFindingLineage);
  const store = readNormalizedText(
    files.apiSastFindingLineageStore
  );
  const verifier = readNormalizedText(
    files.apiSastFindingRenameVerifier
  );
  const coverageGate = readNormalizedText(
    files.apiSastFindingCoverageGate
  );
  const serviceTest = readNormalizedText(
    files.apiSastFindingLineageTest
  );
  const persistenceTest = readNormalizedText(
    files.apiSastFindingLineagePersistenceTest
  );
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(
    files.apiSastFindingLineageMigration
  );
  const scanPlaneModule = readNormalizedText(
    files.apiScanPlaneModule
  );
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const plan = readNormalizedText(files.plan);
  const spec = readNormalizedText(files.spec);
  const research = readNormalizedText(files.research);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(
    sharedLineage,
    /SAST_FINDING_LINEAGE_VERSION\s*=[^;]*'sast-finding-lineage-v1'/
  );
  assert.match(
    sharedLineage,
    /SAST_FINDING_RENAME_ATTESTATION_VERSION\s*=[^;]*'sast-finding-rename-attestation-v1'/
  );
  assert.match(
    sharedLineage,
    /SAST_FINDING_LIFECYCLE_COVERAGE_VERSION\s*=[^;]*'sast-finding-lifecycle-coverage-v1'/
  );
  assert.match(sharedLineage, /maximumFindings:\s*25_000/);
  assert.match(
    sharedLineage,
    /coverageCalculationAuthority:\s*false/
  );
  assert.match(sharedLineage, /policyAuthority:\s*false/);
  assert.match(sharedLineage, /publicationAuthority:\s*false/);
  assert.match(sharedLineage, /aiPayloadEligible:\s*false/);
  assert.match(
    sharedIndex,
    /export \* from '.\/types\/sast-finding-lineage';/
  );
  assert.match(
    sharedLineageTest,
    /one-to-one, sorted, fixed-commit rename attestation/
  );
  assert.match(
    sharedLineageTest,
    /binds reconciliation transition counts/
  );

  assert.match(service, /class SastFindingLineageService/);
  assert.match(
    service,
    /isSastFingerprintedFindingBatchShapeValid/
  );
  assert.match(
    service,
    /isSastFindingLifecycleContextInputValid/
  );
  assert.doesNotMatch(service, /\bLogger\b|\bconsole\./u);
  assert.doesNotMatch(service, /@Controller|@(Get|Post|Put|Patch|Delete)\(/u);
  assert.match(
    verifier,
    /UnavailableSastFindingRenameAttestationVerifier/
  );
  assert.match(verifier, /return 'UNAVAILABLE'/);
  assert.match(
    coverageGate,
    /UnavailableSastFindingLifecycleCoverageGate/
  );
  assert.match(coverageGate, /return 'UNAVAILABLE'/);

  assert.match(
    store,
    /Prisma\.TransactionIsolationLevel\.Serializable/
  );
  assert.match(store, /SERIALIZABLE_ATTEMPTS = 3/);
  assert.match(
    store,
    /SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000/
  );
  assert.match(store, /canonicalizeSastFingerprintedFinding/);
  assert.match(store, /SAST_SCANNER_RESPONSIBILITIES/);
  assert.match(
    serviceTest,
    /rejects a non-canonical durable target context/
  );
  assert.match(
    persistenceTest,
    /separates global identity, ordered occurrences, target lifecycle, and append-only events/
  );

  for (const model of [
    'SastFindingLineage',
    'SastFindingIdentityAlias',
    'SastFindingObservationBatch',
    'SastFindingOccurrence',
    'SastFindingLifecycleState',
    'SastFindingLifecycleReconciliation',
    'SastFindingLifecycleEvent'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(
      migration,
      new RegExp(`CREATE TABLE "${model}"`)
    );
  }
  assert.match(
    migration,
    /SastFindingLifecycleEvent_observation_scope_fkey/
  );
  assert.match(
    migration,
    /SastFindingLifecycleEvent_reconciliation_scope_fkey/
  );
  assertScanPlaneExports(scanPlaneModule);

  assert.match(tasks, /- \[x\] T037\b/);
  assert.match(
    quickstart,
    /T038 authority-aware cross-tool correlation[\s\S]{0,320}T041 bounded[\s\S]{0,180}are complete; T042/
  );
  assert.match(contract, /Finding lineage and lifecycle gate v1/);
  assert.match(dataModel, /SastFindingLifecycleReconciliation/);
  assert.match(
    plan,
    /T037 now revalidates that complete handoff/
  );
  assert.match(spec, /FR-035a/);
  assert.match(spec, /FR-037a/);
  assert.match(
    research,
    /Decision 19: Separate Exact Lineage, Ordered Occurrences, and Target Lifecycle/
  );
  assert.match(threatModel, /Finding-ledger replay forgery/);
  assert.match(threatModel, /Incomplete-batch false fix/);
  assert.match(
    qualityGates,
    /100% `sast-finding-lineage-v1` revalidation/
  );
  assert.match(
    qualityGates,
    /including\s+zero-finding batches/
  );
});

test('SAST T038 correlates by scanner authority while preserving every provenance record', () => {
  const sharedCorrelation = readNormalizedText(
    files.sharedSastFindingCorrelation
  );
  const sharedCorrelationTest = readNormalizedText(
    files.sharedSastFindingCorrelationTest
  );
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiSastFindingCorrelation);
  const store = readNormalizedText(
    files.apiSastFindingCorrelationStore
  );
  const serviceTest = readNormalizedText(
    files.apiSastFindingCorrelationTest
  );
  const persistenceTest = readNormalizedText(
    files.apiSastFindingCorrelationPersistenceTest
  );
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(
    files.apiSastFindingCorrelationMigration
  );
  const scanPlaneModule = readNormalizedText(
    files.apiScanPlaneModule
  );
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const plan = readNormalizedText(files.plan);
  const spec = readNormalizedText(files.spec);
  const research = readNormalizedText(files.research);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(
    sharedCorrelation,
    /SAST_FINDING_CORRELATION_VERSION\s*=[^;]*'sast-finding-correlation-v1'/
  );
  assert.match(sharedCorrelation, /maximumOccurrences:\s*25_000/);
  assert.match(sharedCorrelation, /maximumEdges:\s*100_000/);
  assert.match(sharedCorrelation, /EXACT_FINGERPRINT/);
  assert.match(sharedCorrelation, /SAME_DEPENDENCY_CVE/);
  assert.match(sharedCorrelation, /SUPPORTING_EVIDENCE/);
  assert.match(sharedCorrelation, /POSSIBLE_OVERLAP/);
  assert.match(sharedCorrelation, /findingMergeAllowed:\s*false/);
  assert.match(sharedCorrelation, /severityAuthority:\s*false/);
  assert.match(sharedCorrelation, /publicationAuthority:\s*false/);
  assert.match(sharedCorrelation, /aiPayloadEligible:\s*false/);
  assert.match(
    sharedIndex,
    /export \* from '.\/types\/sast-finding-correlation';/
  );
  assert.match(
    sharedCorrelationTest,
    /complete durable T037 source set independently from replay result digests/
  );
  assert.match(
    sharedCorrelationTest,
    /cannot merge or inherit severity/
  );

  assert.match(service, /class SastFindingCorrelationService/);
  assert.match(service, /SAST_SCANNER_RESPONSIBILITIES/);
  assert.match(service, /yieldOccurrenceInterval/);
  assert.match(service, /connectStar/);
  assert.match(service, /connectAcrossCapabilities/);
  assert.doesNotMatch(service, /\bLogger\b|\bconsole\./u);
  assert.doesNotMatch(
    service,
    /@Controller|@(Get|Post|Put|Patch|Delete)\(/u
  );
  assert.match(
    serviceTest,
    /keeps two authoritative capability families as display-only possible overlap/
  );
  assert.match(
    serviceTest,
    /optional-profile scanner output only as supporting evidence/
  );
  assert.match(
    serviceTest,
    /replay identity independent from the T037 replay flag/
  );

  assert.match(
    store,
    /Prisma\.TransactionIsolationLevel\.Serializable/
  );
  assert.match(store, /allBatches\.length !== orderedIds\.length/);
  assert.match(store, /replayCorrelation/);
  assert.match(
    persistenceTest,
    /closed source set, non-collapsing edges, and two-sided provenance/
  );
  for (const model of [
    'SastFindingCorrelationBatch',
    'SastFindingCorrelationSource',
    'SastFindingCorrelationEdge',
    'SastFindingCorrelationProvenance'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(
      migration,
      new RegExp(`CREATE TABLE "${model}"`)
    );
  }
  assertScanPlaneExports(scanPlaneModule);

  assert.match(tasks, /- \[x\] T038\b/);
  assert.match(
    quickstart,
    /T039 fail-closed scanner\/capability coverage[\s\S]{0,220}T041 bounded[\s\S]{0,180}are complete; T042/
  );
  assert.match(contract, /Finding correlation gate v1/);
  assert.match(dataModel, /SastFindingCorrelationProvenance/);
  assert.match(plan, /T038 now closes that complete durable source set/);
  assert.match(spec, /FR-036a/);
  assert.match(
    research,
    /Decision 20: Correlate by Authority Without Collapsing Capability Families/
  );
  assert.match(threatModel, /Correlation source-set truncation/);
  assert.match(
    qualityGates,
    /100% exact equality between supplied canonical T037 results/
  );
});

test('SAST T039 coverage feeds T040 freshness and bounded retry authority', () => {
  const sharedCoverage = readNormalizedText(
    files.sharedSastScanCoverage
  );
  const sharedCoverageTest = readNormalizedText(
    files.sharedSastScanCoverageTest
  );
  const sharedFreshness = readNormalizedText(
    files.sharedSastScanFreshness
  );
  const sharedFreshnessTest = readNormalizedText(
    files.sharedSastScanFreshnessTest
  );
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiSastScanCoverage);
  const store = readNormalizedText(files.apiSastScanCoverageStore);
  const serviceTest = readNormalizedText(
    files.apiSastScanCoverageTest
  );
  const prismaTest = readNormalizedText(
    files.apiSastScanCoveragePrismaTest
  );
  const persistenceTest = readNormalizedText(
    files.apiSastScanCoveragePersistenceTest
  );
  const freshnessService = readNormalizedText(
    files.apiSastScanFreshness
  );
  const freshnessStore = readNormalizedText(
    files.apiSastScanFreshnessStore
  );
  const freshnessTest = readNormalizedText(
    files.apiSastScanFreshnessTest
  );
  const freshnessPersistenceTest = readNormalizedText(
    files.apiSastScanFreshnessPersistenceTest
  );
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(
    files.apiSastScanCoverageMigration
  );
  const freshnessMigration = readNormalizedText(
    files.apiSastScanFreshnessMigration
  );
  const onlineSchema = readNormalizedText(
    files.apiOnlineSastRuntimeSchema
  );
  const scanPlaneModule = readNormalizedText(
    files.apiScanPlaneModule
  );
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const plan = readNormalizedText(files.plan);
  const spec = readNormalizedText(files.spec);
  const research = readNormalizedText(files.research);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(
    sharedCoverage,
    /SAST_SCAN_COVERAGE_VERSION\s*=[^;]*'sast-scan-coverage-v1'/
  );
  assert.match(
    sharedCoverage,
    /SAST_SCANNER_COVERAGE_VERSION\s*=[^;]*'sast-scanner-coverage-v1'/
  );
  assert.match(
    sharedCoverage,
    /SAST_EXTERNAL_PUBLICATION_DECISION_VERSION\s*=[^;]*'sast-external-publication-v1'/
  );
  assert.match(
    sharedCoverage,
    /coverageCalculationAuthority:\s*true/
  );
  assert.match(sharedCoverage, /publicationAuthority:\s*false/);
  assert.match(sharedCoverage, /aiPayloadEligible:\s*false/);
  assert.match(sharedCoverage, /externalCommentAllowed:\s*false/);
  assert.match(sharedCoverage, /blockingStatusAllowed:\s*false/);
  assert.match(sharedCoverage, /lifecycleMutationAllowed:\s*false/);
  assert.match(
    sharedIndex,
    /export \* from '.\/types\/sast-scan-coverage';/
  );
  assert.match(
    sharedCoverageTest,
    /absent optional scanner visible without lowering required coverage/
  );
  assert.match(
    sharedCoverageTest,
    /fail-closing every external publication authority/
  );
  assert.match(
    sharedFreshness,
    /SAST_SCAN_FRESHNESS_VERSION\s*=[^;]*'sast-scan-freshness-v1'/
  );
  assert.match(
    sharedFreshness,
    /SAST_SCAN_RETRY_DECISION_VERSION\s*=[^;]*'sast-scan-retry-decision-v1'/
  );
  assert.match(sharedFreshness, /evaluateSastScanFreshness/);
  assert.match(sharedFreshness, /evaluateSastScanRetry/);
  assert.match(
    sharedIndex,
    /export \* from '.\/types\/sast-scan-freshness';/
  );
  assert.match(
    sharedFreshnessTest,
    /independently verified fresh comparable coverage/
  );
  assert.match(
    sharedFreshnessTest,
    /exactly one infrastructure-only retry with a fresh sandbox/
  );

  assert.match(service, /class SastScanCoverageService/);
  assert.match(service, /isSastFindingCorrelationResultShapeValid/);
  assert.match(service, /evaluateSastScanCoverageRecords/);
  assert.match(
    service,
    /buildFailClosedSastExternalPublicationDecision/
  );
  assert.doesNotMatch(service, /\bLogger\b|\bconsole\./u);
  assert.doesNotMatch(
    service,
    /@Controller|@(Get|Post|Put|Patch|Delete)\(/u
  );
  assert.match(
    serviceTest,
    /complete Java Deep coverage while denying every publication authority/
  );
  assert.match(serviceTest, /running required scanner pending without publishing/);
  assert.match(serviceTest, /expect\(result\.persisted\)\.toBe\(false\)/);
  assert.match(
    serviceTest,
    /lifecycle authority denied even when the canonical T039 source matches/
  );
  assert.match(serviceTest, /timed-out required scanner as terminal partial coverage/);
  assert.match(serviceTest, /rejects duplicate or foreign durable scanner rows/);
  assert.match(serviceTest, /rejects individually invalid durable correlation counters/);

  assert.match(
    store,
    /Prisma\.TransactionIsolationLevel\.Serializable/
  );
  assert.match(store, /SERIALIZABLE_ATTEMPTS = 3/);
  assert.match(store, /buildSastScanPlanDigestPreimage/);
  assert.match(store, /isScannerArtifactEnvelopeBoundToPlan/);
  assert.match(
    store,
    /canonicalizeSastArtifactDispositionDecision/
  );
  assert.match(store, /replayCoverage/);
  assert.match(
    prismaTest,
    /zero-publication authority atomically/
  );
  assert.match(prismaTest, /rejects late durable-state drift/);
  assert.match(
    persistenceTest,
    /zero external publication a database invariant/
  );
  assert.match(freshnessService, /class SastScanFreshnessService/);
  assert.match(freshnessService, /SastLatestTargetAuthority/);
  assert.match(freshnessService, /SastRetryRuntimeAuthority/);
  assert.match(freshnessStore, /SERIALIZABLE_ATTEMPTS = 3/);
  assert.match(freshnessStore, /verifyLifecycleSource/);
  assert.match(freshnessTest, /denies a stale target head/);
  assert.match(
    freshnessPersistenceTest,
    /durable allowed retry row before attempt two starts/
  );

  for (const model of [
    'SastScanCoverageDecision',
    'SastScannerCoverageRecord',
    'SastExternalPublicationDecision'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(migration, new RegExp(`CREATE TABLE "${model}"`));
  }
  for (const model of [
    'SastLatestTargetObservation',
    'SastScanFreshnessDecision',
    'SastScanRetryDecision'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(
      freshnessMigration,
      new RegExp(`CREATE TABLE "${model}"`)
    );
  }
  assert.match(
    onlineSchema,
    /SastExternalPublicationDecision_contract_check[\s\S]{0,160}SastExternalPublicationDecision_t039_source_check/
  );
  assert.match(
    onlineSchema,
    /CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "SastScanCoverageDecision_comparison_scope_key"/
  );
  assert.match(
    onlineSchema,
    /CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "SastScanAttempt_retryDecisionId_key"/
  );
  for (const constraint of [
    'scanner_scope_fkey',
    'ingestion_scope_fkey',
    'disposition_scope_fkey',
    'source_scope_fkey'
  ]) {
    assert.match(
      onlineSchema,
      new RegExp(`SastScannerCoverageRecord_${constraint}`)
    );
  }
  assert.match(
    onlineSchema,
    /CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "SastArtifactDispositionDecision_coverage_scope_key"/
  );
  assert.match(
    onlineSchema,
    /CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "SastFindingCorrelationSource_coverage_scope_key"/
  );
  assert.match(onlineSchema, /ADD CONSTRAINT[\s\S]{0,160}NOT VALID/);
  assert.match(onlineSchema, /VALIDATE CONSTRAINT/);
  assert.match(
    onlineSchema,
    /SastScannerCoverageRecord_ingestion_scope_fkey[\s\S]{0,500}ON DELETE RESTRICT ON UPDATE CASCADE/
  );
  assertScanPlaneExports(scanPlaneModule);

  assert.match(tasks, /- \[x\] T039\b/);
  assert.match(tasks, /- \[x\] T040\b/);
  assert.match(
    quickstart,
    /T040 stale-scan denial and bounded infrastructure-only retry[\s\S]{0,160}T041 bounded[\s\S]{0,160}complete; T042[\s\S]{0,220}next implementation task/
  );
  assert.match(contract, /Scan coverage gate v1/);
  assert.match(contract, /Freshness and bounded retry gate v1/);
  assert.match(dataModel, /SastExternalPublicationDecision/);
  assert.match(dataModel, /SastScanFreshnessDecision/);
  assert.match(dataModel, /SastScanRetryDecision/);
  assert.match(plan, /T039 now[\s\S]{0,80}immutable plan/);
  assert.match(spec, /FR-039a/);
  assert.match(
    research,
    /Decision 21: Persist Coverage from Durable Authority and Deny Publication Until Freshness Exists/
  );
  assert.match(threatModel, /Coverage authority injection/);
  assert.match(threatModel, /Premature complete publication/);
  assert.match(qualityGates, /100% T039 zero-publication invariant/);
});

test('SAST T041 builds bounded accepted-finding evidence and rejects reconstruction', () => {
  const shared = readNormalizedText(
    files.sharedSastAcceptedEvidence
  );
  const sharedTest = readNormalizedText(
    files.sharedSastAcceptedEvidenceTest
  );
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(
    files.apiSastAcceptedEvidence
  );
  const store = readNormalizedText(
    files.apiSastAcceptedEvidenceStore
  );
  const serviceTest = readNormalizedText(
    files.apiSastAcceptedEvidenceTest
  );
  const persistenceTest = readNormalizedText(
    files.apiSastAcceptedEvidencePersistenceTest
  );
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(
    files.apiSastAcceptedEvidenceMigration
  );
  const onlineSchema = readNormalizedText(
    files.apiOnlineSastRuntimeSchema
  );
  const scanPlaneModule = readNormalizedText(
    files.apiScanPlaneModule
  );
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const plan = readNormalizedText(files.plan);
  const spec = readNormalizedText(files.spec);
  const research = readNormalizedText(files.research);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(
    shared,
    /sast-accepted-finding-evidence-v1/
  );
  assert.match(
    shared,
    /maximumReconstructedFileCoverageBasisPoints:\s*2500/
  );
  assert.match(shared, /maximumFragmentsPerFile:\s*2/);
  assert.match(shared, /EVIDENCE_RECONSTRUCTION_OVERLAP/);
  assert.match(shared, /EVIDENCE_RECONSTRUCTION_ADJACENT/);
  assert.match(shared, /EVIDENCE_RECONSTRUCTION_COVERAGE/);
  assert.match(shared, /dashboardAccessAllowed:\s*false/);
  assert.match(sharedIndex, /sast-accepted-evidence/);
  assert.match(
    sharedTest,
    /rejects full-file, overlapping, adjacent, and substantial reconstruction sets/
  );

  assert.match(service, /KNOWN_SECRET_PATTERNS/);
  assert.match(service, /platformSecretValues/);
  assert.match(service, /dashboardPayloadCreated:\s*false/);
  assert.match(service, /aiPayloadCreated:\s*false/);
  assert.match(service, /publicationAttempted:\s*false/);
  assert.doesNotMatch(
    service,
    /@Controller|@(Get|Post|Put|Patch|Delete)\(/u
  );
  assert.doesNotMatch(service, /\bLogger\b|\bconsole\./u);
  assert.match(
    serviceTest,
    /redacts trusted source and persists a bounded internal-only pack/
  );
  assert.match(
    serviceTest,
    /rejects full-file and overlapping reconstruction/
  );
  assert.match(
    persistenceTest,
    /rebinds the complete fresh T040 decision and accepted T037 occurrence/
  );

  assert.match(
    store,
    /isSastScanFreshnessDecisionShapeValid/
  );
  assert.match(store, /isSastFingerprintedFindingShapeValid/);
  assert.match(
    store,
    /Prisma\.TransactionIsolationLevel\.Serializable/
  );
  assert.match(store, /replayExisting/);
  for (const model of [
    'SastEvidenceBuildDecision',
    'SastAcceptedEvidencePack',
    'SastAcceptedEvidenceFragment'
  ]) {
    assert.match(schema, new RegExp('model ' + model + ' \\{'));
    assert.match(
      migration,
      new RegExp('CREATE TABLE "' + model + '"')
    );
  }
  assert.match(
    migration,
    /SastEvidenceBuildDecision_freshness_scope_fkey/
  );
  assert.match(
    onlineSchema,
    /SastEvidenceBuildDecision_occurrence_scope_fkey/
  );
  assert.match(migration, /"dashboardSafe" = false/);
  assert.match(migration, /"aiSafe" = false/);
  assertScanPlaneExports(scanPlaneModule);

  assert.match(tasks, /- \[x\] T041\b/);
  assert.match(
    quickstart,
    /T041 bounded[\s\S]{0,180}are complete; T042[\s\S]{0,220}next implementation task/
  );
  assert.match(contract, /Accepted-finding evidence gate v1/);
  assert.match(dataModel, /SastEvidenceBuildDecision/);
  assert.match(dataModel, /SastAcceptedEvidencePack/);
  assert.match(
    plan,
    /T040 and T041 independently and now proceeds to T042/
  );
  assert.match(spec, /FR-046a/);
  assert.match(
    research,
    /Decision 23: Build Evidence from a Rebound Accepted Occurrence and Reject Reconstruction/
  );
  assert.match(threatModel, /Evidence source forgery/);
  assert.match(
    qualityGates,
    /100% T041 reconstruction invariant/
  );
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
