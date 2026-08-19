import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const files = {
  agents: new URL('../../AGENTS.md', import.meta.url),
  readme: new URL('../../README.md', import.meta.url),
  conventions: new URL('../../docs/github-conventions.md', import.meta.url),
  gitattributes: new URL('../../.gitattributes', import.meta.url),
  rootPackage: new URL('../../package.json', import.meta.url),
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
  sharedSastEvidenceAccess: new URL('../../packages/shared/src/types/sast-evidence-access.ts', import.meta.url),
  sharedSastEvidenceAccessTest: new URL('../../packages/shared/test/sast-evidence-access.test.mjs', import.meta.url),
  sharedSastAiAdvisoryHandoff: new URL('../../packages/shared/src/types/sast-ai-advisory-handoff.ts', import.meta.url),
  sharedSastAiAdvisoryAuthority: new URL('../../packages/shared/src/types/sast-ai-advisory-authority.ts', import.meta.url),
  sharedSastAiAdvisoryAuthorityTest: new URL('../../packages/shared/test/sast-ai-advisory-authority.test.mjs', import.meta.url),
  sharedSastRuleBundleManifest: new URL('../../packages/shared/src/types/sast-rule-bundle-manifest.ts', import.meta.url),
  sharedSastRuleBundleManifestTest: new URL('../../packages/shared/test/sast-rule-bundle-manifest.test.mjs', import.meta.url),
  sharedSastRuleSemanticPolicy: new URL('../../packages/shared/src/types/sast-rule-semantic-policy.ts', import.meta.url),
  sharedSastRuleSemanticPolicyTest: new URL('../../packages/shared/test/sast-rule-semantic-policy.test.mjs', import.meta.url),
  sharedSastRulePromotionLifecycle: new URL('../../packages/shared/src/types/sast-rule-promotion-lifecycle.ts', import.meta.url),
  sharedSastRulePromotionLifecycleTest: new URL('../../packages/shared/test/sast-rule-promotion-lifecycle.test.mjs', import.meta.url),
  sharedSastRuleBundleCanary: new URL('../../packages/shared/src/types/sast-rule-bundle-canary.ts', import.meta.url),
  sharedSastRuleBundleCanaryTest: new URL('../../packages/shared/test/sast-rule-bundle-canary.test.mjs', import.meta.url),
  sharedSastKillSwitch: new URL('../../packages/shared/src/types/sast-kill-switch.ts', import.meta.url),
  sharedSastKillSwitchTest: new URL('../../packages/shared/test/sast-kill-switch.test.mjs', import.meta.url),
  sharedSastRuleBundleRollback: new URL('../../packages/shared/src/types/sast-rule-bundle-rollback.ts', import.meta.url),
  sharedSastRuleBundleRollbackTest: new URL('../../packages/shared/test/sast-rule-bundle-rollback.test.mjs', import.meta.url),
  sharedSastQualificationCorpus: new URL('../../packages/shared/src/types/sast-qualification-corpus.ts', import.meta.url),
  sharedSastQualificationCorpusTest: new URL('../../packages/shared/test/sast-qualification-corpus.test.mjs', import.meta.url),
  qualificationGenerator: new URL('../../tools/sast-qualification/golden-corpus-assets.mjs', import.meta.url),
  qualificationLoader: new URL('../../tools/sast-qualification/corpus-loader.mjs', import.meta.url),
  qualificationLoaderTest: new URL('../../test/qualification/sast-qualification-corpus-loader.test.mjs', import.meta.url),
  qualificationSnapshot: new URL('../../qualification/corpora/v1/golden-corpus.snapshot.json', import.meta.url),
  qualificationPriorReleaseManifest: new URL('../../qualification/corpora/v1/prior-release-must-detect.manifest.json', import.meta.url),
  qualificationReadme: new URL('../../qualification/corpora/v1/README.md', import.meta.url),
  sharedSastMultiClassQualificationCorpus: new URL('../../packages/shared/src/types/sast-multi-class-qualification-corpus.ts', import.meta.url),
  sharedSastMultiClassQualificationCorpusTest: new URL('../../packages/shared/test/sast-multi-class-qualification-corpus.test.mjs', import.meta.url),
  multiClassQualificationGenerator: new URL('../../tools/sast-qualification/multi-class-corpus-assets.mjs', import.meta.url),
  multiClassQualificationLoader: new URL('../../tools/sast-qualification/multi-class-corpus-loader.mjs', import.meta.url),
  multiClassQualificationLoaderTest: new URL('../../test/qualification/sast-multi-class-qualification-corpus-loader.test.mjs', import.meta.url),
  multiClassQualificationSnapshot: new URL('../../qualification/corpora/t052-v1/multi-class-corpus.snapshot.json', import.meta.url),
  multiClassQualificationReadme: new URL('../../qualification/corpora/t052-v1/README.md', import.meta.url),
  sharedSastIsolatedQualification: new URL('../../packages/shared/src/types/sast-isolated-integration-qualification.ts', import.meta.url),
  sharedSastIsolatedQualificationTest: new URL('../../packages/shared/test/sast-isolated-integration-qualification.test.mjs', import.meta.url),
  isolatedQualificationGenerator: new URL('../../tools/sast-qualification/isolated-integration-assets.mjs', import.meta.url),
  isolatedQualificationLoader: new URL('../../tools/sast-qualification/isolated-integration-loader.mjs', import.meta.url),
  isolatedQualificationValidator: new URL('../../tools/sast-qualification/validate-isolated-integration.mjs', import.meta.url),
  isolatedQualificationPlanTool: new URL('../../tools/sast-qualification/generate-isolated-integration-plan.mjs', import.meta.url),
  isolatedQualificationEvidenceTool: new URL('../../tools/sast-qualification/verify-isolated-integration-evidence.mjs', import.meta.url),
  isolatedQualificationLoaderTest: new URL('../../test/qualification/sast-isolated-integration-loader.test.mjs', import.meta.url),
  isolatedQualificationToolsTest: new URL('../../test/qualification/sast-isolated-integration-tools.test.mjs', import.meta.url),
  isolatedQualificationManifest: new URL('../../qualification/t053-v1/isolated-integration.manifest.json', import.meta.url),
  isolatedQualificationPolicy: new URL('../../qualification/t053-v1/materialization-policy.json', import.meta.url),
  isolatedQualificationReadme: new URL('../../qualification/t053-v1/README.md', import.meta.url),
  sharedSastEndToEndQualification: new URL('../../packages/shared/src/types/sast-end-to-end-qualification.ts', import.meta.url),
  sharedSastEndToEndQualificationTest: new URL('../../packages/shared/test/sast-end-to-end-qualification.test.mjs', import.meta.url),
  endToEndQualificationGenerator: new URL('../../tools/sast-qualification/end-to-end-qualification-assets.mjs', import.meta.url),
  endToEndQualificationLoader: new URL('../../tools/sast-qualification/end-to-end-qualification-loader.mjs', import.meta.url),
  endToEndQualificationValidator: new URL('../../tools/sast-qualification/validate-end-to-end-qualification.mjs', import.meta.url),
  endToEndQualificationPlanTool: new URL('../../tools/sast-qualification/generate-end-to-end-qualification-plan.mjs', import.meta.url),
  endToEndQualificationEvidenceTool: new URL('../../tools/sast-qualification/verify-end-to-end-qualification-evidence.mjs', import.meta.url),
  endToEndQualificationTrustTool: new URL('../../tools/sast-qualification/end-to-end-qualification-trust.mjs', import.meta.url),
  endToEndQualificationLoaderTest: new URL('../../test/qualification/sast-end-to-end-qualification-loader.test.mjs', import.meta.url),
  endToEndQualificationToolsTest: new URL('../../test/qualification/sast-end-to-end-qualification-tools.test.mjs', import.meta.url),
  endToEndQualificationManifest: new URL('../../qualification/t054-v1/end-to-end-qualification.manifest.json', import.meta.url),
  endToEndQualificationPolicy: new URL('../../qualification/t054-v1/measurement-policy.json', import.meta.url),
  endToEndQualificationReadme: new URL('../../qualification/t054-v1/README.md', import.meta.url),
  apiSastPlanner: new URL('../../apps/api/src/control-plane/sast-scan-planner.service.ts', import.meta.url),
  apiSastPolicyEvaluationClock: new URL('../../apps/api/src/control-plane/sast-policy-evaluation-clock.service.ts', import.meta.url),
  apiSastQueueAdmission: new URL('../../apps/api/src/control-plane/sast-queue-admission.service.ts', import.meta.url),
  apiPrismaSastQueueAdmissionStore: new URL('../../apps/api/src/control-plane/prisma-sast-queue-admission.store.ts', import.meta.url),
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
  apiSastEvidenceAccess: new URL('../../apps/api/src/scan-plane/sast-evidence-access.service.ts', import.meta.url),
  apiSastEvidenceAccessStore: new URL('../../apps/api/src/scan-plane/prisma-sast-evidence-access.store.ts', import.meta.url),
  apiSastEvidenceSecretRegistry: new URL('../../apps/api/src/scan-plane/sast-evidence-secret-registry.ts', import.meta.url),
  apiSastEvidenceDeletionAuthority: new URL('../../apps/api/src/scan-plane/sast-evidence-deletion.authority.ts', import.meta.url),
  apiSastEvidenceDeletion: new URL('../../apps/api/src/scan-plane/sast-evidence-deletion.service.ts', import.meta.url),
  apiSastEvidenceDeletionTask: new URL('../../apps/api/src/scan-plane/sast-evidence-deletion.task.ts', import.meta.url),
  apiDashboardEvidenceController: new URL('../../apps/api/src/dashboard/dashboard-evidence.controller.ts', import.meta.url),
  apiSastEvidenceAccessTest: new URL('../../apps/api/test/scan-plane/sast-evidence-access.e2e-spec.ts', import.meta.url),
  apiSastEvidenceAccessPersistenceTest: new URL('../../apps/api/test/scan-plane/sast-evidence-access-persistence.e2e-spec.ts', import.meta.url),
  apiAiAdvisoryService: new URL('../../apps/api/src/ai-plane/ai-advisory.service.ts', import.meta.url),
  apiAiAdvisoryStore: new URL('../../apps/api/src/ai-plane/prisma-sast-ai-advisory.store.ts', import.meta.url),
  apiAiAdvisoryRuntime: new URL('../../apps/api/src/ai-plane/ai-advisory-runtime.client.ts', import.meta.url),
  apiAiAdvisoryController: new URL('../../apps/api/src/ai-plane/ai-advisory.controller.ts', import.meta.url),
  apiAiAdvisoryModule: new URL('../../apps/api/src/ai-plane/ai-plane.module.ts', import.meta.url),
  apiAiAdvisoryServiceTest: new URL('../../apps/api/test/ai-plane/ai-advisory.service.e2e-spec.ts', import.meta.url),
  apiAiAdvisoryPersistenceTest: new URL('../../apps/api/test/ai-plane/sast-ai-advisory-persistence.e2e-spec.ts', import.meta.url),
  apiAiAdvisoryAuthorityService: new URL('../../apps/api/src/ai-plane/ai-advisory-authority.service.ts', import.meta.url),
  apiAiAdvisoryAuthorityStore: new URL('../../apps/api/src/ai-plane/prisma-sast-ai-advisory-authority.store.ts', import.meta.url),
  apiAiAdvisoryAuthorityServiceTest: new URL('../../apps/api/test/ai-plane/ai-advisory-authority.service.e2e-spec.ts', import.meta.url),
  apiAiAdvisoryAuthorityPersistenceTest: new URL('../../apps/api/test/ai-plane/sast-ai-advisory-authority-persistence.e2e-spec.ts', import.meta.url),
  apiPolicyEngine: new URL('../../apps/api/src/policy/policy-engine.service.ts', import.meta.url),
  apiPolicyLifecycle: new URL('../../apps/api/src/policy/policy-lifecycle.service.ts', import.meta.url),
  apiPolicyEngineTest: new URL('../../apps/api/test/policy/policy-engine.service.e2e-spec.ts', import.meta.url),
  apiPolicyLifecycleTest: new URL('../../apps/api/test/policy/waiver-suppression-lifecycle.e2e-spec.ts', import.meta.url),
  apiRuleBundleManifestService: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-manifest.service.ts', import.meta.url),
  apiRuleBundleManifestStore: new URL('../../apps/api/src/rule-governance/prisma-sast-rule-bundle-manifest.store.ts', import.meta.url),
  apiRuleBundleCompatibilityGate: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-compatibility.gate.ts', import.meta.url),
  apiRuleBundleSupplyChainAuthority: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-supply-chain.authority.ts', import.meta.url),
  apiRuleGovernanceModule: new URL('../../apps/api/src/rule-governance/rule-governance.module.ts', import.meta.url),
  apiRuleBundleManifestServiceTest: new URL('../../apps/api/test/rule-governance/sast-rule-bundle-manifest.service.e2e-spec.ts', import.meta.url),
  apiRuleBundleManifestPersistenceTest: new URL('../../apps/api/test/rule-governance/sast-rule-bundle-manifest-persistence.e2e-spec.ts', import.meta.url),
  apiRuleSemanticPolicyService: new URL('../../apps/api/src/rule-governance/sast-rule-semantic-policy.service.ts', import.meta.url),
  apiRuleSemanticPolicyStore: new URL('../../apps/api/src/rule-governance/prisma-sast-rule-semantic-policy.store.ts', import.meta.url),
  apiTenantRulePolicyGate: new URL('../../apps/api/src/rule-governance/sast-tenant-rule-policy.gate.ts', import.meta.url),
  apiRuleSemanticPolicyServiceTest: new URL('../../apps/api/test/rule-governance/sast-rule-semantic-policy.service.e2e-spec.ts', import.meta.url),
  apiRuleSemanticPolicyPersistenceTest: new URL('../../apps/api/test/rule-governance/sast-rule-semantic-policy-persistence.e2e-spec.ts', import.meta.url),
  apiRuleBundleLifecycleService: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-lifecycle.service.ts', import.meta.url),
  apiRuleBundleLifecycleStore: new URL('../../apps/api/src/rule-governance/prisma-sast-rule-bundle-lifecycle.store.ts', import.meta.url),
  apiRuleBundleLifecycleGate: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-lifecycle.gate.ts', import.meta.url),
  apiRuleBundleLifecycleAuthority: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-lifecycle.authority.ts', import.meta.url),
  apiRuleBundleLifecycleClock: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-lifecycle.clock.ts', import.meta.url),
  apiRuleBundleLifecycleServiceTest: new URL('../../apps/api/test/rule-governance/sast-rule-bundle-lifecycle.service.e2e-spec.ts', import.meta.url),
  apiRuleBundleLifecyclePersistenceTest: new URL('../../apps/api/test/rule-governance/sast-rule-bundle-lifecycle-persistence.e2e-spec.ts', import.meta.url),
  apiRuleBundleCanaryService: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-canary.service.ts', import.meta.url),
  apiRuleBundleCanaryStore: new URL('../../apps/api/src/rule-governance/prisma-sast-rule-bundle-canary.store.ts', import.meta.url),
  apiRuleBundleCanaryGate: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-canary.gate.ts', import.meta.url),
  apiRuleBundleCanaryKeyProvider: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-canary-key.provider.ts', import.meta.url),
  apiRuleBundleCanaryObservationSource: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-canary-observation.source.ts', import.meta.url),
  apiRuleBundleLifecycleAuthorityRouter: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-lifecycle-authority.router.ts', import.meta.url),
  apiRuleBundleCanaryServiceTest: new URL('../../apps/api/test/rule-governance/sast-rule-bundle-canary.service.e2e-spec.ts', import.meta.url),
  apiRuleBundleCanaryPersistenceTest: new URL('../../apps/api/test/rule-governance/sast-rule-bundle-canary-persistence.e2e-spec.ts', import.meta.url),
  apiSastKillSwitchService: new URL('../../apps/api/src/rule-governance/sast-kill-switch.service.ts', import.meta.url),
  apiSastKillSwitchStore: new URL('../../apps/api/src/rule-governance/prisma-sast-kill-switch.store.ts', import.meta.url),
  apiSastKillSwitchPersistence: new URL('../../apps/api/src/rule-governance/sast-kill-switch-persistence.ts', import.meta.url),
  apiSastKillSwitchGate: new URL('../../apps/api/src/rule-governance/sast-kill-switch.gate.ts', import.meta.url),
  apiSastKillSwitchSignatureAuthority: new URL('../../apps/api/src/rule-governance/sast-kill-switch-signature.authority.ts', import.meta.url),
  apiSastKillSwitchCanarySuspension: new URL('../../apps/api/src/rule-governance/sast-kill-switch-canary-suspension.service.ts', import.meta.url),
  apiSastKillSwitchServiceTest: new URL('../../apps/api/test/rule-governance/sast-kill-switch.service.e2e-spec.ts', import.meta.url),
  apiSastKillSwitchPersistenceTest: new URL('../../apps/api/test/rule-governance/sast-kill-switch-persistence.e2e-spec.ts', import.meta.url),
  apiSastRuleBundleRollbackService: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-rollback.service.ts', import.meta.url),
  apiSastRuleBundleRollbackStore: new URL('../../apps/api/src/rule-governance/prisma-sast-rule-bundle-rollback.store.ts', import.meta.url),
  apiSastRuleBundleRollbackSignatureAuthority: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-rollback-signature.authority.ts', import.meta.url),
  apiSastRuleBundleRollbackClock: new URL('../../apps/api/src/rule-governance/sast-rule-bundle-rollback.clock.ts', import.meta.url),
  apiSastRuleBundleRollbackServiceTest: new URL('../../apps/api/test/rule-governance/sast-rule-bundle-rollback.service.e2e-spec.ts', import.meta.url),
  apiSastRuleBundleRollbackPersistenceTest: new URL('../../apps/api/test/rule-governance/sast-rule-bundle-rollback-persistence.e2e-spec.ts', import.meta.url),
  apiSastRuleBundleRollbackPostgresTest: new URL('../../apps/api/test/rule-governance/sast-rule-bundle-rollback.postgres.e2e-spec.ts', import.meta.url),
  apiSastQueueKillSwitchFenceTest: new URL('../../apps/api/test/control-plane/sast-queue-kill-switch-fence.e2e-spec.ts', import.meta.url),
  apiSastKillSwitchArtifactGate: new URL('../../apps/api/src/scan-plane/sast-kill-switch-artifact-acceptance.gate.ts', import.meta.url),
  apiSastKillSwitchCoverageGate: new URL('../../apps/api/src/scan-plane/sast-kill-switch-finding-lifecycle-coverage.gate.ts', import.meta.url),
  apiSastKillSwitchRetryAuthority: new URL('../../apps/api/src/scan-plane/sast-kill-switch-retry-runtime.authority.ts', import.meta.url),
  apiSastKillSwitchAdapterTest: new URL('../../apps/api/test/scan-plane/sast-kill-switch-adapters.e2e-spec.ts', import.meta.url),
  apiSastScannerRuntime: new URL('../../apps/api/src/scan-plane/sast-scanner-runtime.service.ts', import.meta.url),
  apiSastArtifactAcceptanceGate: new URL('../../apps/api/src/scan-plane/sast-artifact-acceptance-gate.ts', import.meta.url),
  apiControlPlaneService: new URL('../../apps/api/src/control-plane/control-plane.service.ts', import.meta.url),
  aiAdvisoryRuntime: new URL('../../apps/ai/src/advisory-runtime.ts', import.meta.url),
  aiModelGateway: new URL('../../apps/ai/src/model-gateway.ts', import.meta.url),
  apiPrismaSchema: new URL('../../apps/api/prisma/schema.prisma', import.meta.url),
  apiOnlineSastRuntimeSchema: new URL('../../apps/api/scripts/apply-online-sast-runtime-schema.mjs', import.meta.url),
  apiSastFindingLineageMigration: new URL('../../apps/api/prisma/migrations/20260730160000_sast_finding_lineage_lifecycle/migration.sql', import.meta.url),
  apiSastFindingCorrelationMigration: new URL('../../apps/api/prisma/migrations/20260802120000_sast_finding_correlation/migration.sql', import.meta.url),
  apiSastScanCoverageMigration: new URL('../../apps/api/prisma/migrations/20260802150000_sast_scan_coverage/migration.sql', import.meta.url),
  apiSastScanFreshnessMigration: new URL('../../apps/api/prisma/migrations/20260810030000_sast_scan_freshness_retry/migration.sql', import.meta.url),
  apiSastAcceptedEvidenceMigration: new URL('../../apps/api/prisma/migrations/20260810043000_sast_accepted_evidence/migration.sql', import.meta.url),
  apiSastEvidenceAccessMigration: new URL('../../apps/api/prisma/migrations/20260810070000_sast_evidence_access_deletion/migration.sql', import.meta.url),
  apiSastAiAdvisoryMigration: new URL('../../apps/api/prisma/migrations/20260811040000_sast_ai_advisory_handoff/migration.sql', import.meta.url),
  apiSastAiAdvisoryAuthorityMigration: new URL('../../apps/api/prisma/migrations/20260811140000_sast_ai_advisory_authority_proof/migration.sql', import.meta.url),
  apiSastRuleBundleManifestMigration: new URL('../../apps/api/prisma/migrations/20260813120000_sast_rule_bundle_manifest/migration.sql', import.meta.url),
  apiSastRuleSemanticPolicyMigration: new URL('../../apps/api/prisma/migrations/20260813130000_sast_rule_semantic_policy/migration.sql', import.meta.url),
  apiSastRuleBundleLifecycleMigration: new URL('../../apps/api/prisma/migrations/20260814120000_sast_rule_bundle_lifecycle/migration.sql', import.meta.url),
  apiSastRuleBundleCanaryMigration: new URL('../../apps/api/prisma/migrations/20260819120000_sast_rule_bundle_canary/migration.sql', import.meta.url),
  apiSastKillSwitchMigration: new URL('../../apps/api/prisma/migrations/20260819180000_sast_kill_switch_authority/migration.sql', import.meta.url),
  apiSastRuleBundleRollbackMigration: new URL('../../apps/api/prisma/migrations/20260819220000_sast_rule_bundle_rollback/migration.sql', import.meta.url),
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
  assert.match(exportsBlock, /SastEvidenceAccessService/);
  assert.doesNotMatch(exportsBlock, /SastAcceptedEvidenceService/);
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

const assertT049QuickstartHandoff = (quickstart) => {
  assert.match(
    quickstart,
    /T048 deterministic[\s\S]{0,480}are complete\. T049 signed[\s\S]{0,520}are complete\. T050[\s\S]{0,420}are complete\. T051[\s\S]{0,420}is complete:[\s\S]{0,420}T052/
  );
};

const assertT049PlanHandoff = (plan) => {
  assert.match(
    plan,
    /T040 through T052 independently\. The T053 repository-side provider handoff is package-ready/
  );
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
  assert.match(ruleGovernance, /HMAC-SHA-256/);
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
    /T042 purpose-bound dashboard\/AI classification,[\s\S]{0,260}are complete;[\s\S]{0,120}T043/
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
    /T042 purpose-bound dashboard\/AI classification,[\s\S]{0,260}are complete;[\s\S]{0,120}T043/
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
    /T042 purpose-bound dashboard\/AI classification,[\s\S]{0,260}are complete;[\s\S]{0,120}T043/
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
    /T042 purpose-bound dashboard\/AI classification,[\s\S]{0,260}are complete;[\s\S]{0,120}T043/
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
    /T042 purpose-bound dashboard\/AI classification,[\s\S]{0,260}are complete;[\s\S]{0,120}T043/
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
  assertT049QuickstartHandoff(quickstart);
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
  assertT049QuickstartHandoff(quickstart);
  assert.match(contract, /Accepted-finding evidence gate v1/);
  assert.match(dataModel, /SastEvidenceBuildDecision/);
  assert.match(dataModel, /SastAcceptedEvidencePack/);
  assertT049PlanHandoff(plan);
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

test('SAST T042 classifies purpose-bound evidence and proves fenced deletion', () => {
  const shared = readNormalizedText(files.sharedSastEvidenceAccess);
  const sharedTest = readNormalizedText(
    files.sharedSastEvidenceAccessTest
  );
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiSastEvidenceAccess);
  const store = readNormalizedText(files.apiSastEvidenceAccessStore);
  const registry = readNormalizedText(
    files.apiSastEvidenceSecretRegistry
  );
  const deletionAuthority = readNormalizedText(
    files.apiSastEvidenceDeletionAuthority
  );
  const deletionService = readNormalizedText(
    files.apiSastEvidenceDeletion
  );
  const deletionTask = readNormalizedText(
    files.apiSastEvidenceDeletionTask
  );
  const dashboardController = readNormalizedText(
    files.apiDashboardEvidenceController
  );
  const serviceTest = readNormalizedText(
    files.apiSastEvidenceAccessTest
  );
  const persistenceTest = readNormalizedText(
    files.apiSastEvidenceAccessPersistenceTest
  );
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(
    files.apiSastEvidenceAccessMigration
  );
  const scanPlaneModule = readNormalizedText(files.apiScanPlaneModule);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const plan = readNormalizedText(files.plan);
  const spec = readNormalizedText(files.spec);
  const research = readNormalizedText(files.research);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(shared, /sast-evidence-access-decision-v1/);
  assert.match(shared, /sast-evidence-deletion-schedule-v1/);
  assert.match(shared, /sast-evidence-deletion-proof-v1/);
  assert.match(shared, /SAST_EVIDENCE_MAX_RETENTION_SECONDS/);
  assert.match(shared, /SAST_AI_PAYLOAD_MAX_RETENTION_SECONDS/);
  assert.match(shared, /dashboardReadAllowed/);
  assert.match(shared, /reducedEvidenceReferenceAllowed/);
  assert.match(sharedIndex, /sast-evidence-access/);
  assert.match(
    sharedTest,
    /dashboard and AI access decisions keep purpose authority independent/
  );
  assert.match(
    sharedTest,
    /deletion proof binds the deterministic operation and bounded provider receipt/
  );
  assert.match(
    sharedTest,
    /denied decisions keep AI-only fields null and never parse unused expiry/
  );

  assert.match(service, /class SastEvidenceAccessService/);
  assert.match(service, /async readDashboard/);
  assert.match(service, /async classifyForAi/);
  assert.match(service, /KNOWN_SECRET_PATTERNS/);
  assert.match(service, /ENTROPY_TOKEN_PATTERN/);
  assert.match(service, /confirmAccess/);
  assert.doesNotMatch(service, /\bLogger\b|\bconsole\./u);
  assert.match(store, /Prisma\.TransactionIsolationLevel\.Serializable/);
  assert.match(store, /claimDeletion/);
  assert.match(store, /finalizeDeletion/);
  assert.match(store, /providerReceiptDigest/);
  assert.match(store, /fenceDriftedClaim/);
  assert.match(store, /QUARANTINED/);
  assert.match(store, /FOR UPDATE OF p SKIP LOCKED/);
  assert.match(store, /randomInt/);
  assert.match(registry, /UnavailableSastEvidenceSecretRegistry/);
  assert.match(
    registry,
    /Promise\.resolve\(\{ status: 'UNAVAILABLE' \}\)/
  );
  assert.match(
    deletionAuthority,
    /UnavailableSastEvidenceDeletionAuthority/
  );
  assert.match(deletionService, /class SastEvidenceDeletionService/);
  assert.match(deletionService, /DELETION_LEASE_MILLISECONDS/);
  assert.match(deletionService, /isReceiptValid/);
  assert.match(deletionService, /error\.reason === 'CONTEXT_DRIFT'/);
  assert.match(deletionTask, /MAXIMUM_DELETIONS_PER_BATCH = 64/);
  assert.match(deletionTask, /MAXIMUM_BACKFILLS_PER_BATCH = 128/);
  assert.match(deletionTask, /this\.schedule\(0\)/);
  assert.match(deletionTask, /if \(this\.batchSaturated\)/);
  assert.match(deletionTask, /nextDueAt\.getTime\(\) - Date\.now\(\)/);
  assert.match(deletionTask, /attemptClock\(\)/);
  assert.match(dashboardController, /@UseGuards\(SessionAuthGuard\)/);
  assert.match(dashboardController, /@Get\(':evidencePackId'\)/);
  assert.match(dashboardController, /user\.tenantId/);
  assert.match(
    serviceTest,
    /denies expired-at-start and expired-during-read without returning content/
  );
  assert.match(
    serviceTest,
    /denies late readers when the secret registry drifts or deletion is claimed/
  );
  assert.match(
    serviceTest,
    /claims by deterministic operation, deletes content, and retains one bounded proof/
  );
  assert.match(
    serviceTest,
    /fences concurrent workers and rejects a changed receipt after exact proof replay/
  );
  assert.match(
    serviceTest,
    /accepts the original deterministic receipt when finalization retries later/
  );
  assert.match(
    serviceTest,
    /starts immediately and wakes at the earliest durable deletion deadline/
  );
  assert.match(
    serviceTest,
    /contains a fenced context-drift claim so later deletion work can continue/
  );
  assert.match(
    serviceTest,
    /reads a fresh attempt clock for every item in a batch/
  );
  assert.match(
    persistenceTest,
    /serializable replay, claim fencing, and default-unavailable authorities/
  );

  for (const model of [
    'SastEvidenceAccessDecision',
    'SastEvidenceDeletionSchedule',
    'SastEvidenceDeletionClaim',
    'SastEvidenceDeletionProof'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(migration, new RegExp(`CREATE TABLE "${model}"`));
  }
  assert.match(migration, /INTERVAL '7 days'/);
  assert.match(migration, /INTERVAL '24 hours'/);
  assert.match(migration, /SastEvidenceAccessDecision_immutable_update/);
  assert.match(migration, /SastEvidenceDeletionSchedule_immutable_update/);
  assert.match(migration, /SastEvidenceDeletionProof_immutable_update/);
  assert.match(migration, /SastEvidenceAccessDecision_scan_scope_idx/);
  assert.match(migration, /SastEvidenceAccessDecision_build_scope_idx/);
  assert.match(migration, /SastEvidenceDeletionSchedule_scan_scope_idx/);
  assert.match(migration, /QUARANTINED/);
  assertScanPlaneExports(scanPlaneModule);

  assert.match(tasks, /- \[x\] T042\b/);
  assertT049QuickstartHandoff(quickstart);
  assert.match(contract, /Evidence access and deletion gate v1/);
  assert.match(dataModel, /SastEvidenceAccessDecision/);
  assert.match(dataModel, /SastEvidenceDeletionProof/);
  assert.match(plan, /Only `SastEvidenceAccessService` crosses the/);
  assert.match(spec, /FR-048a/);
  assert.match(
    research,
    /Decision 24: Separate Purpose-Bound Access from Receipt-Proven Content Deletion/
  );
  assert.match(threatModel, /False deletion proof/);
  assert.match(qualityGates, /100% T042 deletion-proof invariant/);
});

test('SAST T043 sends only a durable normalized finding and opaque AI reference', () => {
  const shared = readNormalizedText(
    files.sharedSastAiAdvisoryHandoff
  );
  const sharedTest = readNormalizedText(
    files.sharedSastEvidenceAccessTest
  );
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiAiAdvisoryService);
  const store = readNormalizedText(files.apiAiAdvisoryStore);
  const runtime = readNormalizedText(files.apiAiAdvisoryRuntime);
  const controller = readNormalizedText(
    files.apiAiAdvisoryController
  );
  const aiModule = readNormalizedText(files.apiAiAdvisoryModule);
  const serviceTest = readNormalizedText(
    files.apiAiAdvisoryServiceTest
  );
  const persistenceTest = readNormalizedText(
    files.apiAiAdvisoryPersistenceTest
  );
  const aiRuntime = readNormalizedText(files.aiAdvisoryRuntime);
  const modelGateway = readNormalizedText(files.aiModelGateway);
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(
    files.apiSastAiAdvisoryMigration
  );
  const onlineSchema = readNormalizedText(
    files.apiOnlineSastRuntimeSchema
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

  assert.match(shared, /sast-ai-advisory-handoff-v1/);
  assert.match(shared, /isSastAiAdvisoryIntentShapeValid/);
  assert.match(shared, /createdAt: input\.decision\.decidedAt/);
  assert.match(shared, /isSastReducedEvidenceReferenceShapeValid/);
  assert.match(shared, /hasAsciiControl\(value\.title\)/);
  assert.match(shared, /record\[key\] !== undefined/);
  assert.match(sharedIndex, /sast-ai-advisory-handoff/);
  assert.match(
    sharedTest,
    /T043 retries are deterministic and reject caller fields or authority widening/
  );

  assert.match(service, /isSastAiAdvisoryIntentShapeValid/);
  assert.equal(
    service.match(/this\.classify\(scope, clock\)/gu)?.length,
    2
  );
  assert.match(store, /isSastEvidenceAccessDecisionShapeValid/);
  assert.match(
    store,
    /isSastSecretRedactedFindingCandidateShapeValid/
  );
  assert.match(
    store,
    /Prisma\.TransactionIsolationLevel\.Serializable/
  );
  assert.match(store, /id_tenantId/);
  assert.match(store, /isSameInstant/);
  assert.match(service, /safeErrorCategory/);
  assert.doesNotMatch(
    store,
    /handoff:\s*handoff as unknown as Prisma\.InputJsonValue/u
  );
  assert.match(runtime, /snippets: \[\]/);
  assert.match(runtime, /modelVersion: handoff\.modelVersion/);
  assert.match(runtime, /candidate\.modelMetadata\.version !== handoff\.modelVersion/);
  assert.match(runtime, /MAX_RUNTIME_ADVISORIES/);
  assert.match(runtime, /MAX_RUNTIME_SCAN_DEPTH/);
  assert.match(runtime, /retrievalAllowed: false/);
  assert.match(runtime, /toolsAllowed: false/);
  assert.doesNotMatch(runtime, /redactedContent/);
  assert.match(controller, /SastAiAdvisoryIntent/);
  assert.match(aiModule, /ScanPlaneModule/);
  assert.match(
    serviceTest,
    /never accepts caller payloads/
  );
  assert.match(
    persistenceTest,
    /immutable reference-only handoff ledger/
  );
  assert.match(
    aiRuntime,
    /requires a T043 reduced-reference handoff/
  );
  assert.match(aiRuntime, /version: body\.modelVersion/);
  assert.match(modelGateway, /T043_METADATA_KEYS/);
  assert.match(modelGateway, /request\.modelVersion !== config\.version/);
  assert.match(modelGateway, /evidence\.snippets\.length === 0/);

  assert.match(schema, /model SastAiAdvisoryHandoff \{/);
  assert.match(migration, /CREATE TABLE "SastAiAdvisoryHandoff"/);
  assert.match(
    onlineSchema,
    /SastAiAdvisoryHandoff_access_scope_fkey/
  );
  assert.match(
    onlineSchema,
    /CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "SastEvidenceAccessDecision_ai_scope_key"/
  );
  assert.match(
    onlineSchema,
    /CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "AiAdvisoryMetadata_sastHandoffId_key"/
  );
  assert.match(
    onlineSchema,
    /AiAdvisoryMetadata_sastHandoffId_fkey/
  );
  assert.match(
    onlineSchema,
    /SastAiAdvisoryHandoff_occurrence_scope_fkey/
  );
  assert.match(
    onlineSchema,
    /SastAiAdvisoryHandoff_finding_scope_fkey/
  );
  assert.doesNotMatch(
    migration,
    /SastEvidenceAccessDecision_ai_scope_key|SastAiAdvisoryHandoff_(?:occurrence|finding|access)_scope_fkey|AiAdvisoryMetadata_sastHandoffId_(?:key|fkey)/
  );
  assert.match(
    migration,
    /SastAiAdvisoryHandoff_immutable_update/
  );
  assert.doesNotMatch(migration, /"handoff" JSONB/);

  assert.match(tasks, /- \[x\] T043\b/);
  assertT049QuickstartHandoff(quickstart);
  assert.match(contract, /Advisory AI handoff gate v1/);
  assert.match(dataModel, /### SastAiAdvisoryHandoff/);
  assertT049PlanHandoff(plan);
  assert.match(spec, /FR-051a/);
  assert.match(
    research,
    /Decision 25: Derive an Expiring Reference-Only Advisory Handoff from Durable State/
  );
  assert.match(threatModel, /AI handoff forgery or payload smuggling/);
  assert.match(qualityGates, /100% T043 reference-only invariant/);
});

test('SAST T044 proves AI output has zero finding and policy authority', () => {
  const shared = readNormalizedText(
    files.sharedSastAiAdvisoryAuthority
  );
  const sharedTest = readNormalizedText(
    files.sharedSastAiAdvisoryAuthorityTest
  );
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(
    files.apiAiAdvisoryAuthorityService
  );
  const store = readNormalizedText(files.apiAiAdvisoryAuthorityStore);
  const serviceTest = readNormalizedText(
    files.apiAiAdvisoryAuthorityServiceTest
  );
  const persistenceTest = readNormalizedText(
    files.apiAiAdvisoryAuthorityPersistenceTest
  );
  const policy = readNormalizedText(files.apiPolicyEngine);
  const lifecycle = readNormalizedText(files.apiPolicyLifecycle);
  const policyTest = readNormalizedText(files.apiPolicyEngineTest);
  const lifecycleTest = readNormalizedText(
    files.apiPolicyLifecycleTest
  );
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(
    files.apiSastAiAdvisoryAuthorityMigration
  );
  const onlineSchema = readNormalizedText(
    files.apiOnlineSastRuntimeSchema
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

  assert.match(shared, /sast-ai-advisory-authority-proof-v1/);
  assert.match(shared, /sast-ai-advisory-policy-reference-v1/);
  assert.match(
    shared,
    /buildSastAiAdvisoryAuthorityStateSnapshot/
  );
  assert.match(shared, /stableJson\(input\.before\) !== stableJson\(input\.after\)/);
  assert.match(shared, /findingCreateAuthority: false/);
  assert.match(shared, /policyOverrideAuthority: false/);
  assert.match(shared, /blockDecisionAuthority: false/);
  assert.match(sharedIndex, /sast-ai-advisory-authority/);
  assert.match(sharedTest, /rejects state drift, caller authority/);

  assert.match(service, /isSastAiAdvisoryAuthorityProofIntentShapeValid/);
  assert.match(service, /buildSastAiAdvisoryPolicyReference/);
  assert.match(store, /Prisma\.TransactionIsolationLevel\.Serializable/);
  assert.match(store, /captureAuthorityState/);
  assert.match(store, /acquireAuthorityFence\(tx, context\)/);
  assert.doesNotMatch(
    store,
    /const after = await captureAuthorityState\(tx, context\)/
  );
  assert.match(store, /sastAiAdvisoryAuthorityProof\.create/);
  assert.doesNotMatch(
    store,
    /\b(?:normalizedFinding|sastFindingLifecycleState|policyDecision|waiver|suppression)\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany)\b/u
  );
  assert.match(
    policy,
    /isSastAiAdvisoryPolicyReferenceShapeValid/
  );
  assert.match(policy, /verifyPolicyReference/);
  assert.match(lifecycle, /assertExactLifecyclePayload/);
  assert.doesNotMatch(lifecycle, /new RegExp\(forbiddenKey/);
  assert.match(serviceTest, /rejects caller finding, lifecycle, waiver/);
  assert.match(persistenceTest, /no authoritative model writes/);
  assert.match(policyTest, /rejects suggested actions/);
  assert.match(lifecycleTest, /authorityProofId/);

  assert.match(schema, /model SastAiAdvisoryAuthorityProof \{/);
  assert.match(
    migration,
    /CREATE TABLE "SastAiAdvisoryAuthorityProof"/
  );
  assert.match(
    migration,
    /"beforeStateDigest" = "afterStateDigest"/
  );
  assert.match(
    migration,
    /SastAiAdvisoryAuthorityProof_immutable_update/
  );
  assert.match(
    migration,
    /acquire_sast_ai_advisory_authority_fence/
  );
  assert.match(migration, /PolicyDecision_ai_authority_fence/);
  assert.doesNotMatch(migration, /JSONB/);
  assert.match(
    onlineSchema,
    /NormalizedFinding_ai_authority_scope_key/
  );
  assert.match(
    onlineSchema,
    /SastAiAdvisoryHandoff_authority_scope_key/
  );
  assert.match(
    onlineSchema,
    /SastAiAdvisoryAuthorityProof_handoff_authority_scope_fkey/
  );
  assert.match(
    onlineSchema,
    /SastAiAdvisoryAuthorityProof_occurrence_scope_fkey/
  );
  assert.match(
    onlineSchema,
    /SastAiAdvisoryAuthorityProof_finding_scope_fkey/
  );
  assert.doesNotMatch(
    migration,
    /SastAiAdvisoryAuthorityProof_(?:occurrence|finding)_scope_fkey/
  );

  assert.match(tasks, /- \[x\] T044\b/);
  assertT049QuickstartHandoff(quickstart);
  assert.match(contract, /Advisory output authority proof gate v1/);
  assert.match(dataModel, /### SastAiAdvisoryAuthorityProof/);
  assertT049PlanHandoff(plan);
  assert.match(spec, /FR-052a/);
  assert.match(
    research,
    /Decision 26: Prove Advisory Consumption with an Immutable Zero-Authority Ledger/
  );
  assert.match(
    threatModel,
    /AI output authority escalation or proof forgery/
  );
  assert.match(qualityGates, /100% T044 zero-authority invariant/);
});

test('SAST T045 requires signed immutable manifests and exact compatibility before queueing', () => {
  const shared = readNormalizedText(files.sharedSastRuleBundleManifest);
  const sharedTest = readNormalizedText(
    files.sharedSastRuleBundleManifestTest
  );
  const sharedRuntime = readNormalizedText(files.sharedSastRuntime);
  const sharedPlanning = readNormalizedText(files.sharedSastPlanning);
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiRuleBundleManifestService);
  const store = readNormalizedText(files.apiRuleBundleManifestStore);
  const gate = readNormalizedText(files.apiRuleBundleCompatibilityGate);
  const authority = readNormalizedText(
    files.apiRuleBundleSupplyChainAuthority
  );
  const moduleSource = readNormalizedText(files.apiRuleGovernanceModule);
  const serviceTest = readNormalizedText(
    files.apiRuleBundleManifestServiceTest
  );
  const persistenceTest = readNormalizedText(
    files.apiRuleBundleManifestPersistenceTest
  );
  const planner = readNormalizedText(files.apiSastPlanner);
  const plannerTest = readNormalizedText(files.apiSastPlannerTest);
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(
    files.apiSastRuleBundleManifestMigration
  );
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);

  assert.match(shared, /sast-rule-bundle-manifest-v1/);
  assert.match(
    shared,
    /sast-rule-bundle-supply-chain-attestation-v1/
  );
  assert.match(
    shared,
    /sast-rule-bundle-compatibility-receipt-v1/
  );
  assert.match(shared, /signatureBytesStored: false/);
  assert.match(shared, /provenancePayloadStored: false/);
  assert.match(shared, /customerInputAccepted: false/);
  assert.match(shared, /executableRuleContentStored: false/);
  assert.match(shared, /findSastRuleBundleCompatibilityReasonCodes/);
  assert.match(sharedTest, /rejects manifest tampering/);
  assert.match(sharedTest, /persists no denial receipt/);
  assert.match(sharedRuntime, /VerifiedScannerSetDescriptor/);
  assert.match(sharedRuntime, /compatibilityReceiptDigest/);
  assert.match(sharedPlanning, /RULE_BUNDLE_MANIFEST_UNVERIFIED/);
  assert.match(sharedPlanning, /compatibilityReceiptDigest/);
  assert.match(sharedIndex, /sast-rule-bundle-manifest/);

  assert.match(service, /registerVerifiedManifest/);
  assert.match(service, /manifestProjectionMatches/);
  assert.match(service, /buildSastRuleBundleCompatibilityReceipt/);
  assert.match(store, /Prisma\.TransactionIsolationLevel\.Serializable/);
  assert.match(store, /canonicalizeSastRuleBundleManifest/);
  assert.match(store, /recordCompatibilityReceipt/);
  assert.match(gate, /MANIFEST_UNVERIFIED/);
  assert.match(gate, /COMPATIBILITY_UNSUPPORTED/);
  assert.match(authority, /AUTHORITY_UNAVAILABLE/);
  assert.match(
    moduleSource,
    /UnavailableSastRuleBundleSupplyChainAuthority/
  );
  assert.match(serviceTest, /defaults to an unavailable verifier/);
  assert.match(persistenceTest, /gates planning before queue reservation/);

  const compatibilityGate = planner.indexOf(
    'ruleBundleCompatibilityGate.verifyScannerSet'
  );
  const queueReservation = planner.indexOf(
    'assertSastQueueReservationAllowed'
  );
  assert.ok(compatibilityGate >= 0);
  assert.ok(queueReservation > compatibilityGate);
  assert.match(plannerTest, /fails closed before queue reservation/);

  for (const model of [
    'SastRuleBundleManifest',
    'SastRuleBundleManifestMember',
    'SastRuleBundleManifestRule',
    'SastRuleBundleCompatibilityEntry',
    'SastRuleBundleSupplyChainAttestation',
    'SastRuleBundleCompatibilityReceipt'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(migration, new RegExp(`CREATE TABLE "${model}"`));
    assert.match(migration, new RegExp(`${model}_immutable_update`));
    assert.match(migration, new RegExp(`${model}_immutable_delete`));
  }
  assert.doesNotMatch(migration, /JSONB/);
  assert.doesNotMatch(
    migration,
    /"(?:ruleContent|sourceContent|repositoryContent|signatureBytes|provenancePayload|secretValue)"/
  );

  assert.match(tasks, /- \[x\] T045\b/);
  assertT049QuickstartHandoff(quickstart);
  assertT049PlanHandoff(plan);
  assert.match(ruleGovernance, /A signed bundle manifest contains only/);
  assert.match(ruleGovernance, /mutable tags[\s\S]{0,40}invalid production inputs/);
  assert.match(contract, /Rule-bundle manifest and compatibility gate v1/);
  assert.match(dataModel, /### SastRuleBundleManifest/);
  assert.match(dataModel, /### SastRuleBundleCompatibilityReceipt/);
});

test('SAST T046 binds semantic metadata and monotonic tenant policy before queueing', () => {
  const shared = readNormalizedText(files.sharedSastRuleSemanticPolicy);
  const sharedTest = readNormalizedText(
    files.sharedSastRuleSemanticPolicyTest
  );
  const sharedRuntime = readNormalizedText(files.sharedSastRuntime);
  const sharedPlanning = readNormalizedText(files.sharedSastPlanning);
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiRuleSemanticPolicyService);
  const store = readNormalizedText(files.apiRuleSemanticPolicyStore);
  const gate = readNormalizedText(files.apiTenantRulePolicyGate);
  const moduleSource = readNormalizedText(files.apiRuleGovernanceModule);
  const serviceTest = readNormalizedText(
    files.apiRuleSemanticPolicyServiceTest
  );
  const persistenceTest = readNormalizedText(
    files.apiRuleSemanticPolicyPersistenceTest
  );
  const planner = readNormalizedText(files.apiSastPlanner);
  const policyEvaluationClock = readNormalizedText(
    files.apiSastPolicyEvaluationClock
  );
  const plannerTest = readNormalizedText(files.apiSastPlannerTest);
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(
    files.apiSastRuleSemanticPolicyMigration
  );
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const spec = readNormalizedText(files.spec);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(shared, /sast-rule-semantic-identity-v1/);
  assert.match(shared, /sast-rule-definition-metadata-v1/);
  assert.match(shared, /sast-rule-definition-metadata-binding-v1/);
  assert.match(shared, /sast-tenant-rule-policy-v1/);
  assert.match(shared, /sast-tenant-rule-policy-resolution-v1/);
  assert.match(shared, /receiptIdentityDigest/);
  assert.match(shared, /customerExecutableConfigAllowed: false/);
  assert.match(shared, /customerSourceStored: false/);
  assert.match(shared, /secretValueStored: false/);
  assert.match(shared, /maximumManifestDigests: 256/);
  assert.match(
    sharedTest,
    /separates reusable rule metadata from immutable signed-manifest bindings/
  );
  assert.match(
    sharedTest,
    /repository overrides can narrow but cannot re-enable a tenant-disabled rule/
  );
  assert.match(sharedRuntime, /VerifiedSastTenantRulePolicyDescriptor/);
  assert.match(sharedRuntime, /tenantRulePolicy/);
  assert.match(sharedPlanning, /TENANT_RULE_POLICY_INVALID/);
  assert.match(sharedPlanning, /tenantRulePolicy/);
  assert.match(sharedPlanning, /sast-canonical-scan-key-v4/);
  assert.match(sharedIndex, /sast-rule-semantic-policy/);

  assert.match(service, /registerRuleMetadataBinding/);
  assert.match(service, /metadataCompatibilityMatchesManifest/);
  assert.match(service, /buildSastTenantRulePolicyResolution/);
  assert.match(store, /Prisma\.TransactionIsolationLevel\.Serializable/);
  assert.match(store, /assertPolicyReferences/);
  assert.match(store, /recordPolicyResolution/);
  assert.match(gate, /RULE_METADATA_UNVERIFIED/);
  assert.match(gate, /TENANT_POLICY_INVALID/);
  assert.match(moduleSource, /SastTenantRulePolicyGate/);
  assert.match(
    serviceTest,
    /fails closed when the resolved scanner set has %s metadata/
  );
  assert.match(
    persistenceTest,
    /gates the canonical plan and queue admission/
  );

  const compatibilityGate = planner.indexOf(
    'ruleBundleCompatibilityGate.verifyScannerSet'
  );
  const policyGate = planner.indexOf('tenantRulePolicyGate.resolve');
  const canonicalKey = planner.indexOf(
    'buildSastCanonicalScanKeyPreimage',
    policyGate
  );
  const queueReservation = planner.indexOf(
    'assertSastQueueReservationAllowed'
  );
  assert.ok(compatibilityGate >= 0);
  assert.ok(policyGate > compatibilityGate);
  assert.ok(canonicalKey > policyGate);
  assert.ok(queueReservation > canonicalKey);
  assert.match(policyEvaluationClock, /return new Date\(\)/);
  assert.match(planner, /policyEvaluationClock\.now\(\)/);
  assert.match(
    plannerTest,
    /fails closed before queue reservation for tenant policy %s/
  );
  assert.match(
    plannerTest,
    /uses the trusted service clock for policy windows instead of requestedAt/
  );
  assert.match(
    plannerTest,
    /fails closed before queue reservation for a %s policy clock/
  );
  assert.match(plannerTest, /TENANT_RULE_POLICY_INVALID/);

  for (const model of [
    'SastRuleSemanticIdentity',
    'SastRuleSemanticIdentityValue',
    'SastRuleDefinitionMetadata',
    'SastRuleDefinitionMetadataValue',
    'SastRuleDefinitionMetadataBinding',
    'SastTenantRulePolicy',
    'SastTenantRulePolicyDecision',
    'SastTenantRulePolicyPathExclusion',
    'SastTenantRulePolicyRepositoryOverride',
    'SastTenantRulePolicyRepositoryDecision',
    'SastTenantRulePolicyRepositoryPathExclusion',
    'SastTenantRulePolicyWaiverReference',
    'SastTenantRulePolicySuppressionReference',
    'SastTenantRulePolicyResolution',
    'SastTenantRulePolicyResolutionRule',
    'SastTenantRulePolicyResolutionPathExclusion'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(migration, new RegExp(`CREATE TABLE "${model}"`));
    assert.match(migration, new RegExp(`${model}_immutable_update`));
    assert.match(migration, new RegExp(`${model}_immutable_delete`));
  }
  assert.match(migration, /receiptIdentityDigest/);
  assert.match(migration, /"evaluatedAt" TIMESTAMP\(3\) NOT NULL/);
  assert.match(migration, /T046 canonical scan-key v2 cutover/);
  assert.doesNotMatch(migration, /JSONB/);
  assert.doesNotMatch(
    migration,
    /"(?:ruleContent|sourceContent|repositoryContent|signatureBytes|provenancePayload|secretValue)"/
  );

  assert.match(tasks, /- \[x\] T046\b/);
  assertT049QuickstartHandoff(quickstart);
  assertT049PlanHandoff(plan);
  assert.match(contract, /Semantic metadata and tenant rule-policy gate v1/);
  assert.match(contract, /exact UTC millisecond form/);
  assert.match(dataModel, /### RuleDefinitionMetadata/);
  assert.match(dataModel, /### TenantRulePolicy/);
  assert.match(spec, /FR-058a/);
  assert.match(spec, /FR-058b/);
  assert.match(spec, /FR-058c/);
  assert.match(ruleGovernance, /T046 Semantic Metadata and Tenant Policy Boundary/);
  assert.match(threatModel, /Semantic identity reuse/);
  assert.match(qualityGates, /100% T046 semantic-identity invariant/);
  assert.match(qualityGates, /100% T046 policy\/planning invariant/);
});

test('SAST T047 binds promotion evidence and latest lifecycle state before queueing', () => {
  const shared = readNormalizedText(files.sharedSastRulePromotionLifecycle);
  const sharedTest = readNormalizedText(
    files.sharedSastRulePromotionLifecycleTest
  );
  const sharedRuntime = readNormalizedText(files.sharedSastRuntime);
  const sharedPlanning = readNormalizedText(files.sharedSastPlanning);
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiRuleBundleLifecycleService);
  const store = readNormalizedText(files.apiRuleBundleLifecycleStore);
  const gate = readNormalizedText(files.apiRuleBundleLifecycleGate);
  const authority = readNormalizedText(files.apiRuleBundleLifecycleAuthority);
  const clock = readNormalizedText(files.apiRuleBundleLifecycleClock);
  const moduleSource = readNormalizedText(files.apiRuleGovernanceModule);
  const serviceTest = readNormalizedText(files.apiRuleBundleLifecycleServiceTest);
  const persistenceTest = readNormalizedText(
    files.apiRuleBundleLifecyclePersistenceTest
  );
  const planner = readNormalizedText(files.apiSastPlanner);
  const plannerTest = readNormalizedText(files.apiSastPlannerTest);
  const queueStore = readNormalizedText(files.apiPrismaSastQueueAdmissionStore);
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(files.apiSastRuleBundleLifecycleMigration);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const spec = readNormalizedText(files.spec);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(shared, /sast-rule-bundle-promotion-evidence-v1/);
  assert.match(shared, /sast-rule-bundle-promotion-approval-v1/);
  assert.match(shared, /sast-rule-bundle-lifecycle-transition-v1/);
  assert.match(shared, /sast-rule-bundle-lifecycle-selection-v1/);
  assert.match(shared, /minimumPositiveCases: 200/);
  assert.match(shared, /minimumNegativeCases: 200/);
  assert.match(shared, /minimumPerformanceRuns: 30/);
  assert.match(shared, /minimumMustDetectRecallBasisPoints: 9_500/);
  assert.match(shared, /minimumCriticalHighPrecisionBasisPoints: 9_000/);
  assert.match(shared, /maximumFalsePositiveIncreaseBasisPoints: 200/);
  assert.match(shared, /maximumScannerFailureRateBasisPoints: 200/);
  assert.match(shared, /maximumP95LatencyIncreaseBasisPoints: 2_000/);
  assert.match(shared, /automatedEvidenceOnly: true/);
  assert.match(shared, /automatedApproval: false/);
  assert.match(shared, /approvalSeparationVerified: true/);
  assert.match(
    sharedTest,
    /rejects every quantitative gate independently and in stable order/
  );
  assert.match(
    sharedTest,
    /permits only the append-only lifecycle graph and required authorities/
  );
  assert.match(
    sharedTest,
    /validators return false for hostile nested shapes without throwing/
  );
  assert.match(
    sharedTest,
    /rejects digest-derived identifiers that are not bound to their paired digest/
  );
  assert.match(sharedRuntime, /PromotionVerifiedScannerSetDescriptor/);
  assert.match(sharedRuntime, /VerifiedSastRuleBundleLifecycleDescriptor/);
  for (const reason of [
    'RULE_BUNDLE_PROMOTION_EVIDENCE_UNVERIFIED',
    'RULE_BUNDLE_PROMOTION_APPROVAL_INVALID',
    'RULE_BUNDLE_LIFECYCLE_NOT_SELECTABLE',
    'RULE_BUNDLE_LIFECYCLE_STALE',
    'RULE_BUNDLE_LIFECYCLE_AUTHORITY_UNAVAILABLE',
    'RULE_BUNDLE_LIFECYCLE_STORE_UNAVAILABLE'
  ]) {
    assert.match(sharedPlanning, new RegExp(reason));
    assert.match(planner, new RegExp(reason));
  }
  assert.match(sharedPlanning, /sast-canonical-scan-key-v4/);
  assert.match(sharedIndex, /sast-rule-promotion-lifecycle/);

  assert.match(service, /registerPromotionEvidence/);
  assert.match(service, /registerPromotionApproval/);
  assert.match(service, /async transition/);
  assert.match(service, /recordLifecycleSelections/);
  assert.match(store, /Prisma\.TransactionIsolationLevel\.Serializable/);
  assert.match(store, /FOR UPDATE/);
  assert.match(store, /transitionExtendsLatest/);
  assert.match(store, /selectionMatchesLatest/);
  assert.match(gate, /PROMOTION_EVIDENCE_UNVERIFIED/);
  assert.match(gate, /PROMOTION_APPROVAL_INVALID/);
  assert.match(authority, /UnavailableSastRuleBundleLifecycleAuthority/);
  assert.match(clock, /return new Date\(\)/);
  assert.match(moduleSource, /SastRuleBundleLifecycleService/);
  assert.match(moduleSource, /SastRuleBundleLifecycleGate/);
  assert.match(moduleSource, /UnavailableSastRuleBundleLifecycleAuthority/);
  assert.match(
    serviceTest,
    /promotes two verified bundles through the exact graph and binds latest ACTIVE receipts/
  );
  assert.match(
    serviceTest,
    /denies planning after an authoritative suspension transition/
  );
  assert.match(
    serviceTest,
    /persists no partial scanner-set selection when a later bundle is unverified/
  );
  assert.match(
    persistenceTest,
    /serializes append and latest-selection races with bounded retries/
  );
  assert.match(
    persistenceTest,
    /fences queue admission against a concurrent lifecycle transition/
  );
  assert.match(queueStore, /assertCurrentRuleBundleLifecycleHeads/);
  assert.match(queueStore, /FOR UPDATE OF head/);

  const compatibilityGate = planner.indexOf(
    'ruleBundleCompatibilityGate.verifyScannerSet'
  );
  const lifecycleGate = planner.indexOf(
    'ruleBundleLifecycleGate.verifyScannerSet'
  );
  const policyGate = planner.indexOf('tenantRulePolicyGate.resolve');
  const canonicalKey = planner.indexOf(
    'buildSastCanonicalScanKeyPreimage',
    policyGate
  );
  const queueReservation = planner.indexOf(
    'assertSastQueueReservationAllowed'
  );
  assert.ok(compatibilityGate >= 0);
  assert.ok(lifecycleGate > compatibilityGate);
  assert.ok(policyGate > lifecycleGate);
  assert.ok(canonicalKey > policyGate);
  assert.ok(queueReservation > canonicalKey);
  assert.match(
    plannerTest,
    /fails closed before tenant policy and queue reservation for lifecycle %s/
  );
  assert.match(
    plannerTest,
    /lifecycleTransitionDigest: digest\('a'\)/
  );
  assert.match(plannerTest, /expect\(keyFor\(receiptOnlyScannerSet\)\)\.toBe\(baseline\)/);

  const canonicalPreimage = sharedPlanning
    .split('export function buildSastCanonicalScanKeyPreimage')[1]
    .split('function rejectedProfileSelection')[0];
  assert.doesNotMatch(canonicalPreimage, /selectionReceiptId/);
  assert.doesNotMatch(canonicalPreimage, /selectionReceiptDigest/);

  for (const model of [
    'SastRuleBundlePromotionEvidence',
    'SastRuleBundlePromotionApproval',
    'SastRuleBundleLifecycleTransition',
    'SastRuleBundleLifecycleTransitionApproval',
    'SastRuleBundleLifecycleSelectionReceipt'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(migration, new RegExp(`CREATE TABLE "${model}"`));
    assert.match(migration, new RegExp(`${model}_immutable_update`));
    assert.match(migration, new RegExp(`${model}_immutable_delete`));
  }
  assert.match(schema, /model SastRuleBundleLifecycleHead \{/);
  assert.match(migration, /CREATE TABLE "SastRuleBundleLifecycleHead"/);
  assert.match(migration, /SastRuleBundleLifecycleTransition_refresh_head/);
  assert.match(migration, /SastQueueReservation_lifecycle_head/);
  assert.match(migration, /T047 canonical scan-key v3 cutover/);
  assert.match(migration, /"terminalStatus" IS NULL/);
  assert.doesNotMatch(migration, /INTO STRICT/);
  assert.match(
    migration,
    /"positiveCases" BETWEEN 200 AND 1000000000[\s\S]{0,80}"negativeCases" BETWEEN 200 AND 1000000000/
  );
  assert.match(
    migration,
    /"goldenTotalCases" = "positiveCases" \+ "negativeCases"/
  );
  assert.match(
    migration,
    /"candidateP95LatencyMilliseconds" BETWEEN 1 AND 600000/
  );
  assert.match(
    migration,
    /"kind" = 'PROFILE_ID' AND "value" = NEW\."profileId"/
  );
  assert.match(migration, /pg_advisory_xact_lock/);
  assert.match(migration, /DEFERRABLE INITIALLY DEFERRED/);
  assert.match(migration, /SastRuleBundleLifecycleSelectionReceipt_latest/);
  assert.doesNotMatch(
    migration,
    /"(?:evidence|approval|transition|selection|head)(?:Payload|Json)"\s+JSONB/i
  );
  assert.doesNotMatch(
    migration,
    /"(?:ruleContent|sourceContent|repositoryContent|signatureBytes|provenancePayload|secretValue)"/
  );

  assert.match(tasks, /- \[x\] T047\b/);
  assertT049QuickstartHandoff(quickstart);
  assertT049PlanHandoff(plan);
  assert.match(contract, /Promotion evidence and lifecycle selection gate v1/);
  assert.match(dataModel, /### SastRuleBundlePromotionEvidence/);
  assert.match(dataModel, /### SastRuleBundleLifecycleSelectionReceipt/);
  assert.match(spec, /FR-055a/);
  assert.match(spec, /FR-055b/);
  assert.match(spec, /FR-055c/);
  assert.match(ruleGovernance, /T047 Promotion and Lifecycle Boundary/);
  assert.match(threatModel, /Lifecycle fork, stale replay, or partial scanner-set selection/);
  assert.match(qualityGates, /100% T047 evidence invariant/);
  assert.match(qualityGates, /100% T047 planning invariant/);
});

test('SAST T048 binds deterministic cohorts and exact observation authority before queueing', () => {
  const shared = readNormalizedText(files.sharedSastRuleBundleCanary);
  const sharedTest = readNormalizedText(files.sharedSastRuleBundleCanaryTest);
  const sharedRuntime = readNormalizedText(files.sharedSastRuntime);
  const sharedPlanning = readNormalizedText(files.sharedSastPlanning);
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiRuleBundleCanaryService);
  const store = readNormalizedText(files.apiRuleBundleCanaryStore);
  const gate = readNormalizedText(files.apiRuleBundleCanaryGate);
  const keyProvider = readNormalizedText(files.apiRuleBundleCanaryKeyProvider);
  const observationSource = readNormalizedText(
    files.apiRuleBundleCanaryObservationSource
  );
  const authorityRouter = readNormalizedText(
    files.apiRuleBundleLifecycleAuthorityRouter
  );
  const moduleSource = readNormalizedText(files.apiRuleGovernanceModule);
  const serviceTest = readNormalizedText(files.apiRuleBundleCanaryServiceTest);
  const persistenceTest = readNormalizedText(
    files.apiRuleBundleCanaryPersistenceTest
  );
  const planner = readNormalizedText(files.apiSastPlanner);
  const plannerTest = readNormalizedText(files.apiSastPlannerTest);
  const queueStore = readNormalizedText(files.apiPrismaSastQueueAdmissionStore);
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(files.apiSastRuleBundleCanaryMigration);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const spec = readNormalizedText(files.spec);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  for (const version of [
    'sast-rule-bundle-canary-rollout-v1',
    'sast-rule-bundle-canary-eligibility-v1',
    'sast-rule-bundle-canary-membership-v1',
    'sast-rule-bundle-canary-assignment-v1',
    'sast-rule-bundle-canary-scan-observation-v1',
    'sast-rule-bundle-canary-step-decision-v1',
    'sast-rule-bundle-canary-observation-receipt-v1'
  ]) {
    assert.match(shared, new RegExp(version));
  }
  for (const step of [
    'INTERNAL_CORPUS',
    'INTERNAL_REPOSITORIES',
    'PERCENT_1',
    'PERCENT_5',
    'PERCENT_25',
    'PERCENT_100'
  ]) {
    assert.match(shared, new RegExp(step));
  }
  assert.match(shared, /bucketCardinality: 10_000/);
  assert.match(shared, /minimumStandardCompletedScansPerArm: 200/);
  assert.match(shared, /minimumExpandedCompletedScansPerArm: 1_000/);
  assert.match(shared, /maximumFalsePositiveIncreaseBasisPoints: 200/);
  assert.match(shared, /maximumScannerFailureRateBasisPoints: 200/);
  assert.match(shared, /maximumP95LatencyIncreaseBasisPoints: 2_000/);
  assert.match(shared, /maximumCriticalHighVolumeIncreaseBasisPoints: 2_000/);
  assert.match(shared, /COVERAGE_INCOMPLETE/);
  assert.match(shared, /relativeRateIncreaseAtMost\(/);
  assert.match(shared, /frame\(input\.tenantId\)/);
  assert.match(shared, /frame\(input\.repositoryBindingId\)/);
  assert.match(shared, /frame\(input\.profileId\)/);
  assert.match(shared, /frame\(input\.rolloutId\)/);
  assert.match(shared, /CANARY_PAUSE_REASONS/);
  assert.match(sharedTest, /stable tenant-safe membership/);
  assert.match(sharedTest, /1,000 scans per arm and 48 hours/);
  assert.match(sharedTest, /all six passed steps in order/);
  assert.match(sharedRuntime, /CanaryQualifiedScannerSetDescriptor/);
  assert.match(sharedPlanning, /sast-canonical-scan-key-v4/);
  assert.match(sharedIndex, /sast-rule-bundle-canary/);

  assert.match(service, /createHmac\('sha256'/);
  assert.match(service, /keyMaterial\?\.fill\(0\)/);
  assert.match(service, /registerEligibilityDecision/);
  assert.match(service, /recordScanObservation/);
  assert.match(service, /evaluateStep/);
  assert.match(service, /authorizeLifecycleTransition/);
  assert.doesNotMatch(service, /observationIds/);
  assert.match(service, /const windowEndedAt = evaluatedAt/);
  assert.match(service, /windowStartedAt: current\.windowStartedAt/);
  assert.match(store, /Prisma\.TransactionIsolationLevel\.Serializable/);
  assert.match(store, /candidateManifestId_profileId/);
  assert.match(gate, /CANARY_ASSIGNMENT_STALE/);
  assert.match(keyProvider, /MINIMUM_HMAC_KEY_BYTES = 32/);
  assert.match(keyProvider, /SAST_CANARY_COHORT_HMAC_KEY_BASE64/);
  assert.match(keyProvider, /createHash\('sha256'\)\.update\(keyMaterial\)/);
  assert.match(observationSource, /UnavailableSastRuleBundleCanaryObservationSource/);
  assert.doesNotMatch(observationSource, /cohortRole|repositorySizeBucket/);
  assert.match(authorityRouter, /input\.authority !== 'CANARY_OBSERVATION'/);
  assert.match(moduleSource, /SastRuleBundleCanaryService/);
  assert.match(moduleSource, /SastRuleBundleLifecycleAuthorityRouter/);
  assert.match(serviceTest, /passes all six ordered steps/);
  assert.match(serviceTest, /insufficient duration\/sample evidence pending/);
  assert.match(serviceTest, /caller-selected-observations/);
  assert.match(serviceTest, /incomplete coverage/);
  assert.match(persistenceTest, /recomputes every observation aggregate/);
  assert.match(persistenceTest, /canonical v4 stable cohort identity/);

  const compatibilityGate = planner.indexOf(
    'ruleBundleCompatibilityGate.verifyScannerSet'
  );
  const lifecycleGate = planner.indexOf(
    'ruleBundleLifecycleGate.verifyScannerSet'
  );
  const canaryGate = planner.indexOf('ruleBundleCanaryGate.verifyScannerSet');
  const policyGate = planner.indexOf('tenantRulePolicyGate.resolve');
  const canonicalKey = planner.indexOf(
    'buildSastCanonicalScanKeyPreimage',
    policyGate
  );
  assert.ok(compatibilityGate >= 0);
  assert.ok(lifecycleGate > compatibilityGate);
  assert.ok(canaryGate > lifecycleGate);
  assert.ok(policyGate > canaryGate);
  assert.ok(canonicalKey > policyGate);
  assert.match(plannerTest, /fails closed after lifecycle and before tenant policy for canary/);
  assert.match(queueStore, /assertCurrentRuleBundleCanaryAssignments/);
  assert.match(queueStore, /FOR UPDATE OF head/);

  const canonicalPreimage = sharedPlanning
    .split('export function buildSastCanonicalScanKeyPreimage')[1]
    .split('function rejectedProfileSelection')[0];
  assert.match(canonicalPreimage, /rolloutId/);
  assert.match(canonicalPreimage, /membershipId/);
  assert.match(canonicalPreimage, /bucketBasisPoints/);
  assert.doesNotMatch(canonicalPreimage, /assignmentReceiptId/);
  assert.doesNotMatch(canonicalPreimage, /stepHeadDecisionId/);

  for (const model of [
    'SastRuleBundleCanaryRollout',
    'SastRuleBundleCanaryRolloutStep',
    'SastRuleBundleCanaryEligibilityDecision',
    'SastRuleBundleCanaryMembership',
    'SastRuleBundleCanaryAssignmentReceipt',
    'SastRuleBundleCanaryScanObservation',
    'SastRuleBundleCanaryStepDecision',
    'SastRuleBundleCanaryStepDecisionReason',
    'SastRuleBundleCanaryStepDecisionObservation',
    'SastRuleBundleCanaryRolloutHead',
    'SastRuleBundleCanaryObservationReceipt',
    'SastRuleBundleCanaryReceiptPassedStep'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(migration, new RegExp(`CREATE TABLE "${model}"`));
  }
  assert.match(migration, /SastRuleBundleCanaryRollout_candidate_profile_key/);
  assert.match(migration, /derive_sast_rule_bundle_canary_bucket/);
  assert.match(migration, /SastQueueReservation_canary_head/);
  assert.match(migration, /T048 canonical scan-key v4 cutover/);
  assert.match(migration, /coverage_failed := NEW\."candidateIncompleteCoverageCount" <> 0/);
  assert.match(
    migration,
    /FROM public\."SastRuleBundleCanaryScanObservation" o\s+WHERE o\."rolloutId" = NEW\."rolloutId"/
  );
  assert.doesNotMatch(migration, /ON DELETE CASCADE/);
  assert.doesNotMatch(migration, /"[A-Za-z0-9_]+"\s+JSONB\s+(?:NOT\s+)?NULL/i);

  assert.match(tasks, /- \[x\] T048\b/);
  assertT049QuickstartHandoff(quickstart);
  assertT049PlanHandoff(plan);
  assert.match(contract, /Deterministic canary cohort and observation gate v1/);
  assert.match(dataModel, /### SastRuleBundleCanaryRollout and SastRuleBundleCanaryRolloutStep/);
  assert.match(spec, /FR-056d/);
  assert.match(ruleGovernance, /T048 Deterministic Canary and Observation Boundary/);
  assert.match(threatModel, /Canary telemetry poisoning or omission/);
  assert.match(qualityGates, /100% T048 step-gate invariant/);
  assert.match(qualityGates, /caller cannot choose the cutoff or select\/omit observation/);
});

test('SAST T049 propagates signed kill switches through every production authority boundary', () => {
  const shared = readNormalizedText(files.sharedSastKillSwitch);
  const sharedTest = readNormalizedText(files.sharedSastKillSwitchTest);
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiSastKillSwitchService);
  const store = readNormalizedText(files.apiSastKillSwitchStore);
  const persistence = readNormalizedText(files.apiSastKillSwitchPersistence);
  const gate = readNormalizedText(files.apiSastKillSwitchGate);
  const signatureAuthority = readNormalizedText(
    files.apiSastKillSwitchSignatureAuthority
  );
  const canarySuspension = readNormalizedText(
    files.apiSastKillSwitchCanarySuspension
  );
  const serviceTest = readNormalizedText(files.apiSastKillSwitchServiceTest);
  const persistenceTest = readNormalizedText(
    files.apiSastKillSwitchPersistenceTest
  );
  const queueFenceTest = readNormalizedText(
    files.apiSastQueueKillSwitchFenceTest
  );
  const artifactGate = readNormalizedText(files.apiSastKillSwitchArtifactGate);
  const coverageGate = readNormalizedText(files.apiSastKillSwitchCoverageGate);
  const acceptanceAuthority = readNormalizedText(
    files.apiSastArtifactAcceptanceGate
  );
  const retryAuthority = readNormalizedText(
    files.apiSastKillSwitchRetryAuthority
  );
  const adapterTest = readNormalizedText(files.apiSastKillSwitchAdapterTest);
  const planner = readNormalizedText(files.apiSastPlanner);
  const queueStore = readNormalizedText(files.apiPrismaSastQueueAdmissionStore);
  const scannerRuntime = readNormalizedText(files.apiSastScannerRuntime);
  const aiService = readNormalizedText(files.apiAiAdvisoryService);
  const controlPlaneService = readNormalizedText(files.apiControlPlaneService);
  const ruleModule = readNormalizedText(files.apiRuleGovernanceModule);
  const scanModule = readNormalizedText(files.apiScanPlaneModule);
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(files.apiSastKillSwitchMigration);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const spec = readNormalizedText(files.spec);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  for (const version of [
    'sast-kill-switch-context-v1',
    'sast-kill-switch-decision-v1',
    'sast-kill-switch-verification-v1',
    'sast-kill-switch-evaluation-v1',
    'sast-kill-switch-planning-v1',
    'sast-kill-switch-emergency-suspension-v1',
    'sast-kill-switch-canary-suspension-signal-v1'
  ]) {
    assert.match(shared, new RegExp(version));
  }
  for (const scope of [
    "scope: 'GLOBAL'",
    "scope: 'SCANNER_VERSION'",
    "scope: 'RULE_BUNDLE'",
    "scope: 'SEMANTIC_RULE'",
    "scope: 'PROFILE'",
    "scope: 'TENANT'",
    "scope: 'REPOSITORY_BINDING'",
    "scope: 'CAPABILITY'",
    "scope: 'EXTERNAL_PUBLICATION'"
  ]) {
    assert.match(shared, new RegExp(scope));
  }
  for (const runtimeGate of [
    'PLANNING',
    'QUEUE_ADMISSION',
    'SCANNER_START',
    'ARTIFACT_ACCEPTANCE',
    'RETRY_ADMISSION',
    'COVERAGE',
    'EXTERNAL_PUBLICATION',
    'AI_ADVISORY'
  ]) {
    assert.match(shared, new RegExp(runtimeGate));
  }
  assert.match(shared, /buildApplicableSastKillSwitchSelectors/);
  assert.match(shared, /coverageEffect/);
  assert.match(sharedTest, /all runtime selectors/);
  assert.match(sharedTest, /content-free emergency suspension receipt/);
  assert.match(sharedIndex, /sast-kill-switch/);

  assert.match(service, /class SastKillSwitchService extends SastKillSwitchGate/);
  assert.match(service, /evaluatePersistedScan/);
  assert.match(service, /authorizeEmergencySuspension/);
  assert.match(service, /MAX_BOUNDARY_CLOCK_SKEW_MILLISECONDS/);
  assert.match(service, /assertTrustedBoundaryTime/);
  assert.match(persistence, /Prisma\.TransactionIsolationLevel\.Serializable/);
  assert.match(persistence, /SAST_KILL_SWITCH_SERIALIZABLE_RETRIES = 3/);
  assert.match(store, /buildApplicableSastKillSwitchSelectors/);
  assert.match(store, /FOR UPDATE/);
  assert.match(gate, /UnavailableSastKillSwitchGate/);
  assert.match(gate, /AUTHORITY_UNAVAILABLE/);
  assert.match(signatureAuthority, /UnavailableSastKillSwitchSignatureAuthority/);
  assert.match(canarySuspension, /decision\.outcome !== 'PAUSED'/);
  assert.match(serviceTest, /production signature authority is unavailable/);
  assert.match(serviceTest, /only from the locked T048 ledger/);
  assert.match(persistenceTest, /append-only ledgers/);
  assert.match(persistenceTest, /planning, runtime, artifact, retry, publication, AI/);
  assert.match(queueFenceTest, /omits one applicable selector/);
  assert.match(queueFenceTest, /context digest is not derived from the plan/);

  const canaryGate = planner.indexOf('ruleBundleCanaryGate.verifyScannerSet');
  const planningKillSwitch = planner.indexOf('killSwitchGate.evaluateContext');
  const policyGate = planner.indexOf('tenantRulePolicyGate.resolve');
  assert.ok(canaryGate >= 0);
  assert.ok(planningKillSwitch > canaryGate);
  assert.ok(policyGate > planningKillSwitch);
  assert.match(queueStore, /assertCurrentSastKillSwitchEvaluation/);
  assert.match(queueStore, /buildApplicableSastKillSwitchSelectors/);
  assert.match(queueStore, /FOR UPDATE OF head/);

  const scannerKillSwitch = scannerRuntime.indexOf(
    'this.killSwitch.evaluatePlan'
  );
  const scannerProvider = scannerRuntime.indexOf(
    'this.provider.readRepositoryManifest'
  );
  assert.ok(scannerKillSwitch >= 0);
  assert.ok(scannerProvider > scannerKillSwitch);
  assert.match(artifactGate, /SastArtifactAcceptanceAuthority/);
  assert.match(artifactGate, /return await this\.acceptanceAuthority\.evaluate\(input\)/);
  assert.match(acceptanceAuthority, /abstract class SastArtifactAcceptanceAuthority/);
  assert.match(retryAuthority, /gate: 'RETRY_ADMISSION'/);
  assert.match(coverageGate, /gate: 'COVERAGE'/);
  assert.match(coverageGate, /coverageAuthority\.verify\(decision\)/);
  assert.match(controlPlaneService, /gate: 'EXTERNAL_PUBLICATION'/);
  assert.match(
    controlPlaneService,
    /assertExternalPublicationKillSwitchClear/
  );
  assert.match(aiService, /gate: 'AI_ADVISORY'/);
  assert.match(adapterTest, /independent production acceptance denial/);
  assert.match(ruleModule, /provide: SastKillSwitchGate/);
  assert.match(scanModule, /SastKillSwitchArtifactAcceptanceGate/);
  assert.match(scanModule, /SastKillSwitchRetryRuntimeAuthority/);
  assert.match(scanModule, /SastKillSwitchFindingLifecycleCoverageGate/);

  for (const model of [
    'SastKillSwitchDecision',
    'SastKillSwitchVerification',
    'SastKillSwitchHead',
    'SastKillSwitchEvaluation',
    'SastKillSwitchEvaluationHead',
    'SastKillSwitchEvaluationMatch',
    'SastKillSwitchEmergencySuspensionReceipt'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(migration, new RegExp(`CREATE TABLE "${model}"`));
  }
  assert.match(migration, /reject_sast_kill_switch_ledger_mutation/);
  assert.match(migration, /SastQueueReservation_zz_kill_switch_head/);
  assert.match(migration, /enforce_sast_kill_switch_evaluation_complete/);
  assert.doesNotMatch(migration, /ON DELETE CASCADE/);
  assert.doesNotMatch(migration, /"[A-Za-z0-9_]+"\s+JSONB\b/i);

  assert.match(tasks, /- \[x\] T049\b/);
  assertT049QuickstartHandoff(quickstart);
  assertT049PlanHandoff(plan);
  assert.match(contract, /Signed SAST kill-switch authority v1/);
  assert.match(dataModel, /### SastKillSwitchDecision/);
  assert.match(spec, /FR-057/);
  assert.match(
    ruleGovernance,
    /T049 Signed Kill-Switch and Emergency-Suspension Boundary/
  );
  assert.match(
    threatModel,
    /First-activation, selector omission, and plan\/admission race/
  );
  assert.match(qualityGates, /T049 is release-blocking/);
});

test('SAST T050 derives and commits only last-known-good rollback authority', () => {
  const shared = readNormalizedText(files.sharedSastRuleBundleRollback);
  const sharedTest = readNormalizedText(files.sharedSastRuleBundleRollbackTest);
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const service = readNormalizedText(files.apiSastRuleBundleRollbackService);
  const store = readNormalizedText(files.apiSastRuleBundleRollbackStore);
  const signatureAuthority = readNormalizedText(
    files.apiSastRuleBundleRollbackSignatureAuthority
  );
  const clock = readNormalizedText(files.apiSastRuleBundleRollbackClock);
  const serviceTest = readNormalizedText(
    files.apiSastRuleBundleRollbackServiceTest
  );
  const persistenceTest = readNormalizedText(
    files.apiSastRuleBundleRollbackPersistenceTest
  );
  const postgresTest = readNormalizedText(
    files.apiSastRuleBundleRollbackPostgresTest
  );
  const lifecycleAuthority = readNormalizedText(
    files.apiRuleBundleLifecycleAuthority
  );
  const authorityRouter = readNormalizedText(
    files.apiRuleBundleLifecycleAuthorityRouter
  );
  const module = readNormalizedText(files.apiRuleGovernanceModule);
  const schema = readNormalizedText(files.apiPrismaSchema);
  const migration = readNormalizedText(files.apiSastRuleBundleRollbackMigration);
  const ci = readNormalizedText(files.ci);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const spec = readNormalizedText(files.spec);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  for (const version of [
    'sast-rule-bundle-rollback-request-v1',
    'sast-rule-bundle-rollback-command-v1',
    'sast-rule-bundle-rollback-verification-v1',
    'sast-rule-bundle-rollback-approval-v1',
    'sast-rule-bundle-rollback-receipt-v1'
  ]) {
    assert.match(shared, new RegExp(version));
  }
  const requestContract = shared.match(
    /export interface SastRuleBundleRollbackRequest \{[\s\S]*?\n\}/
  )?.[0];
  assert.ok(requestContract);
  assert.match(requestContract, /suspendedTransitionId/);
  assert.doesNotMatch(requestContract, /baseline|target/i);
  assert.match(shared, /maximumCommandAgeMilliseconds: 15 \* 60 \* 1_000/);
  assert.match(shared, /baselineMutationAuthorized: false/);
  assert.match(shared, /historicalMutationAuthorized: false/);
  assert.match(shared, /scannerSetMutationAuthorized: false/);
  assert.match(sharedTest, /never a caller-selected target/);
  assert.match(sharedTest, /fresh independent Security Engineering/);
  assert.match(sharedIndex, /sast-rule-bundle-rollback/);

  assert.doesNotMatch(service, /request\.baselineManifestId/);
  assert.match(service, /evidence\.baselineManifestId/);
  assert.match(service, /candidateSuspensionMatchesRequest/);
  assert.match(service, /input\.authority !== 'ROLLBACK'/);
  assert.match(service, /input\.fromState !== 'SUSPENDED'/);
  assert.match(service, /input\.toState !== 'ROLLED_BACK'/);
  assert.match(store, /runSastKillSwitchSerializable/);
  assert.match(store, /ORDER BY "manifestId" COLLATE "C"/);
  assert.match(store, /FOR UPDATE/);
  assert.match(signatureAuthority, /UnavailableSastRuleBundleRollbackSignatureAuthority/);
  assert.match(clock, /SystemSastRuleBundleRollbackClock/);
  assert.match(serviceTest, /signature authority is not installed/);
  assert.match(serviceTest, /active baseline changes before authorization/);
  assert.match(persistenceTest, /locks both heads canonically/);
  assert.match(persistenceTest, /only the ROLLBACK lifecycle seam/);
  assert.match(postgresTest, /RUN_SAST_ROLLBACK_POSTGRES_PROBE/);
  assert.match(postgresTest, /rejects forged, stale, duplicate, and mutable authority/);
  assert.match(postgresTest, /Promise\.all/);

  assert.match(lifecycleAuthority, /RequiredSastRuleBundleLifecycleExternalAuthority/);
  assert.match(authorityRouter, /input\.authority === 'ROLLBACK'/);
  assert.match(module, /SastRuleBundleRollbackService/);
  assert.match(module, /UnavailableSastRuleBundleRollbackSignatureAuthority/);
  for (const model of [
    'SastRuleBundleRollbackCommand',
    'SastRuleBundleRollbackVerification',
    'SastRuleBundleRollbackApproval',
    'SastRuleBundleRollbackReceipt',
    'SastRuleBundleRollbackReceiptApproval'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(migration, new RegExp(`CREATE TABLE "${model}"`));
  }
  assert.match(migration, /reject_sast_rule_bundle_rollback_ledger_mutation/);
  assert.match(migration, /enforce_sast_rule_bundle_rollback_command_state/);
  assert.match(migration, /enforce_sast_rule_bundle_rollback_receipt_state/);
  assert.match(migration, /enforce_sast_rule_bundle_rollback_lifecycle_authority/);
  assert.match(migration, /ORDER BY "manifestId" COLLATE "C" FOR UPDATE/);
  assert.doesNotMatch(migration, /ON DELETE CASCADE/);
  assert.doesNotMatch(migration, /"[A-Za-z0-9_]+"\s+JSONB\b/i);
  assert.match(ci, /Probe SAST rollback authority on PostgreSQL/);
  assert.match(ci, /RUN_SAST_ROLLBACK_POSTGRES_PROBE: "1"/);

  assert.match(tasks, /- \[x\] T050\b/);
  assertT049QuickstartHandoff(quickstart);
  assertT049PlanHandoff(plan);
  assert.match(contract, /Last-known-good rollback authority v1/);
  assert.match(dataModel, /SastRuleBundleRollbackCommand and SastRuleBundleRollbackVerification/);
  assert.match(spec, /FR-057g/);
  assert.match(spec, /FR-057h/);
  assert.match(ruleGovernance, /T050 Last-Known-Good Rollback Boundary/);
  assert.match(threatModel, /Rollback target substitution or race/);
  assert.match(qualityGates, /T050 is release-blocking/);
});

test('SAST T051 pins versioned golden and prior must-detect qualification corpora', () => {
  const shared = readNormalizedText(files.sharedSastQualificationCorpus);
  const sharedTest = readNormalizedText(files.sharedSastQualificationCorpusTest);
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const generator = readNormalizedText(files.qualificationGenerator);
  const loader = readNormalizedText(files.qualificationLoader);
  const loaderTest = readNormalizedText(files.qualificationLoaderTest);
  const corpusReadme = readNormalizedText(files.qualificationReadme);
  const gitattributes = readNormalizedText(files.gitattributes);
  const rootPackage = readNormalizedText(files.rootPackage);
  const ci = readNormalizedText(files.ci);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const spec = readNormalizedText(files.spec);
  const research = readNormalizedText(files.research);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);
  const snapshot = JSON.parse(readFileSync(files.qualificationSnapshot, 'utf8'));
  const priorReleaseManifest = JSON.parse(
    readFileSync(files.qualificationPriorReleaseManifest, 'utf8')
  );

  assert.match(shared, /sast-qualification-corpus-case-v1/);
  assert.match(shared, /sast-qualification-corpus-snapshot-v1/);
  assert.match(shared, /sast-qualification-prior-release-manifest-v1/);
  assert.match(shared, /minimumPositiveCasesPerProfile: 200/);
  assert.match(shared, /minimumNegativeCasesPerProfile: 200/);
  assert.match(shared, /minimumCriticalHighCasesPerRule: 20/);
  assert.match(shared, /!unique\(cases\.map\(\(item\) => item\.scanPath\)\)/);
  assert.match(sharedIndex, /sast-qualification-corpus/);
  assert.match(sharedTest, /immutable 800-case golden corpus/);
  assert.match(sharedTest, /colliding scan paths/);
  assert.match(sharedTest, /exact prior-release set/);

  assert.match(generator, /createGoldenCorpusAssets/);
  assert.match(generator, /refusing to overwrite immutable prior-release/);
  assert.match(generator, /GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_DIGEST/);
  assert.match(generator, /GOLDEN_CORPUS_REVISION = '1\.0\.0'/);
  assert.match(loader, /SNAPSHOT_DRIFT/);
  assert.match(loader, /SOURCE_PATH_INVALID/);
  assert.match(loader, /decodeCanonicalText/);
  assert.match(loader, /EXPECTED_ROOT_ENTRIES/);
  assert.match(loader, /O_NOFOLLOW/);
  assert.match(generator, /writeStableRegularFile/);
  assert.match(generator, /O_NOFOLLOW/);
  assert.match(loaderTest, /rejects symlink or junction traversal/);
  assert.match(loaderTest, /rejects source drift, BOM, and CRLF ambiguity/);
  assert.match(loaderTest, /rejects unexpected corpus-root entries/);
  assert.match(corpusReadme, /platform-owned input snapshot/);
  assert.match(gitattributes, /qualification\/corpora\/v1\/\*\* text eol=lf/);

  assert.equal(snapshot.caseCount, 800);
  assert.equal(snapshot.positiveCaseCount, 400);
  assert.equal(snapshot.negativeCaseCount, 400);
  assert.equal(snapshot.priorMustDetectCaseCount, 400);
  assert.equal(priorReleaseManifest.caseCount, 400);
  assert.equal(snapshot.priorReleaseRef, priorReleaseManifest.releaseRef);
  assert.equal(
    snapshot.priorReleaseManifestDigest,
    priorReleaseManifest.manifestDigest
  );
  assert.equal(
    snapshot.priorMustDetectSetDigest,
    priorReleaseManifest.caseSetDigest
  );
  assert.equal(snapshot.ruleCounts.length, 20);
  assert.equal(new Set(snapshot.cases.map((item) => item.scanPath)).size, 800);
  assert.equal(new Set(snapshot.cases.map((item) => item.sourcePath)).size, 40);
  assert.ok(
    snapshot.profileCounts.every(
      (count) => count.positiveCases >= 200 && count.negativeCases >= 200
    )
  );
  assert.ok(
    snapshot.ruleCounts.every(
      (count) =>
        count.positiveCases === 20 &&
        count.negativeCases === 20 &&
        count.priorMustDetectCases === 20
    )
  );
  assert.ok(
    snapshot.cases.every(
      (item) =>
        item.sourcePlatformOwned === true &&
        item.customerContentAccepted === false &&
        item.executable === false &&
        item.packageInstallRequired === false &&
        item.buildRequired === false &&
        item.dynamicExecutionRequired === false &&
        item.networkRequired === false &&
        item.immutable === true
    )
  );

  assert.match(rootPackage, /"qualification:validate"/);
  assert.match(ci, /Validate T051-T054 qualification packages/);
  assert.match(ci, /corepack pnpm qualification:validate/);
  assert.match(tasks, /- \[x\] T051\b/);
  assert.match(quickstart, /T051\s+versioned golden qualification corpus is complete/);
  assert.match(quickstart, /T052 multi-class qualification corpus is complete/);
  assert.match(quickstart, /T053's\s+repository provider-handoff implementation is complete/);
  assert.match(plan, /T051 immutable golden corpus is complete/);
  assert.match(contract, /Versioned golden qualification corpus v1/);
  assert.match(dataModel, /SastQualificationCorpusSnapshot/);
  assert.match(spec, /FR-057i/);
  assert.match(research, /Decision 29: Pin Golden Qualification Inputs/);
  assert.match(ruleGovernance, /T051 Golden Qualification Corpus Boundary/);
  assert.match(threatModel, /Qualification corpus substitution or path escape/);
  assert.match(qualityGates, /T051 is release-blocking/);
});

test('SAST T052 pins all multi-class qualification inputs without executing them', () => {
  const shared = readNormalizedText(files.sharedSastMultiClassQualificationCorpus);
  const sharedTest = readNormalizedText(
    files.sharedSastMultiClassQualificationCorpusTest
  );
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const generator = readNormalizedText(files.multiClassQualificationGenerator);
  const loader = readNormalizedText(files.multiClassQualificationLoader);
  const loaderTest = readNormalizedText(files.multiClassQualificationLoaderTest);
  const corpusReadme = readNormalizedText(files.multiClassQualificationReadme);
  const snapshot = JSON.parse(
    readFileSync(files.multiClassQualificationSnapshot, 'utf8')
  );
  const gitattributes = readNormalizedText(files.gitattributes);
  const rootPackage = readNormalizedText(files.rootPackage);
  const ci = readNormalizedText(files.ci);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const spec = readNormalizedText(files.spec);
  const research = readNormalizedText(files.research);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(shared, /sast-multi-class-qualification-fixture-v1/);
  assert.match(shared, /sast-multi-class-qualification-case-v1/);
  assert.match(shared, /sast-multi-class-qualification-snapshot-v1/);
  assert.match(shared, /expectedCaseCount: 84/);
  assert.match(shared, /minimumPerformanceRunsPerBucket: 30/);
  assert.match(shared, /FORBIDDEN_RECIPE_PARAMETER_NAMES/);
  assert.match(sharedIndex, /sast-multi-class-qualification-corpus/);
  assert.match(sharedTest, /immutable 84-case five-class qualification corpus/);
  assert.match(sharedTest, /rejects executable recipe fields/);
  assert.match(sharedTest, /hostile cyclic and over-depth snapshots/);

  assert.match(generator, /createMultiClassCorpusAssets/);
  assert.match(generator, /refusing to overwrite existing T052 corpus root/);
  assert.match(generator, /writeStableRegularFile/);
  assert.match(generator, /O_NOFOLLOW/);
  assert.match(loader, /EXPECTED_ROOT_ENTRIES/);
  assert.match(loader, /assertExactFixtureTree/);
  assert.match(loader, /sameStableIdentity/);
  assert.match(loader, /ignoreBOM: true/);
  assert.match(loader, /O_NOFOLLOW/);
  assert.match(
    loaderTest,
    /rejects invalid encoding, CRLF, BOM, NUL, non-NFC, missing final LF, and oversize/
  );
  assert.match(loaderTest, /remain declarative and never contain executable fields/);
  assert.match(corpusReadme, /authenticates inputs only/);
  assert.match(gitattributes, /qualification\/corpora\/t052-v1\/\*\* text eol=lf/);

  assert.equal(snapshot.caseCount, 84);
  assert.equal(snapshot.fixtureCount, 84);
  assert.deepEqual(
    Object.fromEntries(
      snapshot.classCounts.map((item) => [item.corpusClass, item.cases])
    ),
    {
      SCHEMA_PARSER: 16,
      MALICIOUS_REPOSITORY: 25,
      FINGERPRINT_CORRELATION: 17,
      EVIDENCE_PRIVACY: 17,
      PERFORMANCE: 9
    }
  );
  assert.ok(snapshot.scenarioCounts.every((item) => item.cases === 1));
  assert.ok(snapshot.profileCounts.every((item) => item.performanceBuckets === 3));
  assert.ok(
    snapshot.cases.every(
      (item) =>
        item.minimumRuns === (item.corpusClass === 'PERFORMANCE' ? 30 : 1) &&
        item.customerContentAccepted === false &&
        item.scannerExecutionAuthorized === false &&
        item.findingAuthority === false &&
        item.policyAuthority === false &&
        item.publicationAuthority === false &&
        item.productionReadinessAuthority === false &&
        item.packageInstallRequired === false &&
        item.buildRequired === false &&
        item.dynamicExecutionRequired === false &&
        item.networkRequired === false
    )
  );

  assert.match(rootPackage, /validate-golden-corpus\.mjs/);
  assert.match(rootPackage, /validate-multi-class-corpus\.mjs/);
  assert.match(ci, /Validate T051-T054 qualification packages/);
  assert.match(tasks, /- \[x\] T052\b/);
  assert.match(tasks, /- \[ \] T053\b/);
  assert.match(quickstart, /T052 multi-class qualification corpus is complete/);
  assert.match(plan, /T052 multi-class qualification corpus is complete/);
  assert.match(contract, /Multi-class qualification corpus v1/);
  assert.match(dataModel, /SastMultiClassQualificationSnapshot/);
  assert.match(spec, /FR-057j/);
  assert.match(research, /Decision 30: Pin Multi-Class Qualification Inputs/);
  assert.match(ruleGovernance, /T052 Multi-Class Qualification Corpus Boundary/);
  assert.match(threatModel, /Multi-class qualification recipe substitution/);
  assert.match(qualityGates, /T052 is release-blocking/);
});

test('SAST T053 packages an exact fail-closed provider handoff without fabricating evidence', () => {
  const shared = readNormalizedText(files.sharedSastIsolatedQualification);
  const sharedTest = readNormalizedText(files.sharedSastIsolatedQualificationTest);
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const generator = readNormalizedText(files.isolatedQualificationGenerator);
  const loader = readNormalizedText(files.isolatedQualificationLoader);
  const validator = readNormalizedText(files.isolatedQualificationValidator);
  const planTool = readNormalizedText(files.isolatedQualificationPlanTool);
  const evidenceTool = readNormalizedText(files.isolatedQualificationEvidenceTool);
  const loaderTest = readNormalizedText(files.isolatedQualificationLoaderTest);
  const toolsTest = readNormalizedText(files.isolatedQualificationToolsTest);
  const readme = readNormalizedText(files.isolatedQualificationReadme);
  const manifest = JSON.parse(readFileSync(files.isolatedQualificationManifest, 'utf8'));
  const policy = JSON.parse(readFileSync(files.isolatedQualificationPolicy, 'utf8'));
  const rootPackage = readNormalizedText(files.rootPackage);
  const ci = readNormalizedText(files.ci);
  const gitattributes = readNormalizedText(files.gitattributes);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const spec = readNormalizedText(files.spec);
  const research = readNormalizedText(files.research);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(shared, /sast-isolated-integration-qualification-manifest-v1/);
  assert.match(shared, /sast-isolated-integration-qualification-receipt-v1/);
  assert.match(shared, /expectedCellCount: 123/);
  assert.match(shared, /cleanupSloSeconds: 60/);
  assert.match(shared, /PENDING_PROVIDER_EXECUTION/);
  assert.match(shared, /DETACHED_DUAL_APPROVAL_REQUIRED/);
  assert.match(shared, /trustedEvaluatedAt/);
  assert.match(sharedIndex, /sast-isolated-integration-qualification/);
  assert.match(sharedTest, /passes only an exact 123-cell dual-signed provider receipt set/);
  assert.match(sharedTest, /keeps a valid partial provider run pending/);
  assert.match(sharedTest, /detached approvals strictly before execution starts/);
  assert.match(sharedTest, /stale replay against the trusted evaluation instant/);
  assert.match(sharedTest, /duplicate cells and sandbox or attestation reuse/);

  assert.equal(manifest.sourceCorpusRevision, '1.0.2');
  assert.equal(manifest.caseCount, 41);
  assert.equal(manifest.executionCellCount, 123);
  assert.equal(manifest.cells.length, 123);
  assert.equal(new Set(manifest.cells.map((item) => item.cellId)).size, 123);
  assert.equal(new Set(manifest.cells.map((item) => item.cellKey)).size, 123);
  assert.equal(manifest.providerExecutionStatus, 'PENDING_PROVIDER_EXECUTION');
  assert.equal(manifest.liveProviderEvidencePresent, false);
  assert.equal(manifest.productionReadinessAuthority, false);
  assert.ok(
    manifest.cells.every(
      (item) =>
        item.freshMicroVmRequired === true &&
        item.sandboxReuseAllowed === false &&
        item.scenarioNameBranchingAllowed === false &&
        item.customerContentAccepted === false &&
        item.customerCodeExecutionAllowed === false &&
        item.packageInstallAllowed === false &&
        item.repositoryBuildAllowed === false &&
        item.dynamicTestAllowed === false &&
        item.publicInternetEgressAllowed === false &&
        item.productionReadinessAuthority === false
    )
  );

  assert.equal(policy.version, 'sast-isolated-integration-materialization-policy-v1');
  assert.equal(policy.allowedActions.length, 9);
  assert.equal(policy.localExecutionAllowed, false);
  assert.equal(policy.guestMicroVmMaterializationRequired, true);
  assert.equal(policy.oneFreshMicroVmPerCell, true);
  assert.equal(policy.productionReadinessAuthority, false);

  assert.match(generator, /createIsolatedIntegrationAssets/);
  assert.match(generator, /refusing to overwrite existing T053 qualification root/);
  assert.match(loader, /EXPECTED_ROOT_ENTRIES/);
  assert.match(loader, /before\.isSymbolicLink/);
  assert.match(validator, /PENDING_PROVIDER_EXECUTION/);
  assert.match(planTool, /buildSastIsolatedQualificationExecutionPlan/);
  assert.match(evidenceTool, /verifySignatureBytes/);
  assert.match(evidenceTool, /TRUST_POLICY/);
  assert.match(evidenceTool, /new Date\(\)\.toISOString\(\)/);
  assert.doesNotMatch(evidenceTool, /'--evaluated-at'/);
  assert.match(evidenceTool, /result\.status === 'PASSED'/);
  assert.match(loaderTest, /rejects missing, extra, noncanonical, and linked entries/);
  assert.match(toolsTest, /real Ed25519 approvals and 123 receipts/);
  assert.match(toolsTest, /reject signature tampering/);
  assert.match(readme, /PENDING_PROVIDER_EXECUTION/);

  assert.match(rootPackage, /validate-isolated-integration\.mjs/);
  assert.match(ci, /Validate T051-T054 qualification packages/);
  assert.match(gitattributes, /qualification\/t053-v1\/\*\* text eol=lf/);
  assert.match(tasks, /- \[ \] T053\b/);
  assert.match(tasks, /Repository-side exact 123-cell manifest/);
  assert.match(quickstart, /T053 repository-side 123-cell provider handoff/);
  assert.match(plan, /T053 repository-side provider handoff is package-ready/);
  assert.match(contract, /Isolated integration qualification v1/);
  assert.match(dataModel, /SastIsolatedQualificationReceipt and Result/);
  assert.match(spec, /FR-057k/);
  assert.match(research, /Decision 31: Separate the T053 Provider Handoff/);
  assert.match(ruleGovernance, /T053 Isolated Integration Qualification Boundary/);
  assert.match(threatModel, /Isolated qualification evidence forgery or reuse/);
  assert.match(threatModel, /Isolated qualification clock or retroactive-approval replay/);
  assert.match(qualityGates, /T053 Production-Equivalent Isolated Integration Gates/);
});

test('SAST T054 packages exact end-to-end gates without fabricating external evidence', () => {
  const shared = readNormalizedText(files.sharedSastEndToEndQualification);
  const sharedTest = readNormalizedText(files.sharedSastEndToEndQualificationTest);
  const sharedIndex = readNormalizedText(files.sharedIndex);
  const generator = readNormalizedText(files.endToEndQualificationGenerator);
  const loader = readNormalizedText(files.endToEndQualificationLoader);
  const validator = readNormalizedText(files.endToEndQualificationValidator);
  const planTool = readNormalizedText(files.endToEndQualificationPlanTool);
  const evidenceTool = readNormalizedText(files.endToEndQualificationEvidenceTool);
  const trustTool = readNormalizedText(files.endToEndQualificationTrustTool);
  const loaderTest = readNormalizedText(files.endToEndQualificationLoaderTest);
  const toolsTest = readNormalizedText(files.endToEndQualificationToolsTest);
  const readme = readNormalizedText(files.endToEndQualificationReadme);
  const manifest = JSON.parse(readFileSync(files.endToEndQualificationManifest, 'utf8'));
  const policy = JSON.parse(readFileSync(files.endToEndQualificationPolicy, 'utf8'));
  const rootPackage = readNormalizedText(files.rootPackage);
  const ci = readNormalizedText(files.ci);
  const gitattributes = readNormalizedText(files.gitattributes);
  const tasks = readNormalizedText(files.tasks);
  const quickstart = readNormalizedText(files.quickstart);
  const plan = readNormalizedText(files.plan);
  const contract = readNormalizedText(files.contract);
  const dataModel = readNormalizedText(files.dataModel);
  const spec = readNormalizedText(files.spec);
  const research = readNormalizedText(files.research);
  const ruleGovernance = readNormalizedText(files.ruleGovernance);
  const threatModel = readNormalizedText(files.threatModel);
  const qualityGates = readNormalizedText(files.qualityGates);

  assert.match(shared, /sast-end-to-end-qualification-manifest-v1/);
  assert.match(shared, /sast-end-to-end-qualification-receipt-v1/);
  assert.match(shared, /sast-end-to-end-qualification-artifact-verification-set-v1/);
  assert.match(shared, /sast-end-to-end-qualification-artifact-provenance-v1/);
  assert.match(shared, /verification\.artifactSignature/);
  assert.match(shared, /verification\.provenance/);
  assert.match(shared, /SUPPLY_CHAIN_AUTHORITY/);
  assert.match(shared, /t053ProviderAdapterRef/);
  assert.match(shared, /expectedCellCount: 3_462/);
  assert.match(shared, /BLOCKED_T053_QUALIFICATION/);
  assert.match(shared, /aggregateMetricsAcceptedFromCaller: false/);
  assert.match(shared, /SCANNER_FAILURE_RATE_EXCEEDED/);
  assert.match(sharedIndex, /sast-end-to-end-qualification/);
  assert.match(sharedTest, /exact 3,462-cell denominator/);
  assert.match(sharedTest, /recomputes every gate from all signed receipts/);
  assert.match(sharedTest, /keeps infrastructure retries in reliability metrics/);
  assert.match(sharedTest, /duplicate global identities and retroactive approvals/);
  assert.match(sharedTest, /untrusted artifact attestations and T053 provider transfer/);

  assert.equal(manifest.executionCellCount, 3462);
  assert.equal(manifest.goldenCandidateCellCount, 1880);
  assert.equal(manifest.goldenNegativeBaselineCellCount, 940);
  assert.equal(manifest.endToEndCandidateCellCount, 102);
  assert.equal(manifest.performanceCellCount, 540);
  assert.equal(manifest.performanceBucketCount, 9);
  assert.equal(manifest.requiredPerformanceRunsPerArmBucket, 30);
  assert.equal(manifest.providerExecutionStatus, 'BLOCKED_T053_QUALIFICATION');
  assert.equal(manifest.productionReadinessAuthority, false);
  assert.equal(new Set(manifest.cells.map((item) => item.cellId)).size, 3462);
  assert.ok(
    manifest.cells.every(
      (item) =>
        item.queueToCleanupRequired === true &&
        item.externalPublicationAllowed === false &&
        item.customerContentAccepted === false &&
        item.customerCodeExecutionAllowed === false &&
        item.packageInstallAllowed === false &&
        item.repositoryBuildAllowed === false &&
        item.dynamicTestAllowed === false &&
        item.publicInternetEgressAllowed === false &&
        item.productionReadinessAuthority === false
    )
  );

  assert.equal(
    policy.version,
    'sast-end-to-end-qualification-measurement-policy-v1'
  );
  assert.equal(policy.denominators.totalExecutionCells, 3462);
  assert.equal(policy.denominators.performanceRunsPerArmBucket, 30);
  assert.equal(policy.execution.aggregateMetricsAcceptedFromCaller, false);
  assert.equal(policy.prerequisite.exactT053DependencySetRequired, true);
  assert.equal(policy.prerequisite.sameProviderAndAdapterRequired, true);
  assert.equal(policy.execution.signedArtifactVerificationSetRequired, true);
  assert.equal(policy.execution.artifactSignatureEnvelopePayloadRequired, true);
  assert.equal(policy.execution.artifactProvenanceEnvelopePayloadRequired, true);
  assert.equal(policy.execution.perArtifactEd25519VerificationRequired, true);
  assert.equal(policy.execution.artifactProvenanceSubjectBindingRequired, true);
  assert.equal(
    policy.execution.independentlyConfiguredTrustPolicyDigestRequired,
    true
  );
  assert.equal(policy.prohibited.localExecutionAllowed, false);
  assert.equal(policy.authority.productionReadinessAuthority, false);

  assert.match(generator, /createEndToEndQualificationAssets/);
  assert.match(generator, /refusing to overwrite existing T054 qualification root/);
  assert.match(generator, /createExclusiveFile/);
  assert.match(generator, /writeStableRegularFile/);
  assert.match(generator, /O_NOFOLLOW/);
  assert.match(loader, /EXPECTED_ROOT_ENTRIES/);
  assert.match(loader, /before\.isSymbolicLink/);
  assert.match(validator, /BLOCKED_T053_QUALIFICATION/);
  assert.match(planTool, /buildSastEndToEndQualificationExecutionPlan/);
  assert.match(planTool, /--t053-dependency-set/);
  assert.match(planTool, /--artifact-verification-set/);
  assert.match(evidenceTool, /new Date\(\)\.toISOString\(\)/);
  assert.doesNotMatch(evidenceTool, /'--evaluated-at'/);
  assert.match(trustTool, /verifySignatureBytes/);
  assert.match(trustTool, /TRUST_POLICY/);
  assert.match(trustTool, /SAST_T054_TRUST_POLICY_DIGEST/);
  assert.match(loaderTest, /rejects CRLF and linked package entries/);
  assert.match(toolsTest, /pinned trust root and verify all Ed25519 authorities/);
  assert.match(readme, /BLOCKED_T053_QUALIFICATION/);

  assert.match(rootPackage, /validate-end-to-end-qualification\.mjs/);
  assert.match(ci, /Validate T051-T054 qualification packages/);
  assert.match(gitattributes, /qualification\/t054-v1\/\*\* text eol=lf/);
  assert.match(tasks, /Repository-side exact 3,462-cell T054 manifest/);
  assert.match(tasks, /- \[ \] T054\b/);
  assert.match(quickstart, /T054 repository-side 3,462-cell qualification contract/);
  assert.match(plan, /T054 repository-side end-to-end qualification contract is package-ready/);
  assert.match(contract, /End-to-end qualification v1/);
  assert.match(dataModel, /SastEndToEndQualificationReceipt and Result/);
  assert.match(spec, /FR-057l/);
  assert.match(research, /Decision 32: Make T054 Receipt-Recomputed/);
  assert.match(ruleGovernance, /T054 End-to-End Qualification Boundary/);
  assert.match(threatModel, /End-to-end qualification aggregate forgery or retry erasure/);
  assert.match(threatModel, /T054 prerequisite or retroactive-approval replay/);
  assert.match(threatModel, /T054 self-selected trust root or unsigned artifact substitution/);
  assert.match(threatModel, /T054 provider qualification transfer/);
  assert.match(qualityGates, /T054 End-to-End Qualification Gates/);
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
    'corepack pnpm qualification:validate',
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
