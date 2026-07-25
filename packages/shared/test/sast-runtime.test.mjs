import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const contractFile = new URL('../src/types/sast-runtime.ts', import.meta.url);
const readContract = () => readFileSync(contractFile, 'utf8');

test('SAST runtime contracts assign one authoritative responsibility to each scanner family', () => {
  assert.equal(existsSync(contractFile), true);
  const contract = readContract();

  for (const exportName of [
    'PRODUCTION_SAST_RUNTIME_FEATURE_ID',
    'SAST_SCANNER_KINDS',
    'SAST_CAPABILITIES',
    'SAST_SCANNER_RESPONSIBILITIES',
    'SastScannerKind',
    'SastCapability'
  ]) {
    assert.match(contract, new RegExp(`export (interface|const|type|function) ${exportName}\\b`));
  }

  assert.match(contract, /OPENGREP:[\s\S]*authoritativeCapabilities:\s*\['SAST'\]/);
  assert.match(
    contract,
    /TRIVY:[\s\S]*'DEPENDENCY_VULNERABILITY'[\s\S]*'SECRET_DETECTION'[\s\S]*'IAC_MISCONFIGURATION'/
  );
  assert.match(contract, /SYFT:[\s\S]*authoritativeCapabilities:\s*\['SBOM'\]/);
  assert.match(contract, /SYFT:[\s\S]*mayCreateFindings:\s*false/);
});

test('SAST profiles define Java fast and deep behavior without customer execution', () => {
  const contract = readContract();

  for (const profileId of ['JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1']) {
    assert.match(contract, new RegExp(`\\b${profileId}\\b`));
  }

  assert.match(contract, /JAVA_FAST_V1:[\s\S]*scope:\s*'CHANGED_FILES_WITH_CONTEXT'/);
  assert.match(contract, /JAVA_DEEP_V1:[\s\S]*scope:\s*'FULL_REPOSITORY'/);
  assert.match(contract, /JAVA_DEEP_V1:[\s\S]*requiredScanners:\s*\['OPENGREP', 'TRIVY', 'SYFT'\]/);
  assert.match(contract, /customerBuildAllowed:\s*false/g);
  assert.match(contract, /packageInstallAllowed:\s*false/g);
  assert.match(contract, /dynamicExecutionAllowed:\s*false/g);
  assert.match(contract, /networkEnrichmentAllowed:\s*false/g);
});

test('SAST path and resource policies bound hostile repositories', () => {
  const contract = readContract();

  for (const requiredControl of [
    'rejectAbsolutePaths',
    'rejectParentTraversal',
    'rejectCaseFoldCollisions',
    'REJECT_OUTSIDE_ROOT',
    'DISABLED_BY_DEFAULT',
    'POINTER_METADATA_ONLY_BY_DEFAULT',
    'DO_NOT_EXPAND',
    'maxRepositoryBytes',
    'maxSelectedBytes',
    'maxFileCount',
    'maxSingleFileBytes',
    'maxPathDepth',
    'maxFindings',
    'maxArtifactBytes',
    'maxArtifactRecords',
    'maxStdoutStderrBytes',
    'fileDescriptorLimit',
    'wallClockTimeoutSeconds'
  ]) {
    assert.match(contract, new RegExp(`\\b${requiredControl}\\b`));
  }

  assert.match(contract, /JAVA_FAST_V1:[\s\S]*wallClockTimeoutSeconds:\s*900/);
  assert.match(contract, /JAVA_DEEP_V1:[\s\S]*wallClockTimeoutSeconds:\s*3600/);
});

test('scanner sets and scan plans bind every executable supply-chain artifact', () => {
  const contract = readContract();

  for (const contractName of [
    'SignedSastArtifactDescriptor',
    'ScannerRuntimeDescriptor',
    'VulnerabilityDatabaseDescriptor',
    'ScannerSetDescriptor',
    'ExpectedScannerArtifactBinding',
    'SastArtifactIngressReceipt',
    'SastFileCoordinateMetadata',
    'SAST_APPROVED_PROFILE_DIGESTS',
    'isSignedSastArtifactDescriptorValid',
    'isScannerSetDescriptorValid',
    'isSastScanPlanValid',
    'isScannerArtifactEnvelopeBoundToPlan',
    'isScannerArtifactEnvelopeShapeValid',
    'canonicalizeScannerArtifactEnvelope',
    'buildSastArtifactIngressIdempotencyKey',
    'isScannerArtifactEligibleForNormalization',
    'isSastFindingLocationValid'
  ]) {
    assert.match(contract, new RegExp(`export (interface|const|type|function) ${contractName}\\b`));
  }

  assert.match(contract, /scannerSetDigest:\s*`sha256:\$\{string\}`/);
  assert.match(contract, /wrapper:\s*SignedSastArtifactDescriptor/);
  assert.match(contract, /schemaBundle:\s*SignedSastArtifactDescriptor/);
  assert.match(contract, /normalizerBundle:\s*SignedSastArtifactDescriptor/);
  assert.match(contract, /profileDigest:\s*`sha256:\$\{string\}`/);
  assert.match(
    contract,
    /plan\.profileDigest\s*===\s*SAST_APPROVED_PROFILE_DIGESTS\[plan\.profile\.id\]/
  );
  assert.match(contract, /workloadIdentityRef:\s*string/);
  assert.match(contract, /envelope\.attemptId\s*===\s*expectedBinding\.attemptId/);
  assert.match(contract, /envelope\.scannerRunId\s*===\s*expectedBinding\.scannerRunId/);
  assert.match(
    contract,
    /envelope\.workloadIdentityRef\s*===\s*expectedBinding\.workloadIdentityRef/
  );
  assert.match(
    contract,
    /envelope\.scannerWorkspaceInventoryDigest\s*===\s*expectedBinding\.preflightInventoryDigest/
  );
});

test('rule bundles require immutable signed provenance and reversible rollout', () => {
  const contract = readContract();

  for (const field of [
    'digest',
    'signatureRef',
    'provenanceRef',
    'compatibilityRef',
    'rolloutPolicyRef',
    'killSwitchRef',
    'rollbackRef'
  ]) {
    assert.match(contract, new RegExp(`\\b${field}\\b`));
  }

  assert.match(contract, /source:\s*'PLATFORM_MANAGED'/);
  assert.match(contract, /immutable:\s*true/);
  assert.match(contract, /customerExecutableConfigAllowed:\s*false/);
  assert.match(contract, /isRuleBundlePromotionReady/);
  assert.match(contract, /signedArtifactVerified/);
  assert.match(contract, /provenanceVerified/);
});

test('scanner artifacts carry bounded provenance metadata instead of raw repository payloads', () => {
  const contract = readContract();

  for (const field of [
    'scannerImageDigest',
    'ruleBundleDigest',
    'vulnerabilityDatabaseDigest',
    'schemaBundleDigest',
    'normalizerBundleDigest',
    'inputCommitSha',
    'artifactSchemaVersion',
    'artifactRef',
    'contentDigest',
    'byteSize',
    'recordCount',
    'executionStatus'
  ]) {
    assert.match(contract, new RegExp(`\\b${field}\\b`));
  }

  for (const forbiddenField of [
    'credentialValue',
    'scmToken',
    'fullRepository',
    'sourceArchive',
    'rawScannerPayload'
  ]) {
    assert.doesNotMatch(contract, new RegExp(`\\b${forbiddenField}\\b`, 'i'));
  }
});

test('finding fingerprints exclude unstable line, branch, and commit coordinates', () => {
  const contract = readContract();
  const fingerprintFunction = contract.split('export function buildFindingFingerprintPreimage')[1]
    .split('export function evaluateSastCoverage')[0];

  for (const stableField of [
    'repositoryBindingId',
    'capability',
    'ruleSemanticId',
    'normalizedPath',
    'symbolAnchor',
    'sinkKind',
    'structuralHash'
  ]) {
    assert.match(fingerprintFunction, new RegExp(`input\\.${stableField}\\b`));
  }

  for (const unstableField of ['lineStart', 'lineEnd', 'commitSha', 'targetRef', 'branch']) {
    assert.doesNotMatch(fingerprintFunction, new RegExp(`input\\.${unstableField}\\b`));
  }
  assert.match(fingerprintFunction, /sast-fingerprint-v1\\0/);
  assert.match(contract, /function encodeFingerprintField/);
  assert.match(contract, /new TextEncoder\(\)\.encode\(normalized\)\.byteLength/);
});

test('coverage decisions suppress publication for partial, stale, or security-blocked scans', () => {
  const contract = readContract();

  assert.match(contract, /SAST_COVERAGE_STATES/);
  assert.match(contract, /REQUIRED_SCANNER_MISSING/);
  assert.match(contract, /REQUIRED_SCANNER_INCOMPLETE/);
  assert.match(contract, /REQUIRED_CAPABILITY_MISSING/);
  assert.match(contract, /DUPLICATE_SCANNER_RECORD/);
  assert.match(contract, /ARTIFACT_NOT_ACCEPTED/);
  assert.match(contract, /SCANNER_CAPABILITY_MISMATCH/);
  assert.match(contract, /SECURITY_BLOCKED/);
  assert.match(contract, /STALE_SCAN/);
  assert.match(
    contract,
    /externalPublicationAllowed\s*=\s*state\s*===\s*'COMPLETE'\s*&&\s*!input\.stale\s*&&\s*!hasSecurityFailure/
  );
});

test('evidence policy prevents full-file reconstruction and caps retention at seven days', () => {
  const contract = readContract();

  assert.match(contract, /maxTotalBytes:\s*32768/);
  assert.match(contract, /maxFragmentCount:\s*5/);
  assert.match(contract, /maxFragmentBytes:\s*8192/);
  assert.match(contract, /contextLinesBefore:\s*5/);
  assert.match(contract, /contextLinesAfter:\s*5/);
  assert.match(contract, /maxRetentionSeconds:\s*604800/);
  assert.match(contract, /secretRedactionRequired:\s*true/);
  assert.match(contract, /fullFileAllowed:\s*false/);
  assert.match(contract, /repositoryArchiveAllowed:\s*false/);
  assert.match(contract, /reconstructionRiskCheckRequired:\s*true/);
  assert.match(contract, /isSastEvidencePolicySafe/);
  assert.match(contract, /isSastEvidencePackSafe/);
  assert.match(contract, /sourceFileLineCount/);
  assert.match(contract, /reconstructionRiskDecisionRef/);
  assert.match(contract, /classificationDecisionRef/);
  assert.match(contract, /deletionScheduleRef/);
  assert.match(contract, /isFullFile:\s*false/);
});

test('rule policy, kill switches, and canary activation remain governed and reversible', () => {
  const contract = readContract();

  assert.match(contract, /SAST_KILL_SWITCH_SCOPES/);
  for (const scope of [
    'SCANNER_VERSION',
    'RULE_BUNDLE',
    'SEMANTIC_RULE',
    'TENANT',
    'REPOSITORY_BINDING',
    'CAPABILITY',
    'PROFILE',
    'EXTERNAL_PUBLICATION',
    'GLOBAL'
  ]) {
    assert.match(contract, new RegExp(`'${scope}'`));
  }
  assert.match(contract, /isSastKillSwitchDecisionValid/);
  assert.match(contract, /pathPatternDialect:\s*'GITIGNORE_SUBSET_V1'/);
  assert.match(contract, /customerExecutableConfigAllowed:\s*false/);
  assert.match(contract, /isTenantSastRulePolicyValid/);
  assert.match(contract, /isRuleBundleCanaryHealthy/);
  assert.match(contract, /isRuleBundleActivationReady/);
  assert.match(contract, /isSafeIntegerAtLeast\(evidence\.eligibleCompletedScans, minimumScans\)/);
  assert.match(contract, /observationHours\s*>=\s*minimumHours/);
  const canaryFunction = contract
    .split('export function isRuleBundleCanaryHealthy')[1]
    .split('export function isRuleBundleActivationReady')[0];
  for (const zeroToleranceSignal of [
    'unauthorizedEgressCount',
    'missingDestructionEvidenceCount',
    'evidencePolicyViolationCount',
    'unsignedArtifactExecutionCount'
  ]) {
    assert.match(canaryFunction, new RegExp(`evidence\\.${zeroToleranceSignal}\\s*===\\s*0`));
  }
});

test('production quality gates are quantitative and fail closed', () => {
  const contract = readContract();

  assert.match(contract, /criticalHighPrecision\s*>=\s*0\.9/);
  assert.match(contract, /mustDetectRecall\s*>=\s*0\.95/);
  assert.match(contract, /priorMustDetectRegressionRecall\s*===\s*1/);
  assert.match(contract, /maliciousCorpusPassRate\s*===\s*1/);
  assert.match(contract, /parserRejectRate\s*===\s*1/);
  assert.match(contract, /isSafeIntegerAtLeast\(evidence\.affectedProfilePositiveCaseCount, 200\)/);
  assert.match(contract, /isSafeIntegerAtLeast\(evidence\.affectedProfileNegativeCaseCount, 200\)/);
  assert.match(contract, /isSafeIntegerAtLeast\(evidence\.performanceRunsPerProfileSizeBucket, 30\)/);
  assert.match(contract, /normalizationDeterminismPassRate\s*===\s*1/);
  assert.match(contract, /artifactBindingPassRate\s*===\s*1/);
  assert.match(contract, /retentionExpiryPassRate\s*===\s*1/);
  assert.match(contract, /eligibleCompletedScans,\s*1000/);
  assert.match(contract, /observationHours\s*>=\s*48/);
  assert.match(contract, /securityApprovalRef\s*!==\s*evidence\.platformApprovalRef/);
  assert.match(contract, /fastLaneP95Milliseconds\s*<=\s*600000/);
  assert.match(contract, /deepLaneP95Milliseconds\s*<=\s*2700000/);
  assert.match(contract, /crossTenantLeakCount\s*===\s*0/);
  assert.match(contract, /secretLeakCount\s*===\s*0/);
  assert.match(contract, /sandboxEscapeCount\s*===\s*0/);
  assert.match(contract, /staleExternalPublicationCount\s*===\s*0/);
  assert.match(contract, /unauthorizedEgressCount\s*===\s*0/);
  assert.match(contract, /missingDestructionEvidenceCount\s*===\s*0/);
  assert.match(contract, /evidencePolicyViolationCount\s*===\s*0/);
  assert.match(contract, /unsignedArtifactExecutionCount\s*===\s*0/);
});

test('runtime completion is gated by cleanup evidence and explicit cleanup stages', () => {
  const contract = readContract();

  assert.match(contract, /'CLEANUP_PENDING'/);
  assert.match(contract, /'CLEANUP_FAILED'/);
  assert.match(contract, /canSastRuntimeTransitionToCompleted/);
  assert.match(contract, /currentStage\s*===\s*'CLEANUP_PENDING'/);
  assert.match(contract, /evidence\.attemptId\s*===\s*expectedAttemptId/);
  for (const requiredSignal of [
    'credentialRevokedAndWiped',
    'scannerProcessesTerminated',
    'writableVolumesDestroyed',
    'microVmTerminated',
    'resultIngressClosed',
    'cleanupEvidenceRef',
    'finalAuditEventRef'
  ]) {
    assert.match(contract, new RegExp(`\\b${requiredSignal}\\b`));
  }
});

test('failure decisions retry only bounded infrastructure failures and never publish', () => {
  const contract = readContract();

  assert.match(contract, /retryable\s*=\s*input\.failureClass\s*===\s*'RETRYABLE_INFRASTRUCTURE'/);
  assert.match(contract, /retryAllowed:\s*retryable\s*&&\s*input\.attempt\s*===\s*1/);
  assert.match(contract, /maxAttempts:\s*retryable\s*\?\s*2\s*:\s*1/);
  assert.match(contract, /externalPublicationAllowed:\s*false/);
  assert.match(contract, /quarantineRequired:\s*securityViolation/);
});
