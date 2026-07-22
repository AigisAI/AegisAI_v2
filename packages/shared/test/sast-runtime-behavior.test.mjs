import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = readFileSync(new URL('../src/types/sast-runtime.ts', import.meta.url), 'utf8');
const transpiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2022
  }
});
const localModule = { exports: {} };
const evaluateModule = new Function('module', 'exports', transpiled.outputText);
evaluateModule(localModule, localModule.exports);
const runtime = localModule.exports;

const digest = (character) => `sha256:${character.repeat(64)}`;

const canonicalJson = (value) => {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }

  const entries = Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
  return `{${entries.join(',')}}`;
};

const approvedProfileDigest = (profile) =>
  `sha256:${createHash('sha256')
    .update(canonicalJson({ version: 'sast-profile-digest-v1', profile }), 'utf8')
    .digest('hex')}`;

const signedArtifact = (character) => ({
  digest: digest(character),
  signatureRef: `signature://${character}`,
  provenanceRef: `provenance://${character}`
});

const ruleBundle = (scanner, character, state = 'ACTIVE') => ({
  bundleId: `${scanner.toLowerCase()}-rules`,
  version: '1.0.0',
  state,
  digest: digest(character),
  signatureRef: `signature://rules/${scanner}`,
  provenanceRef: `provenance://rules/${scanner}`,
  compatibilityRef: `compatibility://rules/${scanner}`,
  rolloutPolicyRef: `rollout://rules/${scanner}`,
  killSwitchRef: `kill-switch://rules/${scanner}`,
  scanner,
  source: 'PLATFORM_MANAGED',
  immutable: true,
  customerExecutableConfigAllowed: false
});

const scannerRuntime = (scanner, character, wrapperCharacter) => ({
  ...signedArtifact(character),
  scanner,
  version: '1.0.0',
  sbomRef: `sbom://${scanner}`,
  wrapper: signedArtifact(wrapperCharacter)
});

const buildScannerSet = () => ({
  scannerSetVersion: 'scanner-set-1',
  scannerSetDigest: digest('1'),
  signatureRef: 'signature://scanner-set-1',
  provenanceRef: 'provenance://scanner-set-1',
  scanners: {
    OPENGREP: scannerRuntime('OPENGREP', 'a', 'd'),
    TRIVY: scannerRuntime('TRIVY', 'b', 'e'),
    SYFT: scannerRuntime('SYFT', 'c', 'f')
  },
  ruleBundles: [ruleBundle('OPENGREP', '7'), ruleBundle('TRIVY', '8')],
  vulnerabilityDatabase: {
    ...signedArtifact('9'),
    databaseVersion: '2026-07-21',
    publishedAt: '2026-07-21T00:00:00Z'
  },
  schemaBundle: signedArtifact('0'),
  normalizerBundle: signedArtifact('6'),
  sbomSchema: 'CYCLONEDX_JSON',
  rollbackRef: 'rollback://scanner-set-0'
});

const buildPlan = () => ({
  tenantId: 'tenant-1',
  scanRequestId: 'scan-1',
  canonicalScanKey: digest('2'),
  profile: runtime.SAST_SCAN_PROFILES.JAVA_FAST_V1,
  profileDigest: runtime.SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
  policyVersion: 'policy-1',
  repositoryState: {
    repositoryBindingId: 'repository-1',
    fixedCommitSha: 'a'.repeat(40),
    targetRef: 'refs/heads/dev',
    inventoryDigest: digest('4'),
    attestationRef: 'attestation://inventory-1',
    shallowFetchPreferred: true,
    submodulesEnabled: false,
    lfsObjectsFetched: false
  },
  scannerSet: buildScannerSet(),
  isolationClass: 'HARDENED',
  resultIngressRef: 'ingress://scan-1',
  evidenceOutputRef: 'evidence://scan-1',
  auditSinkRef: 'audit://scan-1',
  forbiddenCapabilities: [...runtime.SAST_FORBIDDEN_CAPABILITIES],
  createdAt: '2026-07-21T00:00:00Z'
});

const buildArtifactEnvelope = (plan) => ({
  tenantId: plan.tenantId,
  scanRequestId: plan.scanRequestId,
  attemptId: 'attempt-1',
  scannerRunId: 'scanner-run-1',
  workloadIdentityRef: 'workload://attempt-1',
  scanner: 'OPENGREP',
  scannerVersion: plan.scannerSet.scanners.OPENGREP.version,
  scannerImageDigest: plan.scannerSet.scanners.OPENGREP.digest,
  wrapperDigest: plan.scannerSet.scanners.OPENGREP.wrapper.digest,
  ruleBundleDigest: plan.scannerSet.ruleBundles.find((bundle) => bundle.scanner === 'OPENGREP')
    .digest,
  scannerSetDigest: plan.scannerSet.scannerSetDigest,
  profileId: plan.profile.id,
  profileDigest: plan.profileDigest,
  preflightAttestationRef: 'attestation://attempt-1/preflight',
  preflightInventoryDigest: digest('3'),
  scannerWorkspaceInventoryDigest: digest('3'),
  inputCommitSha: plan.repositoryState.fixedCommitSha,
  artifactSchema: 'OPENGREP_SARIF',
  artifactSchemaVersion: '2.1.0',
  artifactRef: 'artifact://scanner-run-1',
  contentDigest: digest('4'),
  byteSize: 1024,
  recordCount: 10,
  truncated: false,
  exitCode: 0,
  executionStatus: 'SUCCEEDED',
  producedAt: '2026-07-21T00:01:00Z'
});

const expectedArtifactBinding = (envelope) => ({
  attemptId: envelope.attemptId,
  scannerRunId: envelope.scannerRunId,
  workloadIdentityRef: envelope.workloadIdentityRef,
  preflightAttestationRef: envelope.preflightAttestationRef,
  preflightInventoryDigest: envelope.preflightInventoryDigest
});

const coverageRecord = (scanner, capabilities) => ({
  scanner,
  required: true,
  capabilities,
  status: 'SUCCEEDED',
  artifactAccepted: true,
  scannerVersion: '1.0.0',
  outputDigest: digest(scanner === 'OPENGREP' ? 'a' : 'b')
});

const buildPromotionEvidence = () => ({
  bundle: ruleBundle('OPENGREP', '7', 'VALIDATED'),
  signedArtifactVerified: true,
  provenanceVerified: true,
  goldenCorpusPassRate: 1,
  mustDetectRecall: 0.95,
  criticalHighPrecision: 0.9,
  priorMustDetectRegressionRecall: 1,
  maliciousCorpusPassRate: 1,
  parserRejectRate: 1,
  falsePositiveIncrease: 0.02,
  scannerFailureRate: 0.02,
  p95LatencyIncrease: 0.2,
  affectedProfilePositiveCaseCount: 200,
  affectedProfileNegativeCaseCount: 200,
  observedChangedRulePositiveCaseCount: 10,
  observedChangedRuleNegativeCaseCount: 10,
  criticalHighRuleChanged: true,
  observedChangedCriticalHighRulePositiveCaseCount: 20,
  observedChangedCriticalHighRuleNegativeCaseCount: 20,
  performanceRunsPerProfileSizeBucket: 30,
  normalizationDeterminismPassRate: 1,
  artifactBindingPassRate: 1,
  fingerprintFixturePassRate: 1,
  coverageDecisionFixturePassRate: 1,
  retentionExpiryPassRate: 1,
  crossTenantLeakCount: 0,
  secretLeakCount: 0,
  sandboxEscapeCount: 0,
  staleExternalPublicationCount: 0,
  unauthorizedEgressCount: 0,
  missingDestructionEvidenceCount: 0,
  evidencePolicyViolationCount: 0,
  unsignedArtifactExecutionCount: 0,
  securityApprovalRef: 'approval://security',
  platformApprovalRef: 'approval://platform',
  rollbackRef: 'rollback://rules-0'
});

test('built-in SAST profiles are immutable and satisfy the complete profile validator', () => {
  for (const profile of Object.values(runtime.SAST_SCAN_PROFILES)) {
    assert.equal(runtime.isSastScanProfileValid(profile), true);
    assert.equal(runtime.SAST_APPROVED_PROFILE_DIGESTS[profile.id], approvedProfileDigest(profile));
    assert.equal(Object.isFrozen(profile), true);
    assert.equal(Object.isFrozen(profile.requiredScanners), true);
    assert.equal(Object.isFrozen(profile.limits), true);
    assert.equal(Object.isFrozen(profile.pathPolicy), true);
  }

  const invalidProfile = {
    ...runtime.SAST_SCAN_PROFILES.JAVA_FAST_V1,
    requiredScanners: ['OPENGREP'],
    requiredCapabilities: ['SAST']
  };
  assert.equal(runtime.isSastScanProfileValid(invalidProfile), false);
});

test('scan plans and artifact envelopes bind fixed intent and reject normalization ambiguity', () => {
  const plan = buildPlan();
  const envelope = buildArtifactEnvelope(plan);
  const expectedBinding = expectedArtifactBinding(envelope);

  assert.equal(runtime.isScannerSetDescriptorValid(plan.scannerSet), true);
  assert.equal(runtime.isSastScanPlanValid(plan), true);
  assert.equal(runtime.isSastScanPlanValid({}), false);
  assert.equal(
    runtime.isSastScanPlanValid({
      ...plan,
      repositoryState: { ...plan.repositoryState, attestationRef: '' }
    }),
    false
  );
  assert.equal(
    runtime.isScannerArtifactEnvelopeBoundToPlan(envelope, plan, expectedBinding),
    true
  );
  assert.equal(
    runtime.isScannerArtifactEligibleForNormalization(envelope, plan, expectedBinding),
    true
  );
  assert.equal(
    runtime.isSastScanPlanValid({ ...plan, profileDigest: digest('3') }),
    false
  );

  assert.equal(
    runtime.isScannerArtifactEnvelopeBoundToPlan(
      { ...envelope, inputCommitSha: 'b'.repeat(40) },
      plan,
      expectedBinding
    ),
    false
  );
  assert.equal(
    runtime.isScannerArtifactEnvelopeBoundToPlan(
      { ...envelope, scanner: 'UNSUPPORTED' },
      plan,
      expectedBinding
    ),
    false
  );
  assert.equal(
    runtime.isScannerArtifactEnvelopeBoundToPlan(
      envelope,
      plan,
      { ...expectedBinding, attemptId: 'attempt-current' }
    ),
    false
  );
  assert.equal(
    runtime.isScannerArtifactEnvelopeBoundToPlan(
      { ...envelope, scannerWorkspaceInventoryDigest: digest('5') },
      plan,
      expectedBinding
    ),
    false
  );
  assert.equal(
    runtime.isScannerArtifactEligibleForNormalization(
      { ...envelope, truncated: true },
      plan,
      expectedBinding
    ),
    false
  );
});

test('finding fingerprints use NFC-normalized UTF-8 length-prefix test vectors', () => {
  const canonical = {
    repositoryBindingId: 'repo-é',
    capability: 'SAST',
    ruleSemanticId: 'java.sql-injection',
    normalizedPath: 'src/Café.java',
    symbolAnchor: 'com.example.Café#run',
    sinkKind: 'SQL_EXECUTE',
    structuralHash: 'ast:v1|call(é)'
  };
  const decomposedAdapterOutput = {
    ...canonical,
    repositoryBindingId: 'repo-e\u0301',
    normalizedPath: 'src/Cafe\u0301.java',
    symbolAnchor: 'com.example.Cafe\u0301#run',
    structuralHash: 'ast:v1|call(e\u0301)'
  };
  const expectedPreimage =
    'sast-fingerprint-v1\0' +
    '7:repo-é4:SAST18:java.sql-injection14:src/Café.java' +
    '21:com.example.Café#run11:SQL_EXECUTE15:ast:v1|call(é)';

  const canonicalPreimage = runtime.buildFindingFingerprintPreimage(canonical);
  assert.equal(canonicalPreimage, expectedPreimage);
  assert.equal(
    runtime.buildFindingFingerprintPreimage(decomposedAdapterOutput),
    canonicalPreimage
  );
  assert.equal(
    createHash('sha256').update(canonicalPreimage, 'utf8').digest('hex'),
    '7bc64e19d97c160a7d58334c79149af47c9148d7238732d6092f51c7df269661'
  );
});

test('finding locations require attested file bounds or an explicit unknown location', () => {
  const metadata = {
    normalizedPath: 'src/main/java/App.java',
    lineCount: 3,
    maxColumnByLine: [20, 40, 10]
  };
  const known = {
    kind: 'FILE',
    normalizedPath: metadata.normalizedPath,
    lineStart: 2,
    lineEnd: 3,
    columnStart: 10,
    columnEnd: 8,
    symbol: 'App#run'
  };

  assert.equal(runtime.isSastFindingLocationValid(known, metadata), true);
  assert.equal(runtime.isSastFindingLocationValid(known), false);
  assert.equal(
    runtime.isSastFindingLocationValid({ ...known, lineStart: Number.MAX_SAFE_INTEGER }, metadata),
    false
  );
  assert.equal(
    runtime.isSastFindingLocationValid({ kind: 'UNKNOWN', reasonCode: 'LOCATION_NOT_MAPPABLE' }),
    true
  );
  assert.equal(
    runtime.isSastFindingLocationValid({
      kind: 'UNKNOWN',
      reasonCode: 'LOCATION_NOT_MAPPABLE',
      lineStart: 1
    }),
    false
  );
});

test('coverage is complete only for accepted authoritative required capabilities', () => {
  const profile = runtime.SAST_SCAN_PROFILES.JAVA_FAST_V1;
  const opengrep = coverageRecord('OPENGREP', ['SAST']);
  const trivy = coverageRecord('TRIVY', ['DEPENDENCY_VULNERABILITY', 'SECRET_DETECTION']);

  const complete = runtime.evaluateSastCoverage({
    profile,
    records: [opengrep, trivy],
    stale: false,
    securityBlocked: false
  });
  assert.equal(complete.state, 'COMPLETE');
  assert.equal(complete.externalPublicationAllowed, true);
  assert.equal(complete.aiAdvisoryAllowed, true);

  const duplicate = runtime.evaluateSastCoverage({
    profile,
    records: [opengrep, opengrep, trivy],
    stale: false,
    securityBlocked: false
  });
  assert.equal(duplicate.state, 'FAILED');
  assert.equal(duplicate.externalPublicationAllowed, false);
  assert.ok(duplicate.reasonCodes.includes('DUPLICATE_SCANNER_RECORD'));

  const missingCapability = runtime.evaluateSastCoverage({
    profile,
    records: [opengrep, coverageRecord('TRIVY', ['DEPENDENCY_VULNERABILITY'])],
    stale: false,
    securityBlocked: false
  });
  assert.equal(missingCapability.state, 'PARTIAL');
  assert.deepEqual(missingCapability.missingRequiredCapabilities, ['SECRET_DETECTION']);

  const stale = runtime.evaluateSastCoverage({
    profile,
    records: [opengrep, trivy],
    stale: true,
    securityBlocked: false
  });
  assert.equal(stale.state, 'COMPLETE');
  assert.equal(stale.externalPublicationAllowed, false);
});

test('evidence validation enforces byte, full-file, decision, and retention boundaries', () => {
  const policy = runtime.DEFAULT_SAST_EVIDENCE_POLICY;
  const fragment = {
    normalizedPath: 'src/main/java/App.java',
    startLine: 10,
    endLine: 20,
    sourceFileLineCount: 100,
    redactedContent: 'redacted',
    byteSize: 8,
    contentDigest: digest('5'),
    secretRedactionApplied: true,
    redactionDecisionRef: 'redaction://fragment-1',
    isFullFile: false
  };
  const pack = {
    evidencePackId: 'evidence-1',
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    findingFingerprint: digest('6'),
    policyVersion: 'evidence-policy-1',
    fragments: [fragment],
    totalBytes: 8,
    truncated: false,
    suppressedFragmentCount: 0,
    reconstructionRiskChecked: true,
    reconstructionRiskDecisionRef: 'reconstruction://evidence-1',
    classificationDecisionRef: 'classification://evidence-1',
    deletionScheduleRef: 'deletion://evidence-1',
    dashboardSafe: true,
    aiSafe: true,
    createdAt: '2026-07-21T00:00:00Z',
    expiresAt: '2026-07-22T00:00:00Z'
  };

  assert.equal(runtime.isSastEvidencePackSafe(pack, policy), true);
  assert.equal(
    runtime.isSastEvidencePackSafe(
      {
        ...pack,
        fragments: [{ ...fragment, startLine: 1, endLine: 100 }]
      },
      policy
    ),
    false
  );
  assert.equal(
    runtime.isSastEvidencePackSafe(
      { ...pack, expiresAt: '2026-07-29T00:00:01Z' },
      policy
    ),
    false
  );
});

test('promotion, canary, and production gates enforce samples, approvals, and zero tolerance', () => {
  const promotion = buildPromotionEvidence();
  assert.equal(runtime.isRuleBundlePromotionReady(promotion), true);
  assert.equal(
    runtime.isRuleBundlePromotionReady({ ...promotion, affectedProfilePositiveCaseCount: 199 }),
    false
  );
  assert.equal(
    runtime.isRuleBundlePromotionReady({
      ...promotion,
      platformApprovalRef: promotion.securityApprovalRef
    }),
    false
  );

  const canary = {
    bundle: ruleBundle('OPENGREP', '7', 'CANARY'),
    eligibleCompletedScans: 1000,
    observationHours: 48,
    finalStep: true,
    falsePositiveIncrease: 0.02,
    scannerFailureRate: 0.02,
    p95LatencyIncrease: 0.2,
    unexplainedCriticalHighVolumeChange: 0.2,
    telemetryComplete: true,
    crossTenantLeakCount: 0,
    secretLeakCount: 0,
    sandboxEscapeCount: 0,
    staleExternalPublicationCount: 0,
    unauthorizedEgressCount: 0,
    missingDestructionEvidenceCount: 0,
    evidencePolicyViolationCount: 0,
    unsignedArtifactExecutionCount: 0,
    securityApprovalRef: 'approval://security',
    platformApprovalRef: 'approval://platform',
    rollbackRef: 'rollback://rules-0'
  };
  assert.equal(runtime.isRuleBundleActivationReady(canary), true);
  assert.equal(
    runtime.isRuleBundleActivationReady({ ...canary, eligibleCompletedScans: 999 }),
    false
  );
  for (const zeroToleranceSignal of [
    'unauthorizedEgressCount',
    'missingDestructionEvidenceCount',
    'evidencePolicyViolationCount',
    'unsignedArtifactExecutionCount'
  ]) {
    assert.equal(
      runtime.isRuleBundleActivationReady({ ...canary, [zeroToleranceSignal]: 1 }),
      false
    );
  }

  const quality = {
    eligibleCompletedScans: 1000,
    observationHours: 48,
    performanceRunsPerProfileSizeBucket: 30,
    goldenCorpusPassRate: 1,
    criticalHighPrecision: 0.9,
    mustDetectRecall: 0.95,
    priorMustDetectRegressionRecall: 1,
    maliciousCorpusPassRate: 1,
    parserRejectRate: 1,
    fastLaneP95Milliseconds: 600000,
    deepLaneP95Milliseconds: 2700000,
    falsePositiveIncrease: 0.02,
    scannerFailureRate: 0.02,
    normalizationDeterminismPassRate: 1,
    artifactBindingPassRate: 1,
    fingerprintFixturePassRate: 1,
    coverageDecisionFixturePassRate: 1,
    retentionExpiryPassRate: 1,
    crossTenantLeakCount: 0,
    secretLeakCount: 0,
    sandboxEscapeCount: 0,
    staleExternalPublicationCount: 0,
    unauthorizedEgressCount: 0,
    missingDestructionEvidenceCount: 0,
    evidencePolicyViolationCount: 0,
    unsignedArtifactExecutionCount: 0
  };
  assert.equal(runtime.areSastProductionQualityGatesSatisfied(quality), true);
  assert.equal(
    runtime.areSastProductionQualityGatesSatisfied({ ...quality, unauthorizedEgressCount: 1 }),
    false
  );
  assert.equal(
    runtime.areSastProductionQualityGatesSatisfied({ ...quality, scannerFailureRate: -0.01 }),
    false
  );
});

test('kill-switch scopes are complete and cleanup evidence gates completion', () => {
  assert.deepEqual(runtime.SAST_KILL_SWITCH_SCOPES, [
    'SCANNER_VERSION',
    'RULE_BUNDLE',
    'SEMANTIC_RULE',
    'TENANT',
    'REPOSITORY_BINDING',
    'CAPABILITY',
    'PROFILE',
    'EXTERNAL_PUBLICATION',
    'GLOBAL'
  ]);

  const cleanup = {
    attemptId: 'attempt-1',
    credentialRevokedAndWiped: true,
    scannerProcessesTerminated: true,
    writableVolumesDestroyed: true,
    microVmTerminated: true,
    resultIngressClosed: true,
    cleanupEvidenceRef: 'cleanup://attempt-1',
    finalAuditEventRef: 'audit://attempt-1/terminated',
    completedAt: '2026-07-21T00:02:00Z'
  };
  assert.equal(
    runtime.canSastRuntimeTransitionToCompleted('CLEANUP_PENDING', 'attempt-1', cleanup),
    true
  );
  assert.equal(
    runtime.canSastRuntimeTransitionToCompleted('POLICY_PENDING', 'attempt-1', cleanup),
    false
  );
  assert.equal(
    runtime.canSastRuntimeTransitionToCompleted('CLEANUP_PENDING', 'attempt-current', cleanup),
    false
  );
  assert.equal(
    runtime.canSastRuntimeTransitionToCompleted(
      'CLEANUP_PENDING',
      'attempt-1',
      { ...cleanup, resultIngressClosed: false }
    ),
    false
  );
});

test('failure policy retries only the first infrastructure attempt', () => {
  const first = runtime.decideSastFailure({
    failureClass: 'RETRYABLE_INFRASTRUCTURE',
    attempt: 1,
    reasonCode: 'NODE_LOST'
  });
  const second = runtime.decideSastFailure({
    failureClass: 'RETRYABLE_INFRASTRUCTURE',
    attempt: 2,
    reasonCode: 'NODE_LOST'
  });
  const security = runtime.decideSastFailure({
    failureClass: 'SECURITY_VIOLATION',
    attempt: 1,
    reasonCode: 'DIGEST_MISMATCH'
  });

  assert.equal(first.retryAllowed, true);
  assert.equal(second.retryAllowed, false);
  assert.equal(security.retryAllowed, false);
  assert.equal(security.quarantineRequired, true);
  assert.equal(security.hardenedIsolationRequired, true);
  assert.equal(security.externalPublicationAllowed, false);
});
