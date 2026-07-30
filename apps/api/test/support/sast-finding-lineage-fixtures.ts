import { createHash } from 'node:crypto';

import {
  OPENGREP_SARIF_NORMALIZER_VERSION,
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_FINDING_LIFECYCLE_COVERAGE_VERSION,
  SAST_FINDING_RENAME_ATTESTATION_VERSION,
  SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
  SAST_SECRET_REDACTION_TOKEN,
  SAST_SECRET_REDACTION_VERSION,
  buildSastFindingLifecycleContextPreimage,
  canonicalizeSastFindingLifecycleCoverageDecision,
  canonicalizeSastFindingRenameAttestation,
  canonicalizeSastSecretRedactionBatch,
  canonicalizeSastSecretRedactionDecision,
  compareSastNormalizedFindingCandidates,
  type SastFindingLifecycleCoverageDecision,
  type SastFindingLifecycleCoverageDecisionCore,
  type SastFindingLocation,
  type SastFindingRenameAttestation,
  type SastFindingRenameAttestationCore,
  type SastFingerprintedFindingBatch,
  type SastSecretRedactedFindingCandidate,
  type SastSecretRedactionBatch,
  type SastSecretRedactionBatchCore
} from '@aegisai/shared';

import {
  SastFindingIdentityService
} from '../../src/scan-plane/sast-finding-identity.service';
import type {
  SastFindingLineageScanContext,
  SastFindingReconciliationScanContext
} from '../../src/scan-plane/sast-finding-lineage.store';

export const LINEAGE_FIXTURE_TIME =
  '2026-07-30T00:00:00.000Z';
export const LINEAGE_RETENTION_EXPIRES_AT =
  '2026-08-01T00:00:00.000Z';
export const LINEAGE_DIGEST = fixtureDigest('fixture');

type OpenGrepRedactedFinding = Extract<
  SastSecretRedactedFindingCandidate,
  { capability: 'SAST' }
>;

export async function fingerprintedFindingBatch(
  findingOverrides: readonly Partial<OpenGrepRedactedFinding>[] = [
    {}
  ]
): Promise<SastFingerprintedFindingBatch> {
  const source = redactedBatch(
    findingOverrides.map((overrides) =>
      redactedFinding(overrides)
    )
  );
  const result = await new SastFindingIdentityService().construct(
    { batch: source },
    lineageFixtureClock
  );
  if (result.outcome !== 'FINGERPRINTED') {
    throw new Error('The finding-lineage fixture is invalid.');
  }
  return result.batch;
}

export function lineageObservationContext(
  batch: Readonly<SastFingerprintedFindingBatch>
): SastFindingLineageScanContext {
  return {
    scope: { ...batch.scope },
    targetRef: 'refs/heads/main',
    lane: batch.lane,
    commitSha: batch.commitSha,
    canonicalScanKey: batch.canonicalScanKey,
    planDigest: batch.planDigest,
    profileId: 'JAVA_FAST_V1',
    profileDigest:
      SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
    scanner: batch.scanner,
    source: {
      ingestionId: batch.ingestionId,
      scannerVersion: batch.scannerVersion,
      scannerImageDigest: batch.scannerImageDigest,
      ...(batch.ruleBundleDigest
        ? { ruleBundleDigest: batch.ruleBundleDigest }
        : {}),
      ...(batch.vulnerabilityDatabaseDigest
        ? {
            vulnerabilityDatabaseDigest:
              batch.vulnerabilityDatabaseDigest
          }
        : {}),
      schemaBundleDigest: batch.schemaBundleDigest,
      normalizerBundleDigest: batch.normalizerBundleDigest,
      preflightAttestationRef:
        batch.preflightAttestationRef,
      preflightInventoryDigest:
        batch.preflightInventoryDigest,
      artifactSchema: batch.artifactSchema,
      artifactSchemaVersion: batch.artifactSchemaVersion,
      envelopeDigest: batch.envelopeDigest,
      artifactDigest: batch.artifactDigest,
      validationResultDigest:
        batch.validationResultDigest,
      dispositionDecisionDigest:
        batch.dispositionDecisionDigest,
      retentionExpiresAt: batch.retentionExpiresAt
    }
  };
}

export function lineageContextKey(
  context: Readonly<SastFindingLineageScanContext>
): `sha256:${string}` {
  return fixtureDigest(
    buildSastFindingLifecycleContextPreimage({
      tenantId: context.scope.tenantId,
      repositoryBindingId:
        context.scope.repositoryBindingId,
      targetRef: context.targetRef
    })
  );
}

export function renameAttestation(
  context: Readonly<SastFindingLineageScanContext>,
  overrides: Partial<SastFindingRenameAttestationCore> = {}
): SastFindingRenameAttestation {
  const core: SastFindingRenameAttestationCore = {
    version: SAST_FINDING_RENAME_ATTESTATION_VERSION,
    tenantId: context.scope.tenantId,
    repositoryBindingId:
      context.scope.repositoryBindingId,
    lifecycleContextKey: lineageContextKey(context),
    fromScanRequestId: 'scan-0',
    fromCommitSha: 'b'.repeat(40),
    toScanRequestId: context.scope.scanRequestId,
    toCommitSha: context.commitSha,
    profileId: context.profileId,
    profileDigest: context.profileDigest,
    entries: [
      {
        fromNormalizedPath: 'src/old-config.ts',
        toNormalizedPath: 'src/config.ts'
      }
    ],
    issuedAt: '2026-07-29T23:59:00.000Z',
    attestationRef: 'rename-attestation://scan-0/scan-1',
    signatureRef: 'signature://rename-attestation-1',
    provenanceRef: 'provenance://rename-attestation-1',
    ...overrides
  };
  return {
    ...core,
    attestationDigest: fixtureDigest(
      canonicalizeSastFindingRenameAttestation(core)
    )
  };
}

export function reconciliationContext(): SastFindingReconciliationScanContext {
  return {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    targetRef: 'refs/heads/main',
    lane: 'FAST',
    commitSha: 'a'.repeat(40),
    canonicalScanKey: LINEAGE_DIGEST,
    planDigest: LINEAGE_DIGEST,
    profileId: 'JAVA_FAST_V1',
    profileDigest:
      SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1
  };
}

export function lifecycleCoverageDecision(
  overrides: Partial<SastFindingLifecycleCoverageDecisionCore> = {}
): SastFindingLifecycleCoverageDecision {
  const context = reconciliationContext();
  const core: SastFindingLifecycleCoverageDecisionCore = {
    version: SAST_FINDING_LIFECYCLE_COVERAGE_VERSION,
    tenantId: context.tenantId,
    repositoryBindingId: context.repositoryBindingId,
    scanRequestId: context.scanRequestId,
    attemptId: context.attemptId,
    canonicalScanKey: context.canonicalScanKey,
    planDigest: context.planDigest,
    commitSha: context.commitSha,
    lifecycleContextKey: fixtureDigest(
      buildSastFindingLifecycleContextPreimage({
        tenantId: context.tenantId,
        repositoryBindingId: context.repositoryBindingId,
        targetRef: context.targetRef
      })
    ),
    profileId: context.profileId,
    profileDigest: context.profileDigest,
    state: 'COMPLETE',
    stale: false,
    comparable: true,
    sequence: 1,
    previousScanRequestId: 'scan-0',
    previousCommitSha: 'b'.repeat(40),
    completeCapabilities: ['SAST'],
    eligibleLineageIds: [
      `finding-lineage://${'1'.repeat(64)}`
    ],
    expectedObservationBatchDigests: [
      fixtureDigest('identity-batch')
    ],
    sourceCoverageDecisionDigest:
      fixtureDigest('source-coverage'),
    sourceCoverageDecisionRef: 'coverage://scan-1',
    completedAt: '2026-07-29T23:58:00.000Z',
    decidedAt: '2026-07-29T23:59:00.000Z',
    ...overrides
  };
  return {
    ...core,
    decisionDigest: fixtureDigest(
      canonicalizeSastFindingLifecycleCoverageDecision(core)
    )
  };
}

export function lineageFixtureClock(): Date {
  return new Date(LINEAGE_FIXTURE_TIME);
}

export function fixtureDigest(
  value: string
): `sha256:${string}` {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}

function redactedFinding(
  overrides: Partial<OpenGrepRedactedFinding>
): OpenGrepRedactedFinding {
  const finding = {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    planDigest: LINEAGE_DIGEST,
    canonicalScanKey: LINEAGE_DIGEST,
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: LINEAGE_DIGEST,
    commitSha: 'a'.repeat(40),
    lane: 'FAST',
    capability: 'SAST',
    title: `${SAST_SECRET_REDACTION_TOKEN} exposure`,
    description: 'A credential-like value was removed.',
    severity: 'HIGH',
    confidence: 'HIGH',
    cweIds: ['CWE-798'],
    cveIds: [],
    location: {
      kind: 'FILE',
      normalizedPath: 'src/config.ts',
      lineStart: 4,
      lineEnd: 4
    } satisfies SastFindingLocation,
    identityMaterial: {
      ruleSemanticId: 'javascript.hardcoded-secret',
      symbolAnchor: '',
      sinkKind: '',
      structuralHash: fixtureDigest('structure'),
      scannerMatchBasedId: 'rules.secret:match-1'
    },
    provenance: {
      scanner: 'OPENGREP',
      scannerVersion: '1.22.0',
      scannerImageDigest: LINEAGE_DIGEST,
      ruleId: 'rules.secret',
      ruleRevision: '2026.07.1',
      ruleBundleDigest: LINEAGE_DIGEST,
      artifactDigest: LINEAGE_DIGEST
    },
    notes: [],
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      replacementToken: SAST_SECRET_REDACTION_TOKEN,
      inspectedFieldCount: 10,
      redactedFields: ['TITLE'],
      replacementCount: 1,
      detectorKinds: ['GITHUB_TOKEN'],
      secretValueStored: false,
      matchedValueDigestStored: false,
      rawCandidateStored: false,
      decisionDigest: LINEAGE_DIGEST,
      decisionRef:
        `redaction://${SAST_SECRET_REDACTION_VERSION}/${'a'.repeat(64)}`
    },
    durablePersistenceAllowed: false,
    ...overrides
  } as OpenGrepRedactedFinding;
  const {
    decisionDigest: _decisionDigest,
    decisionRef: _decisionRef,
    ...redactionCore
  } = finding.redaction;
  void _decisionDigest;
  void _decisionRef;
  const decisionDigest = fixtureDigest(
    canonicalizeSastSecretRedactionDecision({
      ...finding,
      redaction: redactionCore
    })
  );
  finding.redaction.decisionDigest = decisionDigest;
  finding.redaction.decisionRef =
    `redaction://${SAST_SECRET_REDACTION_VERSION}/${decisionDigest.slice(
      'sha256:'.length
    )}`;
  return finding;
}

function redactedBatch(
  sourceFindings: OpenGrepRedactedFinding[]
): SastSecretRedactionBatch {
  const findings = [...sourceFindings].sort((left, right) =>
    compareSastNormalizedFindingCandidates(left, right)
  );
  const first = findings[0];
  const batchCore: SastSecretRedactionBatchCore = {
    version: SAST_SECRET_REDACTION_VERSION,
    outcome: 'REDACTED',
    sourceAdapterVersion: OPENGREP_SARIF_NORMALIZER_VERSION,
    artifactSchema: 'OPENGREP_SARIF',
    artifactSchemaVersion: '2.1.0',
    ingestionId: 'ingestion-1',
    scope: {
      tenantId: first?.tenantId ?? 'tenant-1',
      repositoryBindingId:
        first?.repositoryBindingId ?? 'repository-1',
      scanRequestId: first?.scanRequestId ?? 'scan-1',
      attemptId: first?.attemptId ?? 'attempt-1',
      scannerRunId: first?.scannerRunId ?? 'scanner-run-1'
    },
    scannerRunId: first?.scannerRunId ?? 'scanner-run-1',
    scanner: 'OPENGREP',
    scannerVersion:
      first?.provenance.scannerVersion ?? '1.22.0',
    scannerImageDigest:
      first?.provenance.scannerImageDigest ?? LINEAGE_DIGEST,
    ruleBundleDigest:
      first?.provenance.ruleBundleDigest ?? LINEAGE_DIGEST,
    planDigest: first?.planDigest ?? LINEAGE_DIGEST,
    canonicalScanKey:
      first?.canonicalScanKey ?? LINEAGE_DIGEST,
    preflightAttestationRef:
      first?.preflightAttestationRef ??
      'preflight://attempt-1',
    preflightInventoryDigest:
      first?.preflightInventoryDigest ?? LINEAGE_DIGEST,
    lane: first?.lane ?? 'FAST',
    commitSha: first?.commitSha ?? 'a'.repeat(40),
    envelopeDigest: fixtureDigest('envelope'),
    artifactDigest:
      first?.provenance.artifactDigest ?? LINEAGE_DIGEST,
    schemaBundleDigest: fixtureDigest('schema'),
    normalizerBundleDigest: fixtureDigest('normalizer'),
    validationResultDigest: fixtureDigest('validation'),
    dispositionDecisionDigest: fixtureDigest('disposition'),
    retentionExpiresAt: LINEAGE_RETENTION_EXPIRES_AT,
    findings,
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      candidateCount: findings.length,
      batchInspectedFieldCount:
        SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
      inspectedFieldCount:
        findings.reduce(
          (sum, finding) =>
            sum + finding.redaction.inspectedFieldCount,
          0
        ) + SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
      redactedCandidateCount: findings.length,
      redactedFieldCount: findings.length,
      replacementCount: findings.length,
      detectorKinds:
        findings.length === 0 ? [] : ['GITHUB_TOKEN'],
      secretValuesStored: false,
      matchedValueDigestsStored: false,
      rawCandidatesStored: false,
      sourceCandidateDigestStored: false
    },
    durablePersistenceAllowed: false
  };
  return {
    ...batchCore,
    batchDigest: fixtureDigest(
      canonicalizeSastSecretRedactionBatch(batchCore)
    )
  };
}
