import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_CAPABILITIES,
  SAST_FINDING_CORRELATION_SOURCE_VERSION,
  SAST_FINDING_LINEAGE_VERSION,
  SAST_SCAN_PROFILES,
  SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
  SAST_SECRET_REDACTION_TOKEN,
  SAST_SECRET_REDACTION_VERSION,
  TRIVY_JSON_NORMALIZER_VERSION,
  canonicalizeSastFindingLineageObservationResult,
  canonicalizeSastSecretRedactionBatch,
  canonicalizeSastSecretRedactionDecision,
  sastFindingLineageAuthority,
  type SastFindingCorrelationSourceBindingCore,
  type SastFindingLineageObservationResult,
  type SastFindingLineageObservationResultCore,
  type SastFingerprintedFindingBatch,
  type SastCapability,
  type SastSecretRedactedFindingCandidate,
  type SastSecretRedactionBatch,
  type SastSecretRedactionBatchCore
} from '@aegisai/shared';

import { SastFindingIdentityService } from '../../src/scan-plane/sast-finding-identity.service';
import type {
  SastFindingCorrelationContext,
  SastFindingCorrelationOccurrence
} from '../../src/scan-plane/sast-finding-correlation.store';
import {
  LINEAGE_FIXTURE_TIME,
  LINEAGE_RETENTION_EXPIRES_AT,
  fingerprintedFindingBatch,
  fixtureDigest
} from './sast-finding-lineage-fixtures';

type TrivyDependencyRedactedFinding = Extract<
  SastSecretRedactedFindingCandidate,
  { capability: 'DEPENDENCY_VULNERABILITY' }
>;

type FindingCapability = Exclude<SastCapability, 'SBOM'>;

const FINDING_CAPABILITY_ORDER = SAST_CAPABILITIES.filter(
  (capability): capability is FindingCapability => capability !== 'SBOM'
);

export const CORRELATION_CONTEXT_KEY = fixtureDigest(
  'correlation-context'
);
export const CORRELATION_TIME = '2026-07-30T00:01:00.000Z';

export async function correlationFixture(options: {
  repeatedOpenGrep?: boolean;
  crossToolCve?: boolean;
  supportingOpenGrep?: boolean;
  planDigest?: `sha256:${string}`;
} = {}): Promise<{
  observations: SastFindingLineageObservationResult[];
  context: SastFindingCorrelationContext;
}> {
  const lane = options.supportingOpenGrep ? 'DEEP' : 'FAST';
  const cveIds = options.crossToolCve ? ['CVE-2026-12345'] : [];
  const openGrep = await fingerprintedFindingBatch(
    options.repeatedOpenGrep
      ? [
          {
            lane,
            cveIds,
            severity: 'CRITICAL',
            ...(options.planDigest
              ? { planDigest: options.planDigest }
              : {})
          },
          {
            lane,
            cveIds,
            severity: 'LOW',
            ...(options.planDigest
              ? { planDigest: options.planDigest }
              : {}),
            location: {
              kind: 'FILE',
              normalizedPath: 'src/config.ts',
              lineStart: 40,
              lineEnd: 40
            },
            identityMaterial: {
              ruleSemanticId: 'javascript.hardcoded-secret',
              symbolAnchor: '',
              sinkKind: '',
              structuralHash: fixtureDigest('structure'),
              scannerMatchBasedId: 'rules.secret:match-2'
            }
          }
        ]
      : [
          {
            lane,
            cveIds,
            severity: 'CRITICAL',
            ...(options.planDigest
              ? { planDigest: options.planDigest }
              : {})
          }
        ]
  );
  const batches: SastFingerprintedFindingBatch[] = [openGrep];
  if (options.crossToolCve) {
    batches.push(
      await fingerprintedTrivyDependencyBatch(
        lane,
        options.planDigest
      )
    );
  }

  const sources: SastFindingCorrelationSourceBindingCore[] = [];
  const occurrences: SastFindingCorrelationOccurrence[] = [];
  const observations: SastFindingLineageObservationResult[] = [];
  for (let batchIndex = 0; batchIndex < batches.length; batchIndex += 1) {
    const batch = batches[batchIndex];
    if (!batch) throw new Error('Missing correlation fixture batch.');
    const observationBatchId = correlationId(
      'finding-observation',
      batchIndex + 1
    );
    const observedAt = new Date(
      Date.parse(LINEAGE_FIXTURE_TIME) + batchIndex
    ).toISOString();
    const capabilities = [
      ...new Set(batch.findings.map((finding) => finding.capability))
    ].sort(capabilityOrder);
    sources.push({
      version: SAST_FINDING_CORRELATION_SOURCE_VERSION,
      observationBatchId,
      sourceIdentityBatchDigest: batch.batchDigest,
      scannerRunId: batch.scannerRunId,
      scanner: batch.scanner,
      capabilities,
      lifecycleContextKey: CORRELATION_CONTEXT_KEY,
      findingCount: batch.findings.length,
      occurrenceCount: batch.findings.length,
      observedAt
    });
    for (let ordinal = 0; ordinal < batch.findings.length; ordinal += 1) {
      const finding = batch.findings[ordinal];
      if (!finding) throw new Error('Missing correlation fixture finding.');
      occurrences.push({
        id: correlationId(
          'finding-occurrence',
          batchIndex * 100 + ordinal + 1
        ),
        observationBatchId,
        lineageId: correlationId(
          'finding-lineage',
          batchIndex * 100 +
            (options.repeatedOpenGrep ? 1 : ordinal + 1)
        ),
        normalizedFindingId: correlationId(
          'normalized-finding',
          batchIndex * 100 + ordinal + 1
        ),
        scannerRunId: batch.scannerRunId,
        ordinal,
        sourceFinding: finding
      });
    }
    observations.push(
      observationResult({
        observationBatchId,
        batch,
        observedAt,
        distinctFingerprintCount: new Set(
          batch.findings.map(
            (finding) => finding.fingerprint.stableFingerprint
          )
        ).size
      })
    );
  }

  const profileId = options.supportingOpenGrep
    ? 'COMMON_DEEP_V1'
    : 'JAVA_FAST_V1';
  return {
    observations,
    context: {
      scope: {
        tenantId: openGrep.scope.tenantId,
        repositoryBindingId: openGrep.scope.repositoryBindingId,
        scanRequestId: openGrep.scope.scanRequestId,
        attemptId: openGrep.scope.attemptId,
        lifecycleContextKey: CORRELATION_CONTEXT_KEY,
        targetRef: 'refs/heads/main',
        commitSha: openGrep.commitSha,
        lane,
        canonicalScanKey: openGrep.canonicalScanKey,
        planDigest: openGrep.planDigest,
        profileId,
        profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profileId]
      },
      requiredCapabilities: SAST_SCAN_PROFILES[
        profileId
      ].requiredCapabilities.filter(
        (capability): capability is FindingCapability =>
          capability !== 'SBOM'
      ),
      sources,
      occurrences
    }
  };
}

export function correlationFixtureClock(): Date {
  return new Date(CORRELATION_TIME);
}

async function fingerprintedTrivyDependencyBatch(
  lane: 'FAST' | 'DEEP',
  planDigest?: `sha256:${string}`
): Promise<SastFingerprintedFindingBatch> {
  const source = trivyDependencyRedactedBatch(lane, planDigest);
  const result = await new SastFindingIdentityService().construct(
    { batch: source },
    () => new Date(LINEAGE_FIXTURE_TIME)
  );
  if (result.outcome !== 'FINGERPRINTED') {
    throw new Error('The Trivy correlation fixture is invalid.');
  }
  return result.batch;
}

function trivyDependencyRedactedBatch(
  lane: 'FAST' | 'DEEP',
  planDigest?: `sha256:${string}`
): SastSecretRedactionBatch {
  const finding = trivyDependencyRedactedFinding(lane, planDigest);
  const core: SastSecretRedactionBatchCore = {
    version: SAST_SECRET_REDACTION_VERSION,
    outcome: 'REDACTED',
    sourceAdapterVersion: TRIVY_JSON_NORMALIZER_VERSION,
    artifactSchema: 'TRIVY_JSON',
    artifactSchemaVersion: '2',
    ingestionId: 'ingestion-trivy-1',
    scope: {
      tenantId: finding.tenantId,
      repositoryBindingId: finding.repositoryBindingId,
      scanRequestId: finding.scanRequestId,
      attemptId: finding.attemptId,
      scannerRunId: finding.scannerRunId
    },
    scannerRunId: finding.scannerRunId,
    scanner: 'TRIVY',
    scannerVersion: finding.provenance.scannerVersion,
    scannerImageDigest: finding.provenance.scannerImageDigest,
    ruleBundleDigest: finding.provenance.ruleBundleDigest,
    vulnerabilityDatabaseDigest:
      finding.provenance.vulnerabilityDatabaseDigest,
    planDigest: finding.planDigest,
    canonicalScanKey: finding.canonicalScanKey,
    preflightAttestationRef: finding.preflightAttestationRef,
    preflightInventoryDigest: finding.preflightInventoryDigest,
    lane: finding.lane,
    commitSha: finding.commitSha,
    envelopeDigest: fixtureDigest('trivy-envelope'),
    artifactDigest: finding.provenance.artifactDigest,
    schemaBundleDigest: fixtureDigest('trivy-schema'),
    normalizerBundleDigest: fixtureDigest('trivy-normalizer'),
    validationResultDigest: fixtureDigest('trivy-validation'),
    dispositionDecisionDigest: fixtureDigest('trivy-disposition'),
    retentionExpiresAt: LINEAGE_RETENTION_EXPIRES_AT,
    findings: [finding],
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      candidateCount: 1,
      batchInspectedFieldCount:
        SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
      inspectedFieldCount:
        finding.redaction.inspectedFieldCount +
        SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
      redactedCandidateCount: 0,
      redactedFieldCount: 0,
      replacementCount: 0,
      detectorKinds: [],
      secretValuesStored: false,
      matchedValueDigestsStored: false,
      rawCandidatesStored: false,
      sourceCandidateDigestStored: false
    },
    durablePersistenceAllowed: false
  };
  return {
    ...core,
    batchDigest: fixtureDigest(
      canonicalizeSastSecretRedactionBatch(core)
    )
  };
}

function trivyDependencyRedactedFinding(
  lane: 'FAST' | 'DEEP',
  planDigest?: `sha256:${string}`
): TrivyDependencyRedactedFinding {
  const vulnerabilityDatabaseDigest = fixtureDigest(
    'vulnerability-database'
  );
  const finding = {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-trivy-1',
    planDigest: planDigest ?? fixtureDigest('fixture'),
    canonicalScanKey: fixtureDigest('fixture'),
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: fixtureDigest('fixture'),
    commitSha: 'a'.repeat(40),
    lane,
    capability: 'DEPENDENCY_VULNERABILITY',
    title: 'CVE-2026-12345 in org.example:library',
    description: 'A vulnerable dependency version is installed.',
    severity: 'HIGH',
    confidence: 'UNKNOWN',
    cweIds: [],
    cveIds: ['CVE-2026-12345'],
    location: {
      kind: 'UNKNOWN',
      reasonCode: 'SCANNER_LOCATION_OMITTED'
    },
    identityMaterial: {
      ruleSemanticId: 'trivy-advisory:CVE-2026-12345',
      symbolAnchor: 'org.example:library',
      sinkKind: 'maven',
      structuralHash: fixtureDigest('dependency-structure'),
      scannerMatchBasedId: fixtureDigest('dependency-match')
    },
    provenance: {
      scanner: 'TRIVY',
      scannerVersion: '0.66.0',
      scannerImageDigest: fixtureDigest('trivy-image'),
      ruleId: 'CVE-2026-12345',
      ruleRevision: '2026.08.1',
      ruleBundleDigest: fixtureDigest('trivy-rules'),
      artifactDigest: fixtureDigest('fixture'),
      ruleSource: 'VULNERABILITY_DATABASE',
      vulnerabilityDatabaseDigest
    },
    scannerDisposition: {
      source: 'DIRECT',
      status: 'active',
      platformPolicyAuthority: false
    },
    trivy: {
      kind: 'DEPENDENCY_VULNERABILITY',
      vulnerabilityId: 'CVE-2026-12345',
      packageName: 'org.example:library',
      packageType: 'maven',
      installedVersion: '1.2.3',
      fixedVersion: '1.2.4',
      advisoryStatus: 'affected'
    },
    notes: ['UNKNOWN_CONFIDENCE'],
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      replacementToken: SAST_SECRET_REDACTION_TOKEN,
      inspectedFieldCount: 20,
      redactedFields: [],
      replacementCount: 0,
      detectorKinds: [],
      secretValueStored: false,
      matchedValueDigestStored: false,
      rawCandidateStored: false,
      decisionDigest: fixtureDigest('placeholder-redaction'),
      decisionRef: `redaction://${SAST_SECRET_REDACTION_VERSION}/${'a'.repeat(
        64
      )}`
    },
    durablePersistenceAllowed: false
  } satisfies TrivyDependencyRedactedFinding;
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

function observationResult(input: {
  observationBatchId: string;
  batch: Readonly<SastFingerprintedFindingBatch>;
  observedAt: string;
  distinctFingerprintCount: number;
}): SastFindingLineageObservationResult {
  const core: SastFindingLineageObservationResultCore = {
    version: SAST_FINDING_LINEAGE_VERSION,
    outcome: 'OBSERVED',
    operation: 'OBSERVE',
    observationBatchId: input.observationBatchId,
    sourceIdentityBatchDigest: input.batch.batchDigest,
    lifecycleContextKey: CORRELATION_CONTEXT_KEY,
    findingCount: input.batch.findings.length,
    occurrenceCount: input.batch.findings.length,
    distinctFingerprintCount: input.distinctFingerprintCount,
    createdLineageCount: input.distinctFingerprintCount,
    exactMatchCount: 0,
    renamedMatchCount: 0,
    replayed: false,
    observedAt: input.observedAt,
    authority: sastFindingLineageAuthority()
  };
  return {
    ...core,
    resultDigest: fixtureDigest(
      canonicalizeSastFindingLineageObservationResult(core)
    )
  };
}

function correlationId(prefix: string, value: number): string {
  return `${prefix}://${value.toString(16).padStart(64, '0')}`;
}

function capabilityOrder(left: string, right: string): number {
  const leftIndex = FINDING_CAPABILITY_ORDER.indexOf(
    left as FindingCapability
  );
  const rightIndex = FINDING_CAPABILITY_ORDER.indexOf(
    right as FindingCapability
  );
  if (leftIndex < 0 || rightIndex < 0) {
    throw new Error('Unknown correlation fixture capability.');
  }
  return leftIndex - rightIndex;
}
