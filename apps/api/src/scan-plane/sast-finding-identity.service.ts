import { createHash } from 'node:crypto';
import { setImmediate as yieldToEventLoop } from 'node:timers/promises';

import { Injectable } from '@nestjs/common';
import {
  SAST_FINDING_FINGERPRINT_VERSION,
  SAST_FINDING_IDENTITY_LIMITS,
  SAST_FINDING_IDENTITY_VERSION,
  buildFindingFingerprintPreimage,
  canonicalizeSastFindingFingerprintDecision,
  canonicalizeSastFindingIdentityRejection,
  canonicalizeSastFingerprintedFindingBatch,
  isSastFingerprintedFindingBatchShapeValid,
  isSastFingerprintedFindingShapeValid,
  isSastSecretRedactionBatchShapeValid,
  orderSastFindingIdentityRejectionReasons,
  toSastFindingFingerprintInput,
  type SastFindingFingerprintDecision,
  type SastFindingFingerprintDecisionCore,
  type SastFindingIdentityRejectionCore,
  type SastFindingIdentityRejectionReasonCode,
  type SastFindingIdentityResult,
  type SastFingerprintedFinding,
  type SastFingerprintedFindingBatchCore,
  type SastSecretRedactedFindingCandidate,
  type SastSecretRedactionBatch
} from '@aegisai/shared';

export interface SastFindingIdentityInput {
  /**
   * One complete, still-active T035 handoff. No pre-redaction candidate or
   * scanner artifact is accepted at this boundary.
   */
  batch: Readonly<SastSecretRedactionBatch>;
}

@Injectable()
export class SastFindingIdentityService {
  async construct(
    input: Readonly<SastFindingIdentityInput>,
    clock: () => Date = () => new Date()
  ): Promise<SastFindingIdentityResult> {
    if (!isNotOverFindingLimit(input?.batch)) {
      return this.reject(['FINDING_IDENTITY_INPUT_INVALID']);
    }
    if (
      !isSastSecretRedactionBatchShapeValid(input?.batch, digest)
    ) {
      return this.reject(['FINDING_IDENTITY_INPUT_INVALID']);
    }
    const source = input.batch;
    const firstReferenceTime = readReferenceTime(clock);
    if (!Number.isFinite(firstReferenceTime)) {
      return this.reject(['FINDING_IDENTITY_RETENTION_INVALID']);
    }
    const retentionExpiresAt = Date.parse(
      source.retentionExpiresAt
    );
    if (firstReferenceTime >= retentionExpiresAt) {
      return this.reject(['FINDING_IDENTITY_RETENTION_EXPIRED']);
    }

    const findings: SastFingerprintedFinding[] = [];
    const preimageByFingerprint = new Map<string, string>();
    for (
      let index = 0;
      index < source.findings.length;
      index += 1
    ) {
      if (
        index > 0 &&
        index %
          SAST_FINDING_IDENTITY_LIMITS.yieldFindingInterval ===
          0
      ) {
        await this.yieldEventLoop();
      }
      const sourceFinding = source.findings[
        index
      ] as SastSecretRedactedFindingCandidate;
      const fingerprintInput =
        toSastFindingFingerprintInput(sourceFinding);
      const fingerprintPreimage =
        buildFindingFingerprintPreimage(fingerprintInput);
      const stableFingerprint =
        this.digestFingerprint(fingerprintPreimage);
      const previousPreimage =
        preimageByFingerprint.get(stableFingerprint);
      if (
        previousPreimage !== undefined &&
        previousPreimage !== fingerprintPreimage
      ) {
        return this.reject([
          'FINDING_IDENTITY_FINGERPRINT_COLLISION'
        ]);
      }
      preimageByFingerprint.set(
        stableFingerprint,
        fingerprintPreimage
      );

      const decisionCore: SastFindingFingerprintDecisionCore = {
        version: SAST_FINDING_FINGERPRINT_VERSION,
        ...fingerprintInput,
        stableFingerprint,
        sourceRedactionDecisionDigest:
          sourceFinding.redaction.decisionDigest,
        unstableCoordinatesIncluded: false,
        scannerMatchIdentityAuthoritative: false,
        fingerprintPreimageStored: false
      };
      const decisionDigest = digest(
        canonicalizeSastFindingFingerprintDecision(decisionCore)
      );
      const fingerprint: SastFindingFingerprintDecision = {
        ...decisionCore,
        decisionDigest,
        decisionRef:
          `fingerprint://${SAST_FINDING_FINGERPRINT_VERSION}/${decisionDigest.slice(
            'sha256:'.length
          )}`
      };
      const finding = cloneFingerprintedFinding(
        sourceFinding,
        fingerprint
      );
      if (
        !isSastFingerprintedFindingShapeValid(
          finding,
          digest,
          (preimage) => this.digestFingerprint(preimage)
        )
      ) {
        return this.reject(['FINDING_IDENTITY_OUTPUT_INVALID']);
      }
      findings.push(finding);
    }

    const secondReferenceTime = readReferenceTime(clock);
    if (
      !Number.isFinite(secondReferenceTime) ||
      secondReferenceTime < firstReferenceTime
    ) {
      return this.reject(['FINDING_IDENTITY_RETENTION_INVALID']);
    }
    if (secondReferenceTime >= retentionExpiresAt) {
      return this.reject(['FINDING_IDENTITY_RETENTION_EXPIRED']);
    }

    const distinctFingerprintCount =
      preimageByFingerprint.size;
    const batchCore: SastFingerprintedFindingBatchCore = {
      version: SAST_FINDING_IDENTITY_VERSION,
      outcome: 'FINGERPRINTED',
      sourceRedactionVersion: source.version,
      sourceAdapterVersion: source.sourceAdapterVersion,
      artifactSchema: source.artifactSchema,
      artifactSchemaVersion: source.artifactSchemaVersion,
      ingestionId: source.ingestionId,
      scope: {
        tenantId: source.scope.tenantId,
        repositoryBindingId:
          source.scope.repositoryBindingId,
        scanRequestId: source.scope.scanRequestId,
        attemptId: source.scope.attemptId,
        scannerRunId: source.scope.scannerRunId
      },
      scannerRunId: source.scannerRunId,
      scanner: source.scanner,
      scannerVersion: source.scannerVersion,
      scannerImageDigest: source.scannerImageDigest,
      ruleBundleDigest: source.ruleBundleDigest,
      ...('vulnerabilityDatabaseDigest' in source
        ? {
            vulnerabilityDatabaseDigest:
              source.vulnerabilityDatabaseDigest
          }
        : {}),
      planDigest: source.planDigest,
      canonicalScanKey: source.canonicalScanKey,
      preflightAttestationRef:
        source.preflightAttestationRef,
      preflightInventoryDigest:
        source.preflightInventoryDigest,
      lane: source.lane,
      commitSha: source.commitSha,
      envelopeDigest: source.envelopeDigest,
      artifactDigest: source.artifactDigest,
      schemaBundleDigest: source.schemaBundleDigest,
      normalizerBundleDigest:
        source.normalizerBundleDigest,
      validationResultDigest:
        source.validationResultDigest,
      dispositionDecisionDigest:
        source.dispositionDecisionDigest,
      retentionExpiresAt: source.retentionExpiresAt,
      sourceRedactionBatchDigest: source.batchDigest,
      findings,
      sourceRedaction: {
        ...source.redaction,
        detectorKinds: [...source.redaction.detectorKinds]
      },
      identity: {
        version: SAST_FINDING_IDENTITY_VERSION,
        fingerprintVersion:
          SAST_FINDING_FINGERPRINT_VERSION,
        findingCount: findings.length,
        distinctFingerprintCount,
        repeatedOccurrenceCount:
          findings.length - distinctFingerprintCount,
        fingerprintPreimagesStored: false,
        unstableCoordinatesIncluded: false,
        scannerMatchIdentityAuthoritative: false,
        rawSourceCandidatesStored: false,
        secretValuesStored: false
      },
      authority: {
        normalizedFindingPersistenceEligible: true,
        occurrenceAuthority: false,
        lifecycleAuthority: false,
        correlationAuthority: false,
        coverageAuthority: false,
        evidenceAuthority: false,
        policyAuthority: false,
        publicationAuthority: false,
        aiPayloadEligible: false
      },
      durablePersistenceAllowed: true
    };
    const batch = {
      ...batchCore,
      batchDigest: digest(
        canonicalizeSastFingerprintedFindingBatch(batchCore)
      )
    };
    if (
      !isSastFingerprintedFindingBatchShapeValid(
        batch,
        digest,
        (preimage) => this.digestFingerprint(preimage)
      )
    ) {
      return this.reject(['FINDING_IDENTITY_OUTPUT_INVALID']);
    }
    return {
      outcome: 'FINGERPRINTED',
      batch
    };
  }

  protected async yieldEventLoop(): Promise<void> {
    await yieldToEventLoop();
  }

  protected digestFingerprint(
    fingerprintPreimage: string
  ): `sha256:${string}` {
    return digest(fingerprintPreimage);
  }

  private reject(
    reasons: Iterable<SastFindingIdentityRejectionReasonCode>
  ): SastFindingIdentityResult {
    const core: SastFindingIdentityRejectionCore = {
      version: SAST_FINDING_IDENTITY_VERSION,
      outcome: 'REJECTED',
      reasonCodes:
        orderSastFindingIdentityRejectionReasons(reasons),
      sourceBatchDigestStored: false,
      fingerprintPreimageStored: false,
      sourceCandidateStored: false,
      secretValueStored: false
    };
    return {
      ...core,
      rejectionDigest: digest(
        canonicalizeSastFindingIdentityRejection(core)
      )
    };
  }
}

function isNotOverFindingLimit(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return true;
  }
  const findings = (value as { findings?: unknown }).findings;
  return (
    !Array.isArray(findings) ||
    findings.length <=
      SAST_FINDING_IDENTITY_LIMITS.maximumFindings
  );
}

function cloneFingerprintedFinding(
  source: Readonly<SastSecretRedactedFindingCandidate>,
  fingerprint: Readonly<SastFindingFingerprintDecision>
): SastFingerprintedFinding {
  const common = {
    ...source,
    cweIds: [...source.cweIds],
    cveIds: [...source.cveIds],
    location: { ...source.location },
    identityMaterial: { ...source.identityMaterial },
    provenance: { ...source.provenance },
    notes: [...source.notes],
    redaction: {
      ...source.redaction,
      redactedFields: [...source.redaction.redactedFields],
      detectorKinds: [...source.redaction.detectorKinds]
    },
    fingerprint: { ...fingerprint },
    durablePersistenceAllowed: true as const
  };
  if (!('trivy' in source)) {
    return common as SastFingerprintedFinding;
  }
  return {
    ...common,
    scannerDisposition: { ...source.scannerDisposition },
    trivy: { ...source.trivy }
  } as SastFingerprintedFinding;
}

function readReferenceTime(clock: () => Date): number {
  try {
    const value = clock();
    return value instanceof Date ? value.getTime() : Number.NaN;
  } catch {
    return Number.NaN;
  }
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}
