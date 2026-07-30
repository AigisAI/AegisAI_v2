import { createHash } from 'node:crypto';
import { setImmediate as yieldToEventLoop } from 'node:timers/promises';

import { Injectable } from '@nestjs/common';
import {
  SAST_FINDING_LINEAGE_LIMITS,
  SAST_FINDING_LINEAGE_VERSION,
  buildSastFindingLifecycleContextPreimage,
  buildSastFindingRenameCandidate,
  canonicalizeSastFindingLifecycleReconciliationResult,
  canonicalizeSastFindingLineageObservationResult,
  canonicalizeSastFindingLineageRejection,
  isSastFindingLifecycleCoverageDecisionShapeValid,
  isSastFindingLifecycleContextInputValid,
  isSastFindingLifecycleReconciliationResultShapeValid,
  isSastFindingLineageObservationResultShapeValid,
  isSastFindingRenameAttestationShapeValid,
  isSastFingerprintedFindingBatchShapeValid,
  orderSastFindingLineageRejectionReasons,
  orderSastFindingRenameCandidates,
  sastFindingLineageAuthority,
  type SastFindingLifecycleCoverageDecision,
  type SastFindingLifecycleReconciliationOutcome,
  type SastFindingLifecycleReconciliationResult,
  type SastFindingLifecycleReconciliationResultCore,
  type SastFindingLineageObservationOutcome,
  type SastFindingLineageObservationResult,
  type SastFindingLineageObservationResultCore,
  type SastFindingLineageOperation,
  type SastFindingLineageRejection,
  type SastFindingLineageRejectionCore,
  type SastFindingLineageRejectionReasonCode,
  type SastFindingRenameAttestation,
  type SastFindingRenameCandidate,
  type SastFingerprintedFindingBatch
} from '@aegisai/shared';

import {
  SastFindingLifecycleCoverageGate
} from './sast-finding-lifecycle-coverage.gate';
import {
  SastFindingLineageDurableScopeError,
  SastFindingLineageObservationIncompleteError,
  SastFindingLineageReconciliationOrderError,
  SastFindingLineageRenameAmbiguousError,
  SastFindingLineageReplayConflictError,
  SastFindingLineageStore,
  type SastFindingLineageScanContext
} from './sast-finding-lineage.store';
import {
  SastFindingRenameAttestationVerifier
} from './sast-finding-rename-attestation.verifier';

export interface ObserveSastFindingLineageInput {
  /**
   * The complete T036 durable handoff. Individual findings and raw scanner
   * payloads are intentionally not accepted at this persistence boundary.
   */
  batch: Readonly<SastFingerprintedFindingBatch>;
  renameAttestation?: Readonly<SastFindingRenameAttestation>;
}

export interface ReconcileSastFindingLifecycleInput {
  /**
   * T039 calculates this decision. T037 only verifies and applies it.
   */
  coverageDecision: Readonly<SastFindingLifecycleCoverageDecision>;
}

@Injectable()
export class SastFindingLineageService {
  constructor(
    private readonly store: SastFindingLineageStore,
    private readonly renameVerifier:
      SastFindingRenameAttestationVerifier,
    private readonly coverageGate:
      SastFindingLifecycleCoverageGate
  ) {}

  async observe(
    input: Readonly<ObserveSastFindingLineageInput>,
    clock: () => Date = () => new Date()
  ): Promise<SastFindingLineageObservationOutcome> {
    if (!isNotOverFindingLimit(input?.batch)) {
      return this.reject('OBSERVE', [
        'FINDING_LINEAGE_INPUT_INVALID'
      ]);
    }
    if (
      !isSastFingerprintedFindingBatchShapeValid(
        input?.batch,
        digest,
        digest
      )
    ) {
      return this.reject('OBSERVE', [
        'FINDING_LINEAGE_INPUT_INVALID'
      ]);
    }
    const batch = input.batch;
    const firstReferenceTime = readReferenceTime(clock);
    const retentionExpiresAt = Date.parse(batch.retentionExpiresAt);
    if (
      !Number.isFinite(firstReferenceTime) ||
      !Number.isFinite(retentionExpiresAt)
    ) {
      return this.reject('OBSERVE', [
        'FINDING_LINEAGE_RETENTION_INVALID'
      ]);
    }
    if (firstReferenceTime >= retentionExpiresAt) {
      return this.reject('OBSERVE', [
        'FINDING_LINEAGE_RETENTION_EXPIRED'
      ]);
    }

    try {
      const context = await this.store.loadObservationContext(
        batch.scope
      );
      if (!context || !observationContextMatches(batch, context)) {
        return this.reject('OBSERVE', [
          'FINDING_LINEAGE_DURABLE_SCOPE_INVALID'
        ]);
      }
      const lifecycleContext = {
        tenantId: context.scope.tenantId,
        repositoryBindingId:
          context.scope.repositoryBindingId,
        targetRef: context.targetRef
      };
      if (
        !isSastFindingLifecycleContextInputValid(
          lifecycleContext
        )
      ) {
        return this.reject('OBSERVE', [
          'FINDING_LINEAGE_DURABLE_SCOPE_INVALID'
        ]);
      }
      const lifecycleContextKey = digest(
        buildSastFindingLifecycleContextPreimage(
          lifecycleContext
        )
      );

      let renameCandidates: SastFindingRenameCandidate[] = [];
      if (input.renameAttestation !== undefined) {
        const renameResult = await this.prepareRenameCandidates(
          batch,
          context,
          lifecycleContextKey,
          input.renameAttestation,
          firstReferenceTime
        );
        if ('rejection' in renameResult) {
          return renameResult.rejection;
        }
        renameCandidates = renameResult.candidates;
      } else if (
        !(await this.revalidateDistinctFingerprintCount(batch))
      ) {
        return this.reject('OBSERVE', [
          'FINDING_LINEAGE_INPUT_INVALID'
        ]);
      }

      const secondReferenceTime = readReferenceTime(clock);
      if (
        !Number.isFinite(secondReferenceTime) ||
        secondReferenceTime < firstReferenceTime
      ) {
        return this.reject('OBSERVE', [
          'FINDING_LINEAGE_RETENTION_INVALID'
        ]);
      }
      if (secondReferenceTime >= retentionExpiresAt) {
        return this.reject('OBSERVE', [
          'FINDING_LINEAGE_RETENTION_EXPIRED'
        ]);
      }

      const observationBatchId =
        `finding-observation://${digestHex(
          `${SAST_FINDING_LINEAGE_VERSION}\0${batch.batchDigest}\0${lifecycleContextKey}`
        )}`;
      const persisted = await this.store.observe({
        observationBatchId,
        lifecycleContextKey,
        observedAt: new Date(secondReferenceTime).toISOString(),
        batch,
        context,
        ...(input.renameAttestation
          ? {
              renameAttestationDigest:
                input.renameAttestation.attestationDigest,
              renameAttestation: input.renameAttestation
            }
          : {}),
        renameCandidates
      });
      if (
        persisted.observationBatchId !== observationBatchId ||
        persisted.sourceIdentityBatchDigest !==
          batch.batchDigest ||
        persisted.lifecycleContextKey !==
          lifecycleContextKey ||
        persisted.findingCount !== batch.findings.length ||
        persisted.occurrenceCount !== batch.findings.length ||
        persisted.distinctFingerprintCount !==
          batch.identity.distinctFingerprintCount
      ) {
        return this.reject('OBSERVE', [
          'FINDING_LINEAGE_PERSISTENCE_FAILED'
        ]);
      }
      const core: SastFindingLineageObservationResultCore = {
        version: SAST_FINDING_LINEAGE_VERSION,
        outcome: 'OBSERVED',
        operation: 'OBSERVE',
        ...persisted,
        authority: sastFindingLineageAuthority()
      };
      const result: SastFindingLineageObservationResult = {
        ...core,
        resultDigest: digest(
          canonicalizeSastFindingLineageObservationResult(core)
        )
      };
      if (
        !isSastFindingLineageObservationResultShapeValid(
          result,
          digest
        )
      ) {
        return this.reject('OBSERVE', [
          'FINDING_LINEAGE_PERSISTENCE_FAILED'
        ]);
      }
      return result;
    } catch (error) {
      return this.reject('OBSERVE', [
        mapPersistenceError(error)
      ]);
    }
  }

  async reconcile(
    input: Readonly<ReconcileSastFindingLifecycleInput>,
    clock: () => Date = () => new Date()
  ): Promise<SastFindingLifecycleReconciliationOutcome> {
    const coarseReasons = inspectCoverageState(
      input?.coverageDecision
    );
    if (coarseReasons.length > 0) {
      return this.reject('RECONCILE', coarseReasons);
    }
    if (
      !isSastFindingLifecycleCoverageDecisionShapeValid(
        input?.coverageDecision,
        digest
      )
    ) {
      return this.reject('RECONCILE', [
        'FINDING_LINEAGE_COVERAGE_DECISION_INVALID'
      ]);
    }
    const decision = input.coverageDecision;
    const verification = await safelyVerifyCoverage(
      this.coverageGate,
      decision
    );
    if (verification === 'UNAVAILABLE') {
      return this.reject('RECONCILE', [
        'FINDING_LINEAGE_COVERAGE_AUTHORITY_UNAVAILABLE'
      ]);
    }
    if (verification !== 'VERIFIED') {
      return this.reject('RECONCILE', [
        'FINDING_LINEAGE_COVERAGE_DECISION_INVALID'
      ]);
    }

    const referenceTime = readReferenceTime(clock);
    if (
      !Number.isFinite(referenceTime) ||
      referenceTime < Date.parse(decision.decidedAt)
    ) {
      return this.reject('RECONCILE', [
        'FINDING_LINEAGE_COVERAGE_DECISION_INVALID'
      ]);
    }

    try {
      const context = await this.store.loadReconciliationContext({
        tenantId: decision.tenantId,
        repositoryBindingId: decision.repositoryBindingId,
        scanRequestId: decision.scanRequestId,
        attemptId: decision.attemptId
      });
      if (!context || !reconciliationContextMatches(decision, context)) {
        return this.reject('RECONCILE', [
          'FINDING_LINEAGE_DURABLE_SCOPE_INVALID'
        ]);
      }
      const lifecycleContext = {
        tenantId: context.tenantId,
        repositoryBindingId: context.repositoryBindingId,
        targetRef: context.targetRef
      };
      if (
        !isSastFindingLifecycleContextInputValid(
          lifecycleContext
        )
      ) {
        return this.reject('RECONCILE', [
          'FINDING_LINEAGE_DURABLE_SCOPE_INVALID'
        ]);
      }
      const expectedContextKey = digest(
        buildSastFindingLifecycleContextPreimage(
          lifecycleContext
        )
      );
      if (expectedContextKey !== decision.lifecycleContextKey) {
        return this.reject('RECONCILE', [
          'FINDING_LINEAGE_DURABLE_SCOPE_INVALID'
        ]);
      }

      const reconciliationId =
        `finding-reconciliation://${digestHex(
          `${SAST_FINDING_LINEAGE_VERSION}\0${decision.decisionDigest}`
        )}`;
      const persisted = await this.store.reconcile({
        reconciliationId,
        reconciledAt: new Date(referenceTime).toISOString(),
        decision,
        context
      });
      if (
        persisted.reconciliationId !== reconciliationId ||
        persisted.coverageDecisionDigest !==
          decision.decisionDigest ||
        persisted.lifecycleContextKey !==
          decision.lifecycleContextKey ||
        persisted.sequence !== decision.sequence ||
        persisted.eligibleLineageCount !==
          decision.eligibleLineageIds.length
      ) {
        return this.reject('RECONCILE', [
          'FINDING_LINEAGE_PERSISTENCE_FAILED'
        ]);
      }
      const core: SastFindingLifecycleReconciliationResultCore = {
        version: SAST_FINDING_LINEAGE_VERSION,
        outcome: 'RECONCILED',
        operation: 'RECONCILE',
        ...persisted,
        authority: sastFindingLineageAuthority()
      };
      const result: SastFindingLifecycleReconciliationResult = {
        ...core,
        resultDigest: digest(
          canonicalizeSastFindingLifecycleReconciliationResult(core)
        )
      };
      if (
        !isSastFindingLifecycleReconciliationResultShapeValid(
          result,
          digest
        )
      ) {
        return this.reject('RECONCILE', [
          'FINDING_LINEAGE_PERSISTENCE_FAILED'
        ]);
      }
      return result;
    } catch (error) {
      return this.reject('RECONCILE', [
        mapPersistenceError(error)
      ]);
    }
  }

  protected async yieldEventLoop(): Promise<void> {
    await yieldToEventLoop();
  }

  private async prepareRenameCandidates(
    batch: Readonly<SastFingerprintedFindingBatch>,
    context: Readonly<SastFindingLineageScanContext>,
    lifecycleContextKey: `sha256:${string}`,
    attestation: Readonly<SastFindingRenameAttestation>,
    referenceTime: number
  ): Promise<
    | { candidates: SastFindingRenameCandidate[] }
    | { rejection: SastFindingLineageRejection }
  > {
    if (
      !isSastFindingRenameAttestationShapeValid(
        attestation,
        digest
      ) ||
      attestation.tenantId !== context.scope.tenantId ||
      attestation.repositoryBindingId !==
        context.scope.repositoryBindingId ||
      attestation.lifecycleContextKey !== lifecycleContextKey ||
      attestation.toScanRequestId !==
        context.scope.scanRequestId ||
      attestation.toCommitSha !== context.commitSha ||
      attestation.profileId !== context.profileId ||
      attestation.profileDigest !== context.profileDigest ||
      Date.parse(attestation.issuedAt) > referenceTime
    ) {
      return {
        rejection: this.reject('OBSERVE', [
          'FINDING_LINEAGE_RENAME_ATTESTATION_INVALID'
        ])
      };
    }
    const verification = await safelyVerifyRename(
      this.renameVerifier,
      attestation
    );
    if (verification === 'UNAVAILABLE') {
      return {
        rejection: this.reject('OBSERVE', [
          'FINDING_LINEAGE_RENAME_AUTHORITY_UNAVAILABLE'
        ])
      };
    }
    if (verification !== 'VERIFIED') {
      return {
        rejection: this.reject('OBSERVE', [
          'FINDING_LINEAGE_RENAME_ATTESTATION_INVALID'
        ])
      };
    }

    const entryByTargetPath = new Map(
      attestation.entries.map((entry) => [
        entry.toNormalizedPath,
        entry
      ])
    );
    const candidates: SastFindingRenameCandidate[] = [];
    const identityKeys = new Set<string>();
    for (let index = 0; index < batch.findings.length; index += 1) {
      if (
        index > 0 &&
        index %
          SAST_FINDING_LINEAGE_LIMITS.yieldFindingInterval ===
          0
      ) {
        await this.yieldEventLoop();
      }
      const finding = batch.findings[index];
      if (!finding) {
        return {
          rejection: this.reject('OBSERVE', [
            'FINDING_LINEAGE_INPUT_INVALID'
          ])
        };
      }
      identityKeys.add(
        `${finding.capability}\0${finding.fingerprint.stableFingerprint}`
      );
      const entry = entryByTargetPath.get(
        finding.fingerprint.normalizedPath
      );
      if (!entry) continue;
      const candidate = buildSastFindingRenameCandidate(
        finding,
        entry,
        digest
      );
      if (!candidate) {
        return {
          rejection: this.reject('OBSERVE', [
            'FINDING_LINEAGE_RENAME_ATTESTATION_INVALID'
          ])
        };
      }
      candidates.push(candidate);
    }
    if (
      identityKeys.size !==
      batch.identity.distinctFingerprintCount
    ) {
      return {
        rejection: this.reject('OBSERVE', [
          'FINDING_LINEAGE_INPUT_INVALID'
        ])
      };
    }
    const orderedCandidates =
      orderSastFindingRenameCandidates(candidates);
    if (orderedCandidates.length === 0) {
      return {
        rejection: this.reject('OBSERVE', [
          'FINDING_LINEAGE_RENAME_ATTESTATION_INVALID'
        ])
      };
    }
    return { candidates: orderedCandidates };
  }

  private reject(
    operation: SastFindingLineageOperation,
    reasons: Iterable<SastFindingLineageRejectionReasonCode>
  ): SastFindingLineageRejection {
    const core: SastFindingLineageRejectionCore = {
      version: SAST_FINDING_LINEAGE_VERSION,
      outcome: 'REJECTED',
      operation,
      reasonCodes:
        orderSastFindingLineageRejectionReasons(reasons),
      sourceBatchDigestStored: false,
      sourceFindingStored: false,
      renamePathsStored: false,
      eligibleLineageIdsStored: false,
      secretValueStored: false
    };
    return {
      ...core,
      rejectionDigest: digest(
        canonicalizeSastFindingLineageRejection(core)
      )
    };
  }

  private async revalidateDistinctFingerprintCount(
    batch: Readonly<SastFingerprintedFindingBatch>
  ): Promise<boolean> {
    const identities = new Set<string>();
    for (let index = 0; index < batch.findings.length; index += 1) {
      if (
        index > 0 &&
        index %
          SAST_FINDING_LINEAGE_LIMITS.yieldFindingInterval ===
          0
      ) {
        await this.yieldEventLoop();
      }
      const finding = batch.findings[index];
      if (!finding) return false;
      identities.add(
        `${finding.capability}\0${finding.fingerprint.stableFingerprint}`
      );
    }
    return (
      identities.size ===
      batch.identity.distinctFingerprintCount
    );
  }
}

function observationContextMatches(
  batch: Readonly<SastFingerprintedFindingBatch>,
  context: Readonly<SastFindingLineageScanContext>
): boolean {
  return (
    batch.scope.tenantId === context.scope.tenantId &&
    batch.scope.repositoryBindingId ===
      context.scope.repositoryBindingId &&
    batch.scope.scanRequestId === context.scope.scanRequestId &&
    batch.scope.attemptId === context.scope.attemptId &&
    batch.scope.scannerRunId === context.scope.scannerRunId &&
    batch.scannerRunId === context.scope.scannerRunId &&
    batch.scanner === context.scanner &&
    batch.lane === context.lane &&
    batch.commitSha === context.commitSha &&
    batch.canonicalScanKey === context.canonicalScanKey &&
    batch.planDigest === context.planDigest &&
    batch.ingestionId === context.source.ingestionId &&
    batch.scannerVersion === context.source.scannerVersion &&
    batch.scannerImageDigest ===
      context.source.scannerImageDigest &&
    batch.ruleBundleDigest === context.source.ruleBundleDigest &&
    batch.vulnerabilityDatabaseDigest ===
      context.source.vulnerabilityDatabaseDigest &&
    batch.schemaBundleDigest ===
      context.source.schemaBundleDigest &&
    batch.normalizerBundleDigest ===
      context.source.normalizerBundleDigest &&
    batch.preflightAttestationRef ===
      context.source.preflightAttestationRef &&
    batch.preflightInventoryDigest ===
      context.source.preflightInventoryDigest &&
    batch.artifactSchema === context.source.artifactSchema &&
    batch.artifactSchemaVersion ===
      context.source.artifactSchemaVersion &&
    batch.envelopeDigest === context.source.envelopeDigest &&
    batch.artifactDigest === context.source.artifactDigest &&
    batch.validationResultDigest ===
      context.source.validationResultDigest &&
    batch.dispositionDecisionDigest ===
      context.source.dispositionDecisionDigest &&
    batch.retentionExpiresAt ===
      context.source.retentionExpiresAt
  );
}

function reconciliationContextMatches(
  decision: Readonly<SastFindingLifecycleCoverageDecision>,
  context: Readonly<{
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    commitSha: string;
    canonicalScanKey: string;
    planDigest: string;
    profileId: string;
    profileDigest: string;
  }>
): boolean {
  return (
    decision.tenantId === context.tenantId &&
    decision.repositoryBindingId === context.repositoryBindingId &&
    decision.scanRequestId === context.scanRequestId &&
    decision.attemptId === context.attemptId &&
    decision.commitSha === context.commitSha &&
    decision.canonicalScanKey === context.canonicalScanKey &&
    decision.planDigest === context.planDigest &&
    decision.profileId === context.profileId &&
    decision.profileDigest === context.profileDigest
  );
}

function inspectCoverageState(
  value: unknown
): SastFindingLineageRejectionReasonCode[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return ['FINDING_LINEAGE_COVERAGE_DECISION_INVALID'];
  }
  const candidate = value as {
    state?: unknown;
    stale?: unknown;
    comparable?: unknown;
  };
  const reasons: SastFindingLineageRejectionReasonCode[] = [];
  if (candidate.comparable !== true) {
    reasons.push('FINDING_LINEAGE_SCAN_NOT_COMPARABLE');
  }
  if (candidate.stale !== false) {
    reasons.push('FINDING_LINEAGE_SCAN_STALE');
  }
  if (candidate.state !== 'COMPLETE') {
    reasons.push('FINDING_LINEAGE_SCAN_INCOMPLETE');
  }
  return reasons;
}

function mapPersistenceError(
  error: unknown
): SastFindingLineageRejectionReasonCode {
  if (error instanceof SastFindingLineageDurableScopeError) {
    return 'FINDING_LINEAGE_DURABLE_SCOPE_INVALID';
  }
  if (error instanceof SastFindingLineageRenameAmbiguousError) {
    return 'FINDING_LINEAGE_RENAME_AMBIGUOUS';
  }
  if (error instanceof SastFindingLineageReplayConflictError) {
    return 'FINDING_LINEAGE_REPLAY_CONFLICT';
  }
  if (
    error instanceof SastFindingLineageReconciliationOrderError
  ) {
    return 'FINDING_LINEAGE_RECONCILIATION_OUT_OF_ORDER';
  }
  if (
    error instanceof SastFindingLineageObservationIncompleteError
  ) {
    return 'FINDING_LINEAGE_OBSERVATION_INCOMPLETE';
  }
  return 'FINDING_LINEAGE_PERSISTENCE_FAILED';
}

async function safelyVerifyRename(
  verifier: SastFindingRenameAttestationVerifier,
  attestation: Readonly<SastFindingRenameAttestation>
) {
  try {
    return await verifier.verify(attestation);
  } catch {
    return 'REJECTED' as const;
  }
}

async function safelyVerifyCoverage(
  gate: SastFindingLifecycleCoverageGate,
  decision: Readonly<SastFindingLifecycleCoverageDecision>
) {
  try {
    return await gate.verify(decision);
  } catch {
    return 'REJECTED' as const;
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
      SAST_FINDING_LINEAGE_LIMITS.maximumFindings
  );
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
  return `sha256:${digestHex(value)}`;
}

function digestHex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
