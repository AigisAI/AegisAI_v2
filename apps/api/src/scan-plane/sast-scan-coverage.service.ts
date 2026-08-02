import { createHash } from 'node:crypto';

import { Injectable } from '@nestjs/common';
import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_CAPABILITIES,
  SAST_SCAN_COVERAGE_VERSION,
  SAST_SCAN_PROFILES,
  SAST_SCANNER_COVERAGE_VERSION,
  SAST_SCANNER_KINDS,
  SAST_SCANNER_RESPONSIBILITIES,
  buildFailClosedSastExternalPublicationDecision,
  buildSastScanCoverageDecisionKeyPreimage,
  buildSastScanCoverageRecordsPreimage,
  canonicalizeSastScanCoverageDecision,
  canonicalizeSastScanCoverageRejection,
  canonicalizeSastScanCoverageResult,
  canonicalizeSastScannerCoverageRecord,
  evaluateSastScanCoverageRecords,
  isSastFindingCorrelationResultShapeValid,
  isSastFindingLifecycleCoverageDecisionShapeValid,
  isSastScanCoverageDecisionShapeValid,
  isSastScanCoverageResultShapeValid,
  isSastScanCoverageScopeValid,
  isSastScannerCoverageRecordShapeValid,
  orderSastScanCoverageRejectionReasons,
  orderSastScannerCoverageReasons,
  sastScanCoverageAuthority,
  type SastCapability,
  type SastFindingCorrelationResult,
  type SastFindingLifecycleCoverageDecision,
  type SastScanCoverageDecision,
  type SastScanCoverageDecisionCore,
  type SastScanCoverageOutcome,
  type SastScanCoverageRejection,
  type SastScanCoverageRejectionCore,
  type SastScanCoverageRejectionReasonCode,
  type SastScanCoverageResult,
  type SastScanCoverageResultCore,
  type SastScannerCoverageReasonCode,
  type SastScannerCoverageRecord,
  type SastScannerCoverageRecordCore,
  type SastScannerKind
} from '@aegisai/shared';

import {
  SastFindingLifecycleCoverageGate,
  type SastFindingLifecycleCoverageVerification
} from './sast-finding-lifecycle-coverage.gate';
import {
  SastScanCoverageDurableScopeError,
  SastScanCoverageReplayConflictError,
  SastScanCoverageScannerSetError,
  SastScanCoverageSourceSetError,
  SastScanCoverageStore,
  type SastScanCoverageContext,
  type SastScannerCoverageDurableEvidence
} from './sast-scan-coverage.store';

export interface EvaluateSastScanCoverageInput {
  /**
   * The canonical T038 handoff. Caller-provided scanner, capability, stale,
   * publication, and AI authority are deliberately not accepted.
   */
  correlation: Readonly<SastFindingCorrelationResult>;
}

@Injectable()
export class SastScanCoverageService
  extends SastFindingLifecycleCoverageGate {
  constructor(private readonly store: SastScanCoverageStore) {
    super();
  }

  async evaluate(
    input: Readonly<EvaluateSastScanCoverageInput>,
    clock: () => Date = () => new Date()
  ): Promise<SastScanCoverageOutcome> {
    if (
      !isSastFindingCorrelationResultShapeValid(
        input?.correlation,
        digest
      )
    ) {
      return this.reject(['SCAN_COVERAGE_INPUT_INVALID']);
    }

    try {
      const context = await this.store.loadContext(
        input.correlation.correlationBatchId
      );
      if (!context || !isContextScopeValid(context)) {
        return this.reject([
          'SCAN_COVERAGE_DURABLE_SCOPE_INVALID'
        ]);
      }
      if (!correlationMatchesContext(input.correlation, context)) {
        return this.reject([
          'SCAN_COVERAGE_CORRELATION_INVALID'
        ]);
      }
      if (!isScannerContextValid(context)) {
        return this.reject([
          'SCAN_COVERAGE_SCANNER_SET_INVALID'
        ]);
      }

      const profile = SAST_SCAN_PROFILES[context.scope.profileId];
      const records = buildScannerRecords(context);
      if (
        records.length !== SAST_SCANNER_KINDS.length ||
        records.some(
          (record) =>
            !isSastScannerCoverageRecordShapeValid(record, digest)
        )
      ) {
        return this.reject([
          'SCAN_COVERAGE_SCANNER_SET_INVALID'
        ]);
      }
      const recordsDigest = digest(
        buildSastScanCoverageRecordsPreimage(records)
      );
      const coverageDecisionId = deterministicId(
        'sast-coverage',
        buildSastScanCoverageDecisionKeyPreimage({
          scope: context.scope,
          recordsDigest
        })
      );
      const decidedAt = context.existingDecision?.decidedAt ??
        readReferenceTime(clock);
      if (
        !isCanonicalIsoTimestamp(decidedAt) ||
        Date.parse(decidedAt) <
          Date.parse(context.correlation.correlatedAt)
      ) {
        return this.reject(['SCAN_COVERAGE_INPUT_INVALID']);
      }
      const evaluation = evaluateSastScanCoverageRecords({
        profileId: profile.id,
        records
      });
      const decisionCore: SastScanCoverageDecisionCore = {
        version: SAST_SCAN_COVERAGE_VERSION,
        coverageDecisionId,
        scope: context.scope,
        state: evaluation.state,
        requiredScanners: [...profile.requiredScanners],
        optionalScanners: [...profile.optionalScanners],
        missingRequiredScanners:
          evaluation.missingRequiredScanners,
        pendingRequiredScanners:
          evaluation.pendingRequiredScanners,
        failedRequiredScanners:
          evaluation.failedRequiredScanners,
        achievedRequiredCapabilities:
          evaluation.achievedRequiredCapabilities,
        missingRequiredCapabilities:
          evaluation.missingRequiredCapabilities,
        duplicateScanners: evaluation.duplicateScanners,
        optionalIncompleteScanners:
          evaluation.optionalIncompleteScanners,
        reasonCodes: evaluation.reasonCodes,
        recordsDigest,
        authority: sastScanCoverageAuthority(),
        decidedAt
      };
      const decision: SastScanCoverageDecision = {
        ...decisionCore,
        decisionDigest: digest(
          canonicalizeSastScanCoverageDecision(decisionCore)
        )
      };
      if (!isSastScanCoverageDecisionShapeValid(decision, digest)) {
        return this.reject([
          'SCAN_COVERAGE_SCANNER_SET_INVALID'
        ]);
      }
      const publicationDecisionId = deterministicId(
        'sast-publication',
        `${coverageDecisionId}\0${decision.decisionDigest}`
      );
      const publication =
        buildFailClosedSastExternalPublicationDecision({
          publicationDecisionId,
          decision,
          profileAiAdvisoryEligible: profile.aiAdvisoryEligible,
          digestCanonical: digest
        });

      const persisted = await this.store.persist({
        context,
        records,
        decision,
        publication
      });
      if (
        persisted.coverageDecisionId !== coverageDecisionId ||
        persisted.decisionDigest !== decision.decisionDigest ||
        persisted.publicationDecisionId !== publicationDecisionId ||
        persisted.publicationDecisionDigest !==
          publication.decisionDigest ||
        persisted.decidedAt !== decidedAt
      ) {
        return this.reject([
          'SCAN_COVERAGE_PERSISTENCE_FAILED'
        ]);
      }
      const resultCore: SastScanCoverageResultCore = {
        version: SAST_SCAN_COVERAGE_VERSION,
        outcome: 'EVALUATED',
        records,
        decision,
        publication,
        replayed: persisted.replayed
      };
      const result: SastScanCoverageResult = {
        ...resultCore,
        resultDigest: digest(
          canonicalizeSastScanCoverageResult(resultCore)
        )
      };
      if (!isSastScanCoverageResultShapeValid(result, digest)) {
        return this.reject([
          'SCAN_COVERAGE_PERSISTENCE_FAILED'
        ]);
      }
      return result;
    } catch (error) {
      return this.reject([mapStoreError(error)]);
    }
  }

  async verify(
    decision: Readonly<SastFindingLifecycleCoverageDecision>
  ): Promise<SastFindingLifecycleCoverageVerification> {
    if (
      !isSastFindingLifecycleCoverageDecisionShapeValid(
        decision,
        digest
      )
    ) {
      return 'REJECTED';
    }
    try {
      const source = await this.store.verifyLifecycleSource(decision);
      if (source !== 'MATCHED') return 'REJECTED';
      // T039 proves scanner/capability coverage only. T040 must still prove
      // latest-target freshness and comparability before lifecycle authority.
      return 'REJECTED';
    } catch {
      return 'REJECTED';
    }
  }

  private reject(
    reasons: readonly SastScanCoverageRejectionReasonCode[]
  ): SastScanCoverageRejection {
    const core: SastScanCoverageRejectionCore = {
      version: SAST_SCAN_COVERAGE_VERSION,
      outcome: 'REJECTED',
      reasonCodes: orderSastScanCoverageRejectionReasons(reasons),
      scannerRunIdsStored: false,
      artifactReferencesStored: false,
      correlationReferencesStored: false,
      publicationAttempted: false,
      secretValueStored: false
    };
    return {
      ...core,
      rejectionDigest: digest(
        canonicalizeSastScanCoverageRejection(core)
      )
    };
  }
}

function buildScannerRecords(
  context: Readonly<SastScanCoverageContext>
): SastScannerCoverageRecord[] {
  const profile = SAST_SCAN_PROFILES[context.scope.profileId];
  const evidenceByScanner = new Map(
    context.scanners.map((evidence) => [evidence.scanner, evidence])
  );
  return SAST_SCANNER_KINDS.map((scanner) => {
    const responsibilities = SAST_SCANNER_RESPONSIBILITIES[scanner];
    const authoritativeCapabilities = SAST_CAPABILITIES.filter(
      (capability) =>
        (
          responsibilities.authoritativeCapabilities as readonly SastCapability[]
        ).includes(capability)
    );
    const requiredCapabilities = profile.requiredCapabilities.filter(
      (capability) => authoritativeCapabilities.includes(capability)
    );
    const required = profile.requiredScanners.includes(scanner);
    const evidence = evidenceByScanner.get(scanner);
    const scannerCoverageId = deterministicId(
      'sast-scanner-coverage',
      `${canonicalScope(context)}\0${scanner}`
    );
    if (!evidence) {
      return finalizeRecord({
        version: SAST_SCANNER_COVERAGE_VERSION,
        scannerCoverageId,
        scanner,
        required,
        executionStatus: 'NOT_STARTED',
        authoritativeCapabilities,
        requiredCapabilities,
        achievedCapabilities: [],
        scannerRunId: null,
        scannerVersion: null,
        scannerImageDigest: null,
        wrapperDigest: null,
        ruleBundleDigest: null,
        vulnerabilityDatabaseDigest: null,
        schemaBundleDigest: null,
        normalizerBundleDigest: null,
        artifactIngestionId: null,
        artifactEnvelopeDigest: null,
        artifactDigest: null,
        dispositionDecisionId: null,
        dispositionDecisionDigest: null,
        correlationSourceId: null,
        observationBatchId: null,
        correlationSourceBindingDigest: null,
        artifactAccepted: false,
        normalizationEligible: false,
        findingObservationRequired: responsibilities.mayCreateFindings,
        findingObservationClosed: !responsibilities.mayCreateFindings,
        reasonCodes: ['SCANNER_NOT_STARTED']
      });
    }

    const reasons = scannerEvidenceReasons(
      evidence,
      required,
      responsibilities.mayCreateFindings,
      context.correlation.sourceSetValid
    );
    const findingObservationClosed =
      !responsibilities.mayCreateFindings ||
      (evidence.correlationSourceId !== null &&
        evidence.correlationSourceValid &&
        context.correlation.sourceSetValid);
    const achievedCapabilities =
      evidence.executionStatus === 'SUCCEEDED' &&
      evidence.artifactAccepted &&
      evidence.normalizationEligible &&
      findingObservationClosed &&
      reasons.length === 0
        ? authoritativeCapabilities
        : [];
    return finalizeRecord({
      version: SAST_SCANNER_COVERAGE_VERSION,
      scannerCoverageId,
      scanner,
      required,
      executionStatus: evidence.executionStatus,
      authoritativeCapabilities,
      requiredCapabilities,
      achievedCapabilities,
      scannerRunId: evidence.scannerRunId,
      scannerVersion: evidence.scannerVersion,
      scannerImageDigest: evidence.scannerImageDigest,
      wrapperDigest: evidence.wrapperDigest,
      ruleBundleDigest: evidence.ruleBundleDigest,
      vulnerabilityDatabaseDigest:
        evidence.vulnerabilityDatabaseDigest,
      schemaBundleDigest: evidence.schemaBundleDigest,
      normalizerBundleDigest: evidence.normalizerBundleDigest,
      artifactIngestionId: evidence.artifactIngestionId,
      artifactEnvelopeDigest: evidence.artifactEnvelopeDigest,
      artifactDigest: evidence.artifactDigest,
      dispositionDecisionId: evidence.dispositionDecisionId,
      dispositionDecisionDigest:
        evidence.dispositionDecisionDigest,
      correlationSourceId: evidence.correlationSourceId,
      observationBatchId: evidence.observationBatchId,
      correlationSourceBindingDigest:
        evidence.correlationSourceBindingDigest,
      artifactAccepted: evidence.artifactAccepted,
      normalizationEligible: evidence.normalizationEligible,
      findingObservationRequired: responsibilities.mayCreateFindings,
      findingObservationClosed,
      reasonCodes: reasons
    });
  });
}

function scannerEvidenceReasons(
  evidence: Readonly<SastScannerCoverageDurableEvidence>,
  required: boolean,
  findingObservationRequired: boolean,
  correlationSourceSetValid: boolean
): SastScannerCoverageReasonCode[] {
  const reasons: SastScannerCoverageReasonCode[] = [];
  switch (evidence.executionStatus) {
    case 'PENDING':
    case 'RUNNING':
      reasons.push('SCANNER_PENDING');
      break;
    case 'FAILED':
      reasons.push('SCANNER_FAILED');
      break;
    case 'TIMED_OUT':
      reasons.push('SCANNER_TIMED_OUT');
      break;
    case 'SKIPPED_BY_POLICY':
      reasons.push('SCANNER_SKIPPED');
      break;
    case 'QUARANTINED':
      reasons.push('SCANNER_QUARANTINED');
      break;
    case 'KILLED':
      reasons.push('SCANNER_KILLED');
      break;
    case 'SUCCEEDED':
      break;
  }
  if (
    evidence.requiredBinding !== required ||
    !evidence.provenanceValid
  ) {
    reasons.push('SCANNER_PROVENANCE_MISMATCH');
  }
  if (evidence.artifactIngestionId !== null) {
    if (!evidence.artifactBindingValid) {
      reasons.push('ARTIFACT_BINDING_INVALID');
    }
  } else if (evidence.executionStatus === 'SUCCEEDED') {
    reasons.push('ARTIFACT_MISSING');
  }
  if (
    evidence.executionStatus === 'SUCCEEDED' &&
    !evidence.artifactAccepted
  ) {
    reasons.push('ARTIFACT_NOT_ACCEPTED');
  }
  if (
    evidence.executionStatus === 'SUCCEEDED' &&
    !evidence.normalizationEligible
  ) {
    reasons.push('ARTIFACT_NOT_NORMALIZATION_ELIGIBLE');
  }
  if (
    findingObservationRequired &&
    evidence.executionStatus === 'SUCCEEDED'
  ) {
    if (evidence.correlationSourceId === null) {
      reasons.push('CORRELATION_SOURCE_MISSING');
    } else if (
      !evidence.correlationSourceValid ||
      !correlationSourceSetValid
    ) {
      reasons.push('CORRELATION_SOURCE_INVALID');
    }
  } else if (
    evidence.correlationSourceId !== null &&
    (!evidence.correlationSourceValid ||
      !correlationSourceSetValid)
  ) {
    reasons.push('CORRELATION_SOURCE_INVALID');
  }
  return orderSastScannerCoverageReasons(reasons);
}

function finalizeRecord(
  core: SastScannerCoverageRecordCore
): SastScannerCoverageRecord {
  return {
    ...core,
    reasonCodes: orderSastScannerCoverageReasons(core.reasonCodes),
    recordDigest: digest(
      canonicalizeSastScannerCoverageRecord({
        ...core,
        reasonCodes: orderSastScannerCoverageReasons(
          core.reasonCodes
        )
      })
    )
  };
}

function isContextScopeValid(
  context: Readonly<SastScanCoverageContext>
): boolean {
  if (!isSastScanCoverageScopeValid(context.scope)) return false;
  const profile = SAST_SCAN_PROFILES[context.scope.profileId];
  return (
    context.scope.profileDigest ===
      SAST_APPROVED_PROFILE_DIGESTS[context.scope.profileId] &&
    context.scope.lane === profile.lane &&
    context.scope.correlationBatchId ===
      context.correlation.correlationBatchId &&
    context.scope.correlationSourceSetDigest ===
      context.correlation.sourceSetDigest &&
    context.scope.lifecycleContextKey ===
      context.correlation.lifecycleContextKey &&
    isCanonicalIsoTimestamp(context.correlation.correlatedAt) &&
    Number.isInteger(context.correlation.sourceBatchCount) &&
    context.correlation.sourceBatchCount >= 0 &&
    Number.isInteger(context.correlation.occurrenceCount) &&
    context.correlation.occurrenceCount >= 0 &&
    Number.isInteger(context.correlation.edgeCount) &&
    context.correlation.edgeCount >= 0 &&
    context.correlation.exactFingerprintCount +
      context.correlation.sameDependencyCveCount +
      context.correlation.supportingEvidenceCount +
      context.correlation.possibleOverlapCount ===
      context.correlation.edgeCount
  );
}

function correlationMatchesContext(
  correlation: Readonly<SastFindingCorrelationResult>,
  context: Readonly<SastScanCoverageContext>
): boolean {
  const durable = context.correlation;
  return (
    correlation.correlationBatchId === durable.correlationBatchId &&
    correlation.sourceSetDigest === durable.sourceSetDigest &&
    correlation.lifecycleContextKey === durable.lifecycleContextKey &&
    correlation.sourceBatchCount === durable.sourceBatchCount &&
    correlation.occurrenceCount === durable.occurrenceCount &&
    correlation.edgeCount === durable.edgeCount &&
    correlation.exactFingerprintCount ===
      durable.exactFingerprintCount &&
    correlation.sameDependencyCveCount ===
      durable.sameDependencyCveCount &&
    correlation.supportingEvidenceCount ===
      durable.supportingEvidenceCount &&
    correlation.possibleOverlapCount ===
      durable.possibleOverlapCount &&
    correlation.correlatedAt === durable.correlatedAt
  );
}

function isScannerContextValid(
  context: Readonly<SastScanCoverageContext>
): boolean {
  const scanners = new Set<SastScannerKind>();
  for (const evidence of context.scanners) {
    if (
      !SAST_SCANNER_KINDS.includes(evidence.scanner) ||
      scanners.has(evidence.scanner) ||
      !evidence.scannerRunId
    ) {
      return false;
    }
    scanners.add(evidence.scanner);
  }
  return context.scanners.length <= SAST_SCANNER_KINDS.length;
}

function canonicalScope(
  context: Readonly<SastScanCoverageContext>
): string {
  return JSON.stringify([
    context.scope.tenantId,
    context.scope.repositoryBindingId,
    context.scope.scanRequestId,
    context.scope.attemptId,
    context.scope.correlationBatchId,
    context.scope.correlationSourceSetDigest,
    context.scope.planDigest,
    context.scope.scannerSetDigest
  ]);
}

function mapStoreError(
  error: unknown
): SastScanCoverageRejectionReasonCode {
  if (error instanceof SastScanCoverageDurableScopeError) {
    return 'SCAN_COVERAGE_DURABLE_SCOPE_INVALID';
  }
  if (error instanceof SastScanCoverageScannerSetError) {
    return 'SCAN_COVERAGE_SCANNER_SET_INVALID';
  }
  if (error instanceof SastScanCoverageSourceSetError) {
    return 'SCAN_COVERAGE_SOURCE_SET_INCOMPLETE';
  }
  if (error instanceof SastScanCoverageReplayConflictError) {
    return 'SCAN_COVERAGE_REPLAY_CONFLICT';
  }
  return 'SCAN_COVERAGE_PERSISTENCE_FAILED';
}

function readReferenceTime(clock: () => Date): string {
  try {
    const value = clock();
    return value instanceof Date && Number.isFinite(value.getTime())
      ? value.toISOString()
      : '';
  } catch {
    return '';
  }
}

function deterministicId(prefix: string, value: string): string {
  return `${prefix}://${digestHex(value)}`;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${digestHex(value)}`;
}

function digestHex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function isCanonicalIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return (
    Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString() === value
  );
}
