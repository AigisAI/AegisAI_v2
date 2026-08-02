import { createHash, randomInt } from 'node:crypto';
import { setTimeout as wait } from 'node:timers/promises';

import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_CAPABILITIES,
  SAST_FINDING_CORRELATION_SOURCE_VERSION,
  SAST_SCAN_PROFILES,
  SAST_SCANNER_KINDS,
  SAST_SCANNER_RESPONSIBILITIES,
  buildFailClosedSastExternalPublicationDecision,
  buildSastScanCoverageDecisionKeyPreimage,
  buildSastScanCoverageRecordsPreimage,
  buildSastFindingCorrelationSourceSetPreimage,
  buildSastScanPlanDigestPreimage,
  canonicalizeScannerArtifactEnvelope,
  canonicalizeSastArtifactDispositionDecision,
  isScannerArtifactEnvelopeBoundToPlan,
  isSastArtifactDispositionDecisionShapeValid,
  isSastExternalPublicationDecisionShapeValid,
  isSastFindingCorrelationSourceBindingShapeValid,
  isSastScanCoverageDecisionShapeValid,
  isSastScannerCoverageRecordShapeValid,
  isSastScanPlanValid,
  evaluateSastScanCoverageRecords,
  orderSastScannerCoverageReasons,
  type ScannerArtifactEnvelope,
  type ScannerExecutionStatus,
  type SastArtifactDispositionDecision,
  type SastCapability,
  type SastFindingCorrelationSourceBinding,
  type SastFindingLifecycleCoverageDecision,
  type SastProfileId,
  type SastScanCoverageDecision,
  type SastScanPlan,
  type SastScannerCoverageReasonCode,
  type SastScannerKind
} from '@aegisai/shared';

import { PrismaService } from '../prisma/prisma.service';
import {
  SastScanCoverageDurableScopeError,
  SastScanCoverageReplayConflictError,
  SastScanCoverageScannerSetError,
  SastScanCoverageStore,
  type PersistSastScanCoverageInput,
  type PersistedSastScanCoverage,
  type SastScanCoverageContext,
  type SastScanCoverageLifecycleSourceVerification,
  type SastScannerCoverageDurableEvidence
} from './sast-scan-coverage.store';

const SERIALIZABLE_ATTEMPTS = 3;
const SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000;
const SERIALIZABLE_RETRY_BASE_DELAY_MILLISECONDS = 10;
const SERIALIZABLE_RETRY_MAX_DELAY_MILLISECONDS = 100;

const CORRELATION_SELECT =
  Prisma.validator<Prisma.SastFindingCorrelationBatchSelect>()({
    id: true,
    tenantId: true,
    repositoryBindingId: true,
    scanRequestId: true,
    attemptId: true,
    lifecycleContextKey: true,
    targetRef: true,
    commitSha: true,
    lane: true,
    profileId: true,
    profileDigest: true,
    canonicalScanKey: true,
    planDigest: true,
    sourceSetDigest: true,
    sourceBatchCount: true,
    occurrenceCount: true,
    edgeCount: true,
    exactFingerprintCount: true,
    sameDependencyCveCount: true,
    supportingEvidenceCount: true,
    possibleOverlapCount: true,
    correlatedAt: true,
    sources: {
      orderBy: { observationBatchId: 'asc' },
      select: {
        id: true,
        observationBatchId: true,
        scannerRunId: true,
        scanner: true,
        capabilities: true,
        sourceIdentityBatchDigest: true,
        sourceBindingDigest: true,
        lifecycleContextKey: true,
        findingCount: true,
        occurrenceCount: true,
        observedAt: true
      }
    },
    sastCoverageDecision: {
      select: {
        id: true,
        decisionDigest: true,
        decidedAt: true,
        publicationDecision: {
          select: {
            id: true,
            decisionDigest: true
          }
        }
      }
    }
  });

const SCANNER_RUN_SELECT = Prisma.validator<Prisma.ScannerRunSelect>()({
  id: true,
  tenantId: true,
  repositoryBindingId: true,
  scanRequestId: true,
  attemptId: true,
  scanner: true,
  scannerVersion: true,
  required: true,
  wrapperDigest: true,
  scannerImageDigest: true,
  ruleBundleDigest: true,
  databaseDigest: true,
  scannerSetDigest: true,
  schemaBundleDigest: true,
  normalizerBundleDigest: true,
  profileId: true,
  profileDigest: true,
  preflightAttestationRef: true,
  preflightInventoryDigest: true,
  scannerWorkspaceInventoryDigest: true,
  artifactSchema: true,
  artifactSchemaVersion: true,
  status: true,
  artifactIngestion: {
    select: {
      id: true,
      tenantId: true,
      repositoryBindingId: true,
      scanRequestId: true,
      attemptId: true,
      scannerRunId: true,
      workloadIdentityRef: true,
      envelope: true,
      envelopeDigest: true,
      declaredContentDigest: true,
      observedContentDigest: true,
      declaredByteSize: true,
      observedByteSize: true,
      identityValidated: true,
      status: true,
      receivedAt: true,
      dispositionDecision: {
        select: {
          id: true,
          ingestionId: true,
          tenantId: true,
          repositoryBindingId: true,
          scanRequestId: true,
          attemptId: true,
          scannerRunId: true,
          disposition: true,
          validationResultDigest: true,
          intentDigest: true,
          decision: true,
          decisionDigest: true,
          storageReceiptDigest: true,
          normalizationEligible: true,
          decidedAt: true
        }
      }
    }
  }
});

const EXISTING_SELECT =
  Prisma.validator<Prisma.SastScanCoverageDecisionSelect>()({
    id: true,
    tenantId: true,
    repositoryBindingId: true,
    scanRequestId: true,
    attemptId: true,
    correlationBatchId: true,
    state: true,
    recordsDigest: true,
    decision: true,
    decisionDigest: true,
    decidedAt: true,
    scannerRecords: {
      orderBy: { scanner: 'asc' },
      select: {
        id: true,
        scanner: true,
        scannerRunId: true,
        artifactIngestionId: true,
        dispositionDecisionId: true,
        correlationSourceId: true,
        record: true,
        recordDigest: true
      }
    },
    publicationDecision: {
      select: {
        id: true,
        coverageDecisionId: true,
        tenantId: true,
        repositoryBindingId: true,
        scanRequestId: true,
        attemptId: true,
        coverageState: true,
        externalCommentAllowed: true,
        blockingStatusAllowed: true,
        aiAdvisoryAllowed: true,
        lifecycleMutationAllowed: true,
        latestTargetAuthority: true,
        staleStatus: true,
        comparabilityStatus: true,
        decision: true,
        decisionDigest: true,
        decidedAt: true
      }
    }
  });

type CorrelationRow =
  Prisma.SastFindingCorrelationBatchGetPayload<{
    select: typeof CORRELATION_SELECT;
  }>;
type ScannerRunRow = Prisma.ScannerRunGetPayload<{
  select: typeof SCANNER_RUN_SELECT;
}>;
type ExistingRow = Prisma.SastScanCoverageDecisionGetPayload<{
  select: typeof EXISTING_SELECT;
}>;
type CoverageReader = Pick<
  Prisma.TransactionClient,
  | 'sastFindingCorrelationBatch'
  | 'sastScanAttempt'
  | 'scannerRun'
  | 'sastScanCoverageDecision'
>;

@Injectable()
export class PrismaSastScanCoverageStore
  extends SastScanCoverageStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async loadContext(
    correlationBatchId: string
  ): Promise<SastScanCoverageContext | null> {
    return this.readContext(this.prisma, correlationBatchId);
  }

  async persist(
    input: Readonly<PersistSastScanCoverageInput>
  ): Promise<PersistedSastScanCoverage> {
    validatePersistenceInput(input);
    return this.runSerializable((transaction) =>
      this.persistInTransaction(transaction, input)
    );
  }

  async verifyLifecycleSource(
    decision: Readonly<SastFindingLifecycleCoverageDecision>
  ): Promise<SastScanCoverageLifecycleSourceVerification> {
    const coverage = await this.prisma.sastScanCoverageDecision.findFirst({
      where: {
        id: decision.sourceCoverageDecisionRef,
        tenantId: decision.tenantId,
        repositoryBindingId: decision.repositoryBindingId,
        scanRequestId: decision.scanRequestId,
        attemptId: decision.attemptId,
        decisionDigest: decision.sourceCoverageDecisionDigest,
        state: 'COMPLETE'
      },
      select: {
        decision: true,
        decisionDigest: true,
        publicationDecision: {
          select: {
            externalCommentAllowed: true,
            blockingStatusAllowed: true,
            aiAdvisoryAllowed: true,
            lifecycleMutationAllowed: true,
            latestTargetAuthority: true,
            staleStatus: true,
            comparabilityStatus: true
          }
        }
      }
    });
    const persisted = coverage?.decision as unknown as
      | SastScanCoverageDecision
      | undefined;
    return persisted &&
      isSastScanCoverageDecisionShapeValid(persisted, digest) &&
      persisted.decisionDigest === coverage?.decisionDigest &&
      persisted.scope.lifecycleContextKey ===
        decision.lifecycleContextKey &&
      persisted.scope.canonicalScanKey ===
        decision.canonicalScanKey &&
      persisted.scope.planDigest === decision.planDigest &&
      persisted.scope.commitSha === decision.commitSha &&
      persisted.scope.profileId === decision.profileId &&
      persisted.scope.profileDigest === decision.profileDigest &&
      coverage?.publicationDecision?.externalCommentAllowed === false &&
      coverage.publicationDecision.blockingStatusAllowed === false &&
      coverage.publicationDecision.aiAdvisoryAllowed === false &&
      coverage.publicationDecision.lifecycleMutationAllowed === false &&
      coverage.publicationDecision.latestTargetAuthority ===
        'UNAVAILABLE' &&
      coverage.publicationDecision.staleStatus === 'UNKNOWN' &&
      coverage.publicationDecision.comparabilityStatus === 'UNKNOWN'
      ? 'MATCHED'
      : 'REJECTED';
  }

  private async persistInTransaction(
    transaction: Prisma.TransactionClient,
    input: Readonly<PersistSastScanCoverageInput>
  ): Promise<PersistedSastScanCoverage> {
    const current = await this.readContext(
      transaction,
      input.context.scope.correlationBatchId
    );
    if (!current || !sameDurableContext(current, input.context)) {
      throw new SastScanCoverageDurableScopeError();
    }
    const scope = current.scope;
    const existing =
      await transaction.sastScanCoverageDecision.findFirst({
        where: {
          tenantId: scope.tenantId,
          OR: [
            { id: input.decision.coverageDecisionId },
            { correlationBatchId: scope.correlationBatchId },
            {
              repositoryBindingId: scope.repositoryBindingId,
              scanRequestId: scope.scanRequestId,
              attemptId: scope.attemptId
            }
          ]
        },
        select: EXISTING_SELECT
      });
    if (existing) return replayCoverage(existing, input);

    const decidedAt = new Date(input.decision.decidedAt);
    await transaction.sastScanCoverageDecision.create({
      data: {
        id: input.decision.coverageDecisionId,
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        correlationBatchId: scope.correlationBatchId,
        lifecycleContextKey: scope.lifecycleContextKey,
        targetRef: scope.targetRef,
        commitSha: scope.commitSha,
        lane: scope.lane,
        profileId: scope.profileId,
        profileDigest: scope.profileDigest,
        canonicalScanKey: scope.canonicalScanKey,
        planDigest: scope.planDigest,
        scannerSetDigest: scope.scannerSetDigest,
        correlationSourceSetDigest:
          scope.correlationSourceSetDigest,
        state: input.decision.state,
        requiredScanners: json(input.decision.requiredScanners),
        optionalScanners: json(input.decision.optionalScanners),
        missingRequiredScanners: json(
          input.decision.missingRequiredScanners
        ),
        pendingRequiredScanners: json(
          input.decision.pendingRequiredScanners
        ),
        failedRequiredScanners: json(
          input.decision.failedRequiredScanners
        ),
        achievedRequiredCapabilities: json(
          input.decision.achievedRequiredCapabilities
        ),
        missingRequiredCapabilities: json(
          input.decision.missingRequiredCapabilities
        ),
        duplicateScanners: json(input.decision.duplicateScanners),
        optionalIncompleteScanners: json(
          input.decision.optionalIncompleteScanners
        ),
        reasonCodes: json(input.decision.reasonCodes),
        recordsDigest: input.decision.recordsDigest,
        authority: json(input.decision.authority),
        decision: json(input.decision),
        decisionDigest: input.decision.decisionDigest,
        decidedAt,
        createdAt: decidedAt
      }
    });

    await transaction.sastScannerCoverageRecord.createMany({
      data: input.records.map((record) => ({
        id: record.scannerCoverageId,
        coverageDecisionId: input.decision.coverageDecisionId,
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        correlationBatchId: scope.correlationBatchId,
        scannerRunId: record.scannerRunId,
        artifactIngestionId: record.artifactIngestionId,
        dispositionDecisionId: record.dispositionDecisionId,
        correlationSourceId: record.correlationSourceId,
        scanner: record.scanner,
        required: record.required,
        executionStatus: record.executionStatus,
        authoritativeCapabilities: json(
          record.authoritativeCapabilities
        ),
        requiredCapabilities: json(record.requiredCapabilities),
        achievedCapabilities: json(record.achievedCapabilities),
        scannerVersion: record.scannerVersion,
        scannerImageDigest: record.scannerImageDigest,
        wrapperDigest: record.wrapperDigest,
        ruleBundleDigest: record.ruleBundleDigest,
        vulnerabilityDatabaseDigest:
          record.vulnerabilityDatabaseDigest,
        schemaBundleDigest: record.schemaBundleDigest,
        normalizerBundleDigest: record.normalizerBundleDigest,
        artifactEnvelopeDigest: record.artifactEnvelopeDigest,
        artifactDigest: record.artifactDigest,
        dispositionDecisionDigest:
          record.dispositionDecisionDigest,
        observationBatchId: record.observationBatchId,
        correlationSourceBindingDigest:
          record.correlationSourceBindingDigest,
        artifactAccepted: record.artifactAccepted,
        normalizationEligible: record.normalizationEligible,
        findingObservationRequired:
          record.findingObservationRequired,
        findingObservationClosed: record.findingObservationClosed,
        reasonCodes: json(record.reasonCodes),
        record: json(record),
        recordDigest: record.recordDigest,
        createdAt: decidedAt
      }))
    });

    await transaction.sastExternalPublicationDecision.create({
      data: {
        id: input.publication.publicationDecisionId,
        coverageDecisionId: input.decision.coverageDecisionId,
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        coverageState: input.publication.coverageState,
        externalCommentAllowed: false,
        blockingStatusAllowed: false,
        aiAdvisoryAllowed: false,
        lifecycleMutationAllowed: false,
        latestTargetAuthority: 'UNAVAILABLE',
        staleStatus: 'UNKNOWN',
        comparabilityStatus: 'UNKNOWN',
        reasonCodes: json(input.publication.reasonCodes),
        decision: json(input.publication),
        decisionDigest: input.publication.decisionDigest,
        decidedAt,
        createdAt: decidedAt
      }
    });

    return {
      coverageDecisionId: input.decision.coverageDecisionId,
      decisionDigest: input.decision.decisionDigest,
      publicationDecisionId:
        input.publication.publicationDecisionId,
      publicationDecisionDigest: input.publication.decisionDigest,
      decidedAt: input.decision.decidedAt,
      replayed: false
    };
  }

  private async readContext(
    reader: CoverageReader,
    correlationBatchId: string
  ): Promise<SastScanCoverageContext | null> {
    if (!/^finding-correlation:\/\/[a-f0-9]{64}$/u.test(correlationBatchId)) {
      throw new SastScanCoverageDurableScopeError();
    }
    const correlation =
      await reader.sastFindingCorrelationBatch.findUnique({
        where: { id: correlationBatchId },
        select: CORRELATION_SELECT
      });
    if (!correlation) return null;

    const attempt = await reader.sastScanAttempt.findFirst({
      where: {
        id: correlation.attemptId,
        tenantId: correlation.tenantId,
        repositoryBindingId: correlation.repositoryBindingId,
        scanRequestId: correlation.scanRequestId,
        stage: {
          in: [
            'SCANNING',
            'CLEANUP_PENDING',
            'COMPLETED',
            'FAILED',
            'CLEANUP_FAILED'
          ]
        },
        scanRequest: {
          status: { in: ['RUNNING', 'COMPLETED', 'FAILED'] }
        }
      },
      select: {
        workloadIdentityRef: true,
        scanRequest: {
          select: {
            lane: true,
            targetRef: true,
            commitSha: true,
            canonicalKey: true,
            sastQueueReservation: {
              select: { immutablePlan: true }
            }
          }
        }
      }
    });
    const plan = parsePlan(
      attempt?.scanRequest.sastQueueReservation?.immutablePlan
    );
    if (!attempt || !plan || !planMatchesCorrelation(plan, correlation, attempt)) {
      throw new SastScanCoverageDurableScopeError();
    }

    const scannerRuns = await reader.scannerRun.findMany({
      where: {
        tenantId: correlation.tenantId,
        repositoryBindingId: correlation.repositoryBindingId,
        scanRequestId: correlation.scanRequestId,
        attemptId: correlation.attemptId
      },
      select: SCANNER_RUN_SELECT,
      orderBy: { scanner: 'asc' }
    });
    if (
      scannerRuns.length > SAST_SCANNER_KINDS.length ||
      scannerRuns.some((row) => row.scanner === 'MOCK')
    ) {
      throw new SastScanCoverageScannerSetError();
    }

    const sourceAnalysis = analyzeCorrelationSources(correlation);
    const sourceByRun = new Map(
      sourceAnalysis.sources.map((source) => [
        source.row.scannerRunId,
        source
      ])
    );
    const scanners = scannerRuns.map((row) =>
      toScannerEvidence(
        row,
        plan,
        attempt.workloadIdentityRef,
        sourceByRun.get(row.id),
        sourceAnalysis.sourceSetValid
      )
    );
    const scope = {
      tenantId: correlation.tenantId,
      repositoryBindingId: correlation.repositoryBindingId,
      scanRequestId: correlation.scanRequestId,
      attemptId: correlation.attemptId,
      lifecycleContextKey:
        correlation.lifecycleContextKey as `sha256:${string}`,
      targetRef: correlation.targetRef,
      commitSha: correlation.commitSha,
      lane: correlation.lane,
      profileId: correlation.profileId as SastProfileId,
      profileDigest: correlation.profileDigest as `sha256:${string}`,
      canonicalScanKey:
        correlation.canonicalScanKey as `sha256:${string}`,
      planDigest: correlation.planDigest as `sha256:${string}`,
      scannerSetDigest: plan.scannerSet
        .scannerSetDigest as `sha256:${string}`,
      correlationBatchId: correlation.id,
      correlationSourceSetDigest:
        correlation.sourceSetDigest as `sha256:${string}`
    };
    const publication =
      correlation.sastCoverageDecision?.publicationDecision;
    return {
      scope,
      correlation: {
        correlationBatchId: correlation.id,
        sourceSetDigest:
          correlation.sourceSetDigest as `sha256:${string}`,
        lifecycleContextKey:
          correlation.lifecycleContextKey as `sha256:${string}`,
        sourceBatchCount: correlation.sourceBatchCount,
        occurrenceCount: correlation.occurrenceCount,
        edgeCount: correlation.edgeCount,
        exactFingerprintCount: correlation.exactFingerprintCount,
        sameDependencyCveCount:
          correlation.sameDependencyCveCount,
        supportingEvidenceCount:
          correlation.supportingEvidenceCount,
        possibleOverlapCount: correlation.possibleOverlapCount,
        correlatedAt: correlation.correlatedAt.toISOString(),
        sourceSetValid: sourceAnalysis.sourceSetValid
      },
      scanners,
      ...(correlation.sastCoverageDecision && publication
        ? {
            existingDecision: {
              coverageDecisionId:
                correlation.sastCoverageDecision.id,
              decisionDigest: correlation.sastCoverageDecision
                .decisionDigest as `sha256:${string}`,
              publicationDecisionId: publication.id,
              publicationDecisionDigest:
                publication.decisionDigest as `sha256:${string}`,
              decidedAt:
                correlation.sastCoverageDecision.decidedAt.toISOString()
            }
          }
        : {})
    };
  }

  private async runSerializable<T>(
    operation: (transaction: Prisma.TransactionClient) => Promise<T>
  ): Promise<T> {
    let lastError: unknown;
    for (let attempt = 0; attempt < SERIALIZABLE_ATTEMPTS; attempt += 1) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel:
            Prisma.TransactionIsolationLevel.Serializable,
          maxWait: SERIALIZABLE_MAX_WAIT_MILLISECONDS,
          timeout: SERIALIZABLE_TIMEOUT_MILLISECONDS
        });
      } catch (error) {
        lastError = error;
        if (!isRetryableTransactionError(error)) throw error;
        if (attempt + 1 < SERIALIZABLE_ATTEMPTS) {
          await wait(serializableRetryDelay(attempt));
        }
      }
    }
    throw lastError;
  }
}

interface SourceAnalysis {
  row: CorrelationRow['sources'][number];
  binding: SastFindingCorrelationSourceBinding | null;
  valid: boolean;
}

function analyzeCorrelationSources(correlation: CorrelationRow): {
  sources: SourceAnalysis[];
  sourceSetValid: boolean;
} {
  const sources = correlation.sources.map((row) => {
    const capabilities = Array.isArray(row.capabilities)
      ? (row.capabilities as SastCapability[])
      : [];
    const binding: SastFindingCorrelationSourceBinding = {
      version: SAST_FINDING_CORRELATION_SOURCE_VERSION,
      observationBatchId: row.observationBatchId,
      sourceIdentityBatchDigest:
        row.sourceIdentityBatchDigest as `sha256:${string}`,
      scannerRunId: row.scannerRunId,
      scanner: row.scanner as 'OPENGREP' | 'TRIVY',
      capabilities: capabilities as Exclude<
        SastCapability,
        'SBOM'
      >[],
      lifecycleContextKey:
        row.lifecycleContextKey as `sha256:${string}`,
      findingCount: row.findingCount,
      occurrenceCount: row.occurrenceCount,
      observedAt: row.observedAt.toISOString(),
      sourceBindingDigest:
        row.sourceBindingDigest as `sha256:${string}`
    };
    const valid =
      (row.scanner === 'OPENGREP' || row.scanner === 'TRIVY') &&
      isSastFindingCorrelationSourceBindingShapeValid(
        binding,
        digest
      );
    return { row, binding: valid ? binding : null, valid };
  });
  const validBindings = sources.flatMap((source) =>
    source.binding ? [source.binding] : []
  );
  const uniqueScannerRuns = new Set(
    sources.map((source) => source.row.scannerRunId)
  );
  const sourceSetValid =
    sources.length === correlation.sourceBatchCount &&
    validBindings.length === sources.length &&
    uniqueScannerRuns.size === sources.length &&
    sources.reduce(
      (count, source) => count + source.row.occurrenceCount,
      0
    ) === correlation.occurrenceCount &&
    digest(
      buildSastFindingCorrelationSourceSetPreimage(validBindings)
    ) === correlation.sourceSetDigest;
  return { sources, sourceSetValid };
}

function toScannerEvidence(
  row: ScannerRunRow,
  plan: Readonly<SastScanPlan>,
  workloadIdentityRef: string,
  source: SourceAnalysis | undefined,
  sourceSetValid: boolean
): SastScannerCoverageDurableEvidence {
  const scanner = row.scanner as SastScannerKind;
  const executionStatus = mapScannerStatus(row.status);
  const descriptor = plan.scannerSet.scanners[scanner];
  const bundles = plan.scannerSet.ruleBundles.filter(
    (bundle) => bundle.scanner === scanner
  );
  const expectedRuleDigest =
    scanner === 'SYFT'
      ? null
      : bundles.length === 1
        ? bundles[0]?.digest ?? null
        : null;
  const expectedDatabaseDigest =
    scanner === 'TRIVY'
      ? plan.scannerSet.vulnerabilityDatabase.digest
      : null;
  const expectedSchema =
    SAST_SCANNER_RESPONSIBILITIES[scanner].outputSchema;
  const terminal = !['PENDING', 'RUNNING'].includes(executionStatus);
  const provenanceValid =
    descriptor !== undefined &&
    (scanner === 'SYFT' || bundles.length === 1) &&
    row.scannerVersion === descriptor.version &&
    row.scannerImageDigest === descriptor.digest &&
    row.wrapperDigest === descriptor.wrapper.digest &&
    row.ruleBundleDigest === expectedRuleDigest &&
    row.databaseDigest === expectedDatabaseDigest &&
    row.scannerSetDigest === plan.scannerSet.scannerSetDigest &&
    row.schemaBundleDigest === plan.scannerSet.schemaBundle.digest &&
    row.normalizerBundleDigest ===
      plan.scannerSet.normalizerBundle.digest &&
    row.profileId === plan.profile.id &&
    row.profileDigest === plan.profileDigest &&
    row.preflightAttestationRef ===
      plan.repositoryState.attestationRef &&
    row.preflightInventoryDigest ===
      plan.repositoryState.inventoryDigest &&
    (!terminal ||
      row.scannerWorkspaceInventoryDigest ===
        plan.repositoryState.inventoryDigest) &&
    row.artifactSchema === expectedSchema &&
    row.artifactSchemaVersion ===
      SAST_ARTIFACT_SCHEMA_VERSIONS[expectedSchema];

  const artifact = analyzeArtifact(
    row,
    plan,
    workloadIdentityRef
  );
  return {
    scanner,
    executionStatus,
    requiredBinding: row.required,
    scannerRunId: row.id,
    scannerVersion: boundedOrNull(row.scannerVersion),
    scannerImageDigest: digestOrNull(row.scannerImageDigest),
    wrapperDigest: digestOrNull(row.wrapperDigest),
    ruleBundleDigest: digestOrNull(row.ruleBundleDigest),
    vulnerabilityDatabaseDigest: digestOrNull(row.databaseDigest),
    schemaBundleDigest: digestOrNull(row.schemaBundleDigest),
    normalizerBundleDigest: digestOrNull(row.normalizerBundleDigest),
    provenanceValid,
    ...artifact,
    correlationSourceId: source?.row.id ?? null,
    observationBatchId: source?.row.observationBatchId ?? null,
    correlationSourceBindingDigest: digestOrNull(
      source?.row.sourceBindingDigest
    ),
    correlationSourceValid:
      Boolean(source?.valid) &&
      source?.row.scannerRunId === row.id &&
      source?.row.scanner === row.scanner &&
      sourceSetValid
  };
}

function analyzeArtifact(
  row: ScannerRunRow,
  plan: Readonly<SastScanPlan>,
  workloadIdentityRef: string
): Pick<
  SastScannerCoverageDurableEvidence,
  | 'artifactIngestionId'
  | 'artifactEnvelopeDigest'
  | 'artifactDigest'
  | 'dispositionDecisionId'
  | 'dispositionDecisionDigest'
  | 'artifactAccepted'
  | 'normalizationEligible'
  | 'artifactBindingValid'
> {
  const ingestion = row.artifactIngestion;
  if (!ingestion) {
    return {
      artifactIngestionId: null,
      artifactEnvelopeDigest: null,
      artifactDigest: null,
      dispositionDecisionId: null,
      dispositionDecisionDigest: null,
      artifactAccepted: false,
      normalizationEligible: false,
      artifactBindingValid: true
    };
  }
  const envelope = parseEnvelope(ingestion.envelope);
  const disposition = parseDisposition(
    ingestion.dispositionDecision?.decision
  );
  const observedUploadMatches =
    (ingestion.status === 'RECEIVING' &&
      ingestion.observedContentDigest === null &&
      ingestion.observedByteSize === null &&
      ingestion.receivedAt === null) ||
    (envelope !== null &&
      envelope.contentDigest === ingestion.observedContentDigest &&
      envelope.byteSize === ingestion.observedByteSize &&
      ingestion.receivedAt !== null &&
      Date.parse(envelope.producedAt) <=
        ingestion.receivedAt.getTime());
  const envelopeValid =
    envelope !== null &&
    isScannerArtifactEnvelopeBoundToPlan(envelope, plan, {
      attemptId: row.attemptId ?? '',
      scannerRunId: row.id,
      scanner: row.scanner as SastScannerKind,
      artifactRef: envelope.artifactRef,
      workloadIdentityRef,
      preflightAttestationRef:
        plan.repositoryState.attestationRef,
      preflightInventoryDigest:
        plan.repositoryState.inventoryDigest
    }) &&
    digest(canonicalizeScannerArtifactEnvelope(envelope)) ===
      ingestion.envelopeDigest &&
    envelope.contentDigest === ingestion.declaredContentDigest &&
    envelope.byteSize === ingestion.declaredByteSize &&
    observedUploadMatches &&
    ingestion.workloadIdentityRef === workloadIdentityRef;
  const dispositionRow = ingestion.dispositionDecision;
  const dispositionValid =
    dispositionRow === null ||
    (disposition !== null &&
      dispositionRow.ingestionId === ingestion.id &&
      dispositionRow.tenantId === row.tenantId &&
      dispositionRow.repositoryBindingId === row.repositoryBindingId &&
      dispositionRow.scanRequestId === row.scanRequestId &&
      dispositionRow.attemptId === row.attemptId &&
      dispositionRow.scannerRunId === row.id &&
      disposition.ingestionId === ingestion.id &&
      disposition.decisionDigest === dispositionRow.decisionDigest &&
      digest(
        canonicalizeSastArtifactDispositionDecision(
          withoutDecisionDigest(disposition)
        )
      ) === dispositionRow.decisionDigest &&
      disposition.disposition === dispositionRow.disposition &&
      disposition.validationResultDigest ===
        dispositionRow.validationResultDigest &&
      disposition.intentDigest === dispositionRow.intentDigest &&
      disposition.storageReceiptDigest ===
        dispositionRow.storageReceiptDigest &&
      disposition.normalizationEligible ===
        dispositionRow.normalizationEligible &&
      disposition.decidedAt ===
        dispositionRow.decidedAt.toISOString() &&
      ingestion.receivedAt !== null &&
      dispositionRow.decidedAt.getTime() >=
        ingestion.receivedAt.getTime());
  const artifactBindingValid =
    ingestion.tenantId === row.tenantId &&
    ingestion.repositoryBindingId === row.repositoryBindingId &&
    ingestion.scanRequestId === row.scanRequestId &&
    ingestion.attemptId === row.attemptId &&
    ingestion.scannerRunId === row.id &&
    envelopeValid &&
    dispositionValid;
  const accepted =
    artifactBindingValid &&
    ingestion.identityValidated &&
    ingestion.status === 'ACCEPTED' &&
    disposition?.disposition === 'ACCEPTED' &&
    disposition.normalizationEligible === true;
  return {
    artifactIngestionId: ingestion.id,
    artifactEnvelopeDigest: digestOrNull(
      ingestion.envelopeDigest
    ),
    artifactDigest: digestOrNull(ingestion.declaredContentDigest),
    dispositionDecisionId: dispositionRow?.id ?? null,
    dispositionDecisionDigest: digestOrNull(
      dispositionRow?.decisionDigest
    ),
    artifactAccepted: accepted,
    normalizationEligible:
      accepted && disposition?.normalizationEligible === true,
    artifactBindingValid
  };
}

function planMatchesCorrelation(
  plan: Readonly<SastScanPlan>,
  correlation: Readonly<CorrelationRow>,
  attempt: Readonly<{
    scanRequest: {
      lane: CorrelationRow['lane'];
      targetRef: string;
      commitSha: string;
      canonicalKey: string;
    };
  }>
): boolean {
  const profileId = correlation.profileId as SastProfileId;
  const profile = SAST_SCAN_PROFILES[profileId];
  return (
    profile !== undefined &&
    correlation.profileDigest ===
      SAST_APPROVED_PROFILE_DIGESTS[profileId] &&
    correlation.lane === profile.lane &&
    plan.tenantId === correlation.tenantId &&
    plan.scanRequestId === correlation.scanRequestId &&
    plan.repositoryState.repositoryBindingId ===
      correlation.repositoryBindingId &&
    plan.repositoryState.targetRef === correlation.targetRef &&
    plan.repositoryState.fixedCommitSha === correlation.commitSha &&
    plan.canonicalScanKey === correlation.canonicalScanKey &&
    plan.profile.id === profileId &&
    plan.profileDigest === correlation.profileDigest &&
    plan.profile.lane === correlation.lane &&
    attempt.scanRequest.lane === correlation.lane &&
    attempt.scanRequest.targetRef === correlation.targetRef &&
    attempt.scanRequest.commitSha === correlation.commitSha &&
    attempt.scanRequest.canonicalKey ===
      correlation.canonicalScanKey &&
    digest(buildSastScanPlanDigestPreimage(plan)) ===
      correlation.planDigest
  );
}

function validatePersistenceInput(
  input: Readonly<PersistSastScanCoverageInput>
): void {
  if (
    !isSastScanCoverageDecisionShapeValid(input.decision, digest) ||
    !isSastExternalPublicationDecisionShapeValid(
      input.publication,
      digest
    ) ||
    input.records.length !== SAST_SCANNER_KINDS.length ||
    input.records.some(
      (record, index) =>
        record.scanner !== SAST_SCANNER_KINDS[index] ||
        !isSastScannerCoverageRecordShapeValid(record, digest)
    ) ||
    digest(buildSastScanCoverageRecordsPreimage(input.records)) !==
      input.decision.recordsDigest ||
    deterministicCoverageId(
      'sast-coverage',
      buildSastScanCoverageDecisionKeyPreimage({
        scope: input.decision.scope,
        recordsDigest: input.decision.recordsDigest
      })
    ) !== input.decision.coverageDecisionId ||
    deterministicCoverageId(
      'sast-publication',
      `${input.decision.coverageDecisionId}\0${input.decision.decisionDigest}`
    ) !== input.publication.publicationDecisionId ||
    stableJson(input.decision.scope) !==
      stableJson(input.context.scope) ||
    input.decision.scope.correlationBatchId !==
      input.context.scope.correlationBatchId ||
    !recordsMatchContext(input)
  ) {
    throw new SastScanCoverageDurableScopeError();
  }
  const evaluation = evaluateSastScanCoverageRecords({
    profileId: input.decision.scope.profileId,
    records: input.records
  });
  const expectedPublication =
    buildFailClosedSastExternalPublicationDecision({
      publicationDecisionId:
        input.publication.publicationDecisionId,
      decision: input.decision,
      profileAiAdvisoryEligible:
        SAST_SCAN_PROFILES[input.decision.scope.profileId]
          .aiAdvisoryEligible,
      digestCanonical: digest
    });
  if (
    evaluation.state !== input.decision.state ||
    stableJson(evaluation.missingRequiredScanners) !==
      stableJson(input.decision.missingRequiredScanners) ||
    stableJson(evaluation.pendingRequiredScanners) !==
      stableJson(input.decision.pendingRequiredScanners) ||
    stableJson(evaluation.failedRequiredScanners) !==
      stableJson(input.decision.failedRequiredScanners) ||
    stableJson(evaluation.achievedRequiredCapabilities) !==
      stableJson(input.decision.achievedRequiredCapabilities) ||
    stableJson(evaluation.missingRequiredCapabilities) !==
      stableJson(input.decision.missingRequiredCapabilities) ||
    stableJson(evaluation.duplicateScanners) !==
      stableJson(input.decision.duplicateScanners) ||
    stableJson(evaluation.optionalIncompleteScanners) !==
      stableJson(input.decision.optionalIncompleteScanners) ||
    stableJson(evaluation.reasonCodes) !==
      stableJson(input.decision.reasonCodes) ||
    input.publication.coverageDecisionId !==
      input.decision.coverageDecisionId ||
    input.publication.coverageDecisionDigest !==
      input.decision.decisionDigest ||
    input.publication.coverageState !== input.decision.state ||
    input.publication.decidedAt !== input.decision.decidedAt ||
    input.publication.externalCommentAllowed !== false ||
    input.publication.blockingStatusAllowed !== false ||
    input.publication.aiAdvisoryAllowed !== false ||
    input.publication.lifecycleMutationAllowed !== false ||
    stableJson(input.publication) !== stableJson(expectedPublication)
  ) {
    throw new SastScanCoverageDurableScopeError();
  }
}

function recordsMatchContext(
  input: Readonly<PersistSastScanCoverageInput>
): boolean {
  const profile = SAST_SCAN_PROFILES[input.context.scope.profileId];
  const evidenceByScanner = new Map(
    input.context.scanners.map((evidence) => [
      evidence.scanner,
      evidence
    ])
  );
  return input.records.every((record) => {
    const responsibilities = SAST_SCANNER_RESPONSIBILITIES[record.scanner];
    const authoritativeCapabilities = SAST_CAPABILITIES.filter(
      (capability) =>
        (
          responsibilities.authoritativeCapabilities as readonly SastCapability[]
        ).includes(capability)
    );
    const requiredCapabilities = profile.requiredCapabilities.filter(
      (capability) => authoritativeCapabilities.includes(capability)
    );
    const required = profile.requiredScanners.includes(record.scanner);
    if (
      record.scannerCoverageId !==
        deterministicCoverageId(
          'sast-scanner-coverage',
          `${coverageScopeIdentity(input.context)}\0${record.scanner}`
        ) ||
      record.required !== required ||
      stableJson(record.authoritativeCapabilities) !==
        stableJson(authoritativeCapabilities) ||
      stableJson(record.requiredCapabilities) !==
        stableJson(requiredCapabilities) ||
      record.findingObservationRequired !==
        responsibilities.mayCreateFindings
    ) {
      return false;
    }
    const evidence = evidenceByScanner.get(record.scanner);
    if (!evidence) {
      return (
        record.executionStatus === 'NOT_STARTED' &&
        record.achievedCapabilities.length === 0 &&
        record.scannerRunId === null &&
        record.scannerVersion === null &&
        record.scannerImageDigest === null &&
        record.wrapperDigest === null &&
        record.ruleBundleDigest === null &&
        record.vulnerabilityDatabaseDigest === null &&
        record.schemaBundleDigest === null &&
        record.normalizerBundleDigest === null &&
        record.artifactIngestionId === null &&
        record.artifactEnvelopeDigest === null &&
        record.artifactDigest === null &&
        record.dispositionDecisionId === null &&
        record.dispositionDecisionDigest === null &&
        record.correlationSourceId === null &&
        record.observationBatchId === null &&
        record.correlationSourceBindingDigest === null &&
        record.artifactAccepted === false &&
        record.normalizationEligible === false &&
        record.findingObservationClosed ===
          !responsibilities.mayCreateFindings &&
        stableJson(record.reasonCodes) ===
          stableJson(['SCANNER_NOT_STARTED'])
      );
    }
    const findingObservationClosed =
      !responsibilities.mayCreateFindings ||
      (evidence.correlationSourceId !== null &&
        evidence.correlationSourceValid &&
        input.context.correlation.sourceSetValid);
    const reasons = expectedScannerRecordReasons(
      evidence,
      required,
      responsibilities.mayCreateFindings,
      input.context.correlation.sourceSetValid
    );
    const achievedCapabilities =
      evidence.executionStatus === 'SUCCEEDED' &&
      evidence.artifactAccepted &&
      evidence.normalizationEligible &&
      findingObservationClosed &&
      reasons.length === 0
        ? authoritativeCapabilities
        : [];
    return (
      record.executionStatus === evidence.executionStatus &&
      stableJson(record.achievedCapabilities) ===
        stableJson(achievedCapabilities) &&
      record.scannerRunId === evidence.scannerRunId &&
      record.scannerVersion === evidence.scannerVersion &&
      record.scannerImageDigest === evidence.scannerImageDigest &&
      record.wrapperDigest === evidence.wrapperDigest &&
      record.ruleBundleDigest === evidence.ruleBundleDigest &&
      record.vulnerabilityDatabaseDigest ===
        evidence.vulnerabilityDatabaseDigest &&
      record.schemaBundleDigest === evidence.schemaBundleDigest &&
      record.normalizerBundleDigest ===
        evidence.normalizerBundleDigest &&
      record.artifactIngestionId === evidence.artifactIngestionId &&
      record.artifactEnvelopeDigest ===
        evidence.artifactEnvelopeDigest &&
      record.dispositionDecisionId ===
        evidence.dispositionDecisionId &&
      record.correlationSourceId === evidence.correlationSourceId &&
      record.observationBatchId === evidence.observationBatchId &&
      record.artifactDigest === evidence.artifactDigest &&
      record.dispositionDecisionDigest ===
        evidence.dispositionDecisionDigest &&
      record.correlationSourceBindingDigest ===
        evidence.correlationSourceBindingDigest &&
      record.artifactAccepted === evidence.artifactAccepted &&
      record.normalizationEligible ===
        evidence.normalizationEligible &&
      record.findingObservationClosed === findingObservationClosed &&
      stableJson(record.reasonCodes) === stableJson(reasons)
    );
  });
}

function expectedScannerRecordReasons(
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

function replayCoverage(
  existing: Readonly<ExistingRow>,
  input: Readonly<PersistSastScanCoverageInput>
): PersistedSastScanCoverage {
  const scope = input.context.scope;
  const recordsById = new Map(
    input.records.map((record) => [record.scannerCoverageId, record])
  );
  if (
    existing.id !== input.decision.coverageDecisionId ||
    existing.tenantId !== scope.tenantId ||
    existing.repositoryBindingId !== scope.repositoryBindingId ||
    existing.scanRequestId !== scope.scanRequestId ||
    existing.attemptId !== scope.attemptId ||
    existing.correlationBatchId !== scope.correlationBatchId ||
    existing.state !== input.decision.state ||
    existing.recordsDigest !== input.decision.recordsDigest ||
    existing.decisionDigest !== input.decision.decisionDigest ||
    existing.decidedAt.toISOString() !== input.decision.decidedAt ||
    stableJson(existing.decision) !== stableJson(input.decision) ||
    existing.scannerRecords.length !== input.records.length ||
    !existing.publicationDecision ||
    stableJson(existing.publicationDecision.decision) !==
      stableJson(input.publication) ||
    existing.publicationDecision.id !==
      input.publication.publicationDecisionId ||
    existing.publicationDecision.coverageDecisionId !== existing.id ||
    existing.publicationDecision.tenantId !== scope.tenantId ||
    existing.publicationDecision.repositoryBindingId !==
      scope.repositoryBindingId ||
    existing.publicationDecision.scanRequestId !== scope.scanRequestId ||
    existing.publicationDecision.attemptId !== scope.attemptId ||
    existing.publicationDecision.coverageState !== input.decision.state ||
    existing.publicationDecision.externalCommentAllowed !== false ||
    existing.publicationDecision.blockingStatusAllowed !== false ||
    existing.publicationDecision.aiAdvisoryAllowed !== false ||
    existing.publicationDecision.lifecycleMutationAllowed !== false ||
    existing.publicationDecision.latestTargetAuthority !== 'UNAVAILABLE' ||
    existing.publicationDecision.staleStatus !== 'UNKNOWN' ||
    existing.publicationDecision.comparabilityStatus !== 'UNKNOWN' ||
    existing.publicationDecision.decisionDigest !==
      input.publication.decisionDigest ||
    existing.publicationDecision.decidedAt.toISOString() !==
      input.publication.decidedAt
  ) {
    throw new SastScanCoverageReplayConflictError();
  }
  for (const row of existing.scannerRecords) {
    const record = recordsById.get(row.id);
    if (
      !record ||
      row.scanner !== record.scanner ||
      row.scannerRunId !== record.scannerRunId ||
      row.artifactIngestionId !== record.artifactIngestionId ||
      row.dispositionDecisionId !== record.dispositionDecisionId ||
      row.correlationSourceId !== record.correlationSourceId ||
      row.recordDigest !== record.recordDigest ||
      stableJson(row.record) !== stableJson(record)
    ) {
      throw new SastScanCoverageReplayConflictError();
    }
  }
  return {
    coverageDecisionId: existing.id,
    decisionDigest:
      existing.decisionDigest as `sha256:${string}`,
    publicationDecisionId: existing.publicationDecision.id,
    publicationDecisionDigest:
      existing.publicationDecision
        .decisionDigest as `sha256:${string}`,
    decidedAt: existing.decidedAt.toISOString(),
    replayed: true
  };
}

function sameDurableContext(
  left: Readonly<SastScanCoverageContext>,
  right: Readonly<SastScanCoverageContext>
): boolean {
  return (
    stableJson(left.scope) === stableJson(right.scope) &&
    stableJson(left.correlation) === stableJson(right.correlation) &&
    stableJson(left.scanners) === stableJson(right.scanners)
  );
}

function parsePlan(value: Prisma.JsonValue | undefined): SastScanPlan | null {
  const candidate = value as unknown as SastScanPlan;
  return candidate && isSastScanPlanValid(candidate)
    ? candidate
    : null;
}

function parseEnvelope(
  value: Prisma.JsonValue | null
): ScannerArtifactEnvelope | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as unknown as ScannerArtifactEnvelope)
    : null;
}

function parseDisposition(
  value: Prisma.JsonValue | null | undefined
): SastArtifactDispositionDecision | null {
  const candidate = value as unknown as SastArtifactDispositionDecision;
  return candidate && isSastArtifactDispositionDecisionShapeValid(candidate)
    ? candidate
    : null;
}

function withoutDecisionDigest(
  decision: Readonly<SastArtifactDispositionDecision>
): Omit<SastArtifactDispositionDecision, 'decisionDigest'> {
  const { decisionDigest: _decisionDigest, ...core } = decision;
  void _decisionDigest;
  return core;
}

function mapScannerStatus(
  status: ScannerRunRow['status']
): ScannerExecutionStatus {
  switch (status) {
    case 'QUEUED':
      return 'PENDING';
    case 'RUNNING':
      return 'RUNNING';
    case 'COMPLETED':
      return 'SUCCEEDED';
    case 'FAILED':
      return 'FAILED';
    case 'TIMED_OUT':
      return 'TIMED_OUT';
    case 'QUARANTINED':
      return 'QUARANTINED';
    case 'KILLED':
      return 'KILLED';
    case 'SKIPPED':
      return 'SKIPPED_BY_POLICY';
  }
}

function boundedOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0
    ? value
    : null;
}

function digestOrNull(
  value: unknown
): `sha256:${string}` | null {
  return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value)
    ? (value as `sha256:${string}`)
    : null;
}

function json(value: unknown): Prisma.InputJsonValue {
  return value as Prisma.InputJsonValue;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort(compareStrings)
      .map(
        (key) =>
          `${JSON.stringify(key)}:${stableJson(record[key])}`
      )
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function coverageScopeIdentity(
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

function deterministicCoverageId(
  prefix: string,
  value: string
): string {
  return `${prefix}://${digest(value).slice('sha256:'.length)}`;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}

function serializableRetryDelay(attempt: number): number {
  const ceiling = Math.min(
    SERIALIZABLE_RETRY_BASE_DELAY_MILLISECONDS * 2 ** attempt,
    SERIALIZABLE_RETRY_MAX_DELAY_MILLISECONDS
  );
  return randomInt(1, ceiling + 1);
}

function isRetryableTransactionError(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    (error.code === 'P2034' || error.code === 'P2002')
  );
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
