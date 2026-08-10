import { createHash } from 'node:crypto';

import {
  SAST_ACCEPTED_EVIDENCE_POLICY,
  isSastAcceptedEvidenceBuildResultShapeValid,
  isSastAcceptedEvidencePackShapeValid,
  isSastFingerprintedFindingShapeValid,
  isSastScanCoverageDecisionShapeValid,
  isSastScanFreshnessDecisionShapeValid,
  type SastAcceptedEvidenceBuildResult,
  type SastAcceptedEvidenceScope,
  type SastEvidenceBuildDecision,
  type SastFingerprintedFinding,
  type SastScanCoverageDecision,
  type SastScanFreshnessCanonicalDigester,
  type SastScanFreshnessDecision
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import {
  SastAcceptedEvidencePersistenceError,
  SastAcceptedEvidenceStore,
  type PersistedSastAcceptedEvidence,
  type SastAcceptedEvidenceContext
} from './sast-accepted-evidence.store';

const EVIDENCE_POLICY_VERSION = 'sast-evidence-policy-v1';
const SERIALIZABLE_ATTEMPTS = 3;
const SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000;

type EvidenceReader = Pick<
  Prisma.TransactionClient,
  'sastScanFreshnessDecision' | 'sastFindingOccurrence'
>;

@Injectable()
export class PrismaSastAcceptedEvidenceStore
  extends SastAcceptedEvidenceStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async loadContext(
    freshnessDecisionId: string,
    occurrenceId: string
  ): Promise<SastAcceptedEvidenceContext | null> {
    return this.readContext(
      this.prisma,
      freshnessDecisionId,
      occurrenceId
    );
  }

  async persist(input: {
    context: Readonly<SastAcceptedEvidenceContext>;
    result: Readonly<SastAcceptedEvidenceBuildResult>;
  }): Promise<PersistedSastAcceptedEvidence> {
    validatePersistInput(input);
    return this.runSerializable(async (transaction) => {
      const decision = input.result.decision;
      const scope = decision.scope;
      const current = await this.readContext(
        transaction,
        scope.freshnessDecisionId,
        scope.occurrenceId
      );
      if (
        !current ||
        stableJson(current) !== stableJson(input.context)
      ) {
        throw new SastAcceptedEvidencePersistenceError(
          'CONTEXT_DRIFT'
        );
      }
      const existing =
        await transaction.sastEvidenceBuildDecision.findFirst({
          where: {
            tenantId: scope.tenantId,
            occurrenceId: scope.occurrenceId,
            policyVersion: scope.policyVersion,
            candidateSetDigest: decision.candidateSetDigest
          },
          include: {
            evidencePack: {
              include: {
                fragments: { orderBy: { ordinal: 'asc' } }
              }
            }
          }
        });
      if (existing) {
        return replayExisting(existing, input.result);
      }

      await transaction.sastEvidenceBuildDecision.create({
        data: {
          id: decision.buildDecisionId,
          freshnessDecisionId: scope.freshnessDecisionId,
          coverageDecisionId: scope.coverageDecisionId,
          tenantId: scope.tenantId,
          repositoryBindingId: scope.repositoryBindingId,
          scanRequestId: scope.scanRequestId,
          attemptId: scope.attemptId,
          occurrenceId: scope.occurrenceId,
          observationBatchId: scope.observationBatchId,
          normalizedFindingId: scope.normalizedFindingId,
          lineageId: scope.lineageId,
          findingFingerprint: scope.findingFingerprint,
          fingerprintVersion: scope.fingerprintVersion,
          capability: scope.capability,
          policyVersion: scope.policyVersion,
          candidateSetDigest: decision.candidateSetDigest,
          outcome: decision.outcome,
          reasonCodes: json(decision.reasonCodes),
          selectedFragmentCount:
            decision.selectedFragmentCount,
          suppressedFragmentCount:
            decision.suppressedFragmentCount,
          reconstructionStatus:
            decision.reconstruction.status,
          reconstructionDecision: json(
            decision.reconstruction
          ),
          reconstructionDecisionDigest:
            decision.reconstruction.decisionDigest,
          evidencePackId: decision.evidencePackId,
          evidencePackDigest: decision.evidencePackDigest,
          authority: json(decision.authority),
          audit: json(decision.audit),
          decision: json(decision),
          decisionDigest: decision.decisionDigest,
          decidedAt: new Date(decision.decidedAt),
          createdAt: new Date(decision.decidedAt)
        }
      });
      const pack = input.result.pack;
      if (pack) {
        await transaction.sastAcceptedEvidencePack.create({
          data: {
            id: pack.evidencePackId,
            buildDecisionId: decision.buildDecisionId,
            tenantId: scope.tenantId,
            repositoryBindingId: scope.repositoryBindingId,
            scanRequestId: scope.scanRequestId,
            attemptId: scope.attemptId,
            occurrenceId: scope.occurrenceId,
            normalizedFindingId: scope.normalizedFindingId,
            lineageId: scope.lineageId,
            findingFingerprint: scope.findingFingerprint,
            policyVersion: scope.policyVersion,
            candidateSetDigest: pack.candidateSetDigest,
            totalBytes: pack.totalBytes,
            fragmentCount: pack.fragments.length,
            truncated: pack.truncated,
            suppressedFragmentCount:
              pack.suppressedFragmentCount,
            reconstructionRiskChecked: true,
            reconstructionDecisionId:
              pack.reconstructionRiskDecisionRef,
            reconstructionDecisionDigest:
              pack.reconstructionRiskDecisionDigest,
            classificationDecisionRef: null,
            deletionScheduleRef: null,
            dashboardSafe: false,
            aiSafe: false,
            pack: json(pack),
            packDigest: pack.packDigest,
            createdAt: new Date(pack.createdAt),
            expiresAt: new Date(pack.expiresAt)
          }
        });
        await transaction.sastAcceptedEvidenceFragment.createMany({
          data: pack.fragments.map((fragment) => ({
            id: fragment.fragmentId,
            evidencePackId: pack.evidencePackId,
            buildDecisionId: decision.buildDecisionId,
            tenantId: scope.tenantId,
            repositoryBindingId: scope.repositoryBindingId,
            scanRequestId: scope.scanRequestId,
            attemptId: scope.attemptId,
            candidateId: fragment.candidateId,
            ordinal: fragment.ordinal,
            role: fragment.role,
            normalizedPath: fragment.normalizedPath,
            startLine: fragment.startLine,
            endLine: fragment.endLine,
            anchorStartLine: fragment.anchorStartLine,
            anchorEndLine: fragment.anchorEndLine,
            sourceFileLineCount:
              fragment.sourceFileLineCount,
            redactedContent: fragment.redactedContent,
            byteSize: fragment.byteSize,
            sourceContentDigest:
              fragment.sourceContentDigest,
            contentDigest: fragment.contentDigest,
            sourceAttestationRef:
              fragment.sourceAttestationRef,
            scannerRedactionDecisionRef:
              fragment.scannerRedactionDecisionRef,
            platformRedactionDecisionRef:
              fragment.platformRedactionDecisionRef,
            secretRedactionApplied: true,
            rawSourceStored: false,
            isFullFile: false,
            fragment: json(fragment),
            fragmentDigest: fragment.fragmentDigest,
            createdAt: new Date(pack.createdAt)
          }))
        });
      }
      return {
        buildDecisionId: decision.buildDecisionId,
        decisionDigest: decision.decisionDigest,
        outcome: decision.outcome,
        evidencePackId: pack?.evidencePackId ?? null,
        replayed: false
      };
    });
  }

  private async readContext(
    reader: EvidenceReader,
    freshnessDecisionId: string,
    occurrenceId: string
  ): Promise<SastAcceptedEvidenceContext | null> {
    const [freshnessRow, occurrence] = await Promise.all([
      reader.sastScanFreshnessDecision.findUnique({
        where: { id: freshnessDecisionId },
        include: {
          coverageDecision: {
            include: {
              correlationBatch: {
                select: {
                  id: true,
                  sourceSetDigest: true,
                  sources: {
                    select: {
                      observationBatchId: true,
                      scannerRunId: true
                    }
                  }
                }
              }
            }
          }
        }
      }),
      reader.sastFindingOccurrence.findUnique({
        where: { id: occurrenceId },
        include: {
          observationBatch: true,
          normalizedFinding: true,
          lineage: true
        }
      })
    ]);
    if (!freshnessRow || !occurrence) return null;
    const freshness = freshnessRow.decision as unknown as
      SastScanFreshnessDecision;
    const coverage = freshnessRow.coverageDecision
      .decision as unknown as SastScanCoverageDecision;
    const sourceFinding = occurrence.sourceFinding as unknown as
      SastFingerprintedFinding;
    if (
      !isSastScanFreshnessDecisionShapeValid(freshness, digest) ||
      !isSastScanCoverageDecisionShapeValid(coverage, digest) ||
      !isSastFingerprintedFindingShapeValid(
        sourceFinding,
        digest,
        digest
      ) ||
      !freshnessRowMatchesDecision(freshnessRow, freshness) ||
      !coverageDecisionMatchesFreshness(
        freshnessRow,
        coverage
      ) ||
      !findingRowsMatch(
        freshnessRow,
        occurrence,
        sourceFinding
      )
    ) {
      throw new SastAcceptedEvidencePersistenceError(
        'CONTEXT_DRIFT'
      );
    }
    if (
      freshnessRow.coverageDecision.state !== 'COMPLETE' ||
      freshness.latestTargetAuthority !== 'VERIFIED' ||
      freshness.staleStatus !== 'FRESH' ||
      freshness.comparabilityStatus !== 'COMPARABLE' ||
      !freshness.externalCommentEligible ||
      !freshness.blockingStatusEligible ||
      !freshness.lifecycleMutationAllowed ||
      freshness.aiAdvisoryAllowed ||
      freshness.publicationAttempted ||
      freshness.reasonCodes.length > 0 ||
      sourceFinding.location.kind !== 'FILE'
    ) {
      return null;
    }
    const lineStart = sourceFinding.location.lineStart;
    const lineEnd =
      sourceFinding.location.lineEnd ?? lineStart;
    const scope: SastAcceptedEvidenceScope = {
      tenantId: freshnessRow.tenantId,
      repositoryBindingId:
        freshnessRow.repositoryBindingId,
      scanRequestId: freshnessRow.scanRequestId,
      attemptId: freshnessRow.attemptId,
      targetRef: freshnessRow.targetRef,
      commitSha: freshnessRow.commitSha,
      canonicalScanKey: freshnessRow.canonicalScanKey,
      planDigest: freshnessRow.planDigest,
      profileId:
        freshnessRow.profileId as SastAcceptedEvidenceScope['profileId'],
      profileDigest: freshnessRow.profileDigest,
      freshnessDecisionId: freshnessRow.id,
      freshnessDecisionDigest: freshnessRow.decisionDigest,
      coverageDecisionId: freshnessRow.coverageDecisionId,
      coverageDecisionDigest:
        freshnessRow.coverageDecisionDigest,
      occurrenceId: occurrence.id,
      observationBatchId: occurrence.observationBatchId,
      normalizedFindingId: occurrence.normalizedFindingId,
      lineageId: occurrence.lineageId,
      findingFingerprint: occurrence.stableFingerprint,
      fingerprintVersion:
        occurrence.fingerprintVersion as typeof scopeFingerprintVersion,
      capability:
        occurrence.capability as SastAcceptedEvidenceScope['capability'],
      normalizedPath: sourceFinding.location.normalizedPath,
      findingStartLine: lineStart,
      findingEndLine: lineEnd,
      policyVersion: EVIDENCE_POLICY_VERSION
    };
    return {
      scope,
      freshnessDecidedAt: freshness.decidedAt
    };
  }

  private async runSerializable<T>(
    operation: (
      transaction: Prisma.TransactionClient
    ) => Promise<T>
  ): Promise<T> {
    let lastError: unknown;
    for (
      let attempt = 1;
      attempt <= SERIALIZABLE_ATTEMPTS;
      attempt += 1
    ) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel:
            Prisma.TransactionIsolationLevel.Serializable,
          maxWait: SERIALIZABLE_MAX_WAIT_MILLISECONDS,
          timeout: SERIALIZABLE_TIMEOUT_MILLISECONDS
        });
      } catch (error) {
        lastError = error;
        if (
          !isRetryableTransactionError(error) ||
          attempt === SERIALIZABLE_ATTEMPTS
        ) {
          throw error;
        }
      }
    }
    throw lastError;
  }
}

const scopeFingerprintVersion = 'sast-fingerprint-v1' as const;

function freshnessRowMatchesDecision(
  row: {
    id: string;
    coverageDecisionId: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    targetRef: string;
    commitSha: string;
    canonicalScanKey: string;
    planDigest: string;
    profileId: string;
    profileDigest: string;
    coverageDecisionDigest: string;
    decisionDigest: string;
    latestTargetAuthority: string;
    staleStatus: string;
    comparabilityStatus: string;
    externalCommentEligible: boolean;
    blockingStatusEligible: boolean;
    lifecycleMutationAllowed: boolean;
    aiAdvisoryAllowed: boolean;
    publicationAttempted: boolean;
    reasonCodes: Prisma.JsonValue;
  },
  decision: Readonly<SastScanFreshnessDecision>
): boolean {
  const scope = decision.scope;
  return (
    row.id === decision.freshnessDecisionId &&
    row.coverageDecisionId === scope.coverageDecisionId &&
    row.tenantId === scope.tenantId &&
    row.repositoryBindingId === scope.repositoryBindingId &&
    row.scanRequestId === scope.scanRequestId &&
    row.attemptId === scope.attemptId &&
    row.targetRef === scope.targetRef &&
    row.commitSha === scope.commitSha &&
    row.canonicalScanKey === scope.canonicalScanKey &&
    row.planDigest === scope.planDigest &&
    row.profileId === scope.profileId &&
    row.profileDigest === scope.profileDigest &&
    row.coverageDecisionDigest ===
      scope.coverageDecisionDigest &&
    row.decisionDigest === decision.decisionDigest &&
    row.latestTargetAuthority ===
      decision.latestTargetAuthority &&
    row.staleStatus === decision.staleStatus &&
    row.comparabilityStatus ===
      decision.comparabilityStatus &&
    row.externalCommentEligible ===
      decision.externalCommentEligible &&
    row.blockingStatusEligible ===
      decision.blockingStatusEligible &&
    row.lifecycleMutationAllowed ===
      decision.lifecycleMutationAllowed &&
    row.aiAdvisoryAllowed === decision.aiAdvisoryAllowed &&
    row.publicationAttempted ===
      decision.publicationAttempted &&
    stableJson(row.reasonCodes) ===
      stableJson(decision.reasonCodes)
  );
}

function findingRowsMatch(
  freshness: {
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    targetRef: string;
    commitSha: string;
    canonicalScanKey: string;
    planDigest: string;
    profileId: string;
    profileDigest: string;
    coverageDecision: {
      decisionDigest: string;
      correlationBatch: {
        sources: Array<{
          observationBatchId: string;
          scannerRunId: string;
        }>;
      };
    };
  },
  occurrence: {
    id: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    scannerRunId: string;
    observationBatchId: string;
    lineageId: string;
    normalizedFindingId: string;
    capability: string;
    fingerprintVersion: string;
    stableFingerprint: string;
    fingerprintDecisionDigest: string;
    observationBatch: {
      tenantId: string;
      repositoryBindingId: string;
      scanRequestId: string;
      attemptId: string;
      scannerRunId: string;
      targetRef: string;
      commitSha: string;
      profileId: string;
      profileDigest: string;
      canonicalScanKey: string;
      planDigest: string;
    };
    normalizedFinding: {
      id: string;
      tenantId: string;
      scanRequestId: string;
      scannerRunId: string;
      filePath: string | null;
      lineStart: number | null;
      lineEnd: number | null;
      sastCapability: string | null;
      sastFingerprintVersion: string | null;
      sastStableFingerprint: string | null;
      sastFingerprintDecisionDigest: string | null;
      sastLineageId: string | null;
      sastObservationBatchId: string | null;
    };
    lineage: {
      id: string;
      tenantId: string;
      repositoryBindingId: string;
      capability: string;
      fingerprintVersion: string;
    };
  },
  finding: Readonly<SastFingerprintedFinding>
): boolean {
  if (finding.location.kind !== 'FILE') return false;
  const observation = occurrence.observationBatch;
  const normalized = occurrence.normalizedFinding;
  const lineage = occurrence.lineage;
  const sourceBound = freshness.coverageDecision
    .correlationBatch.sources.some(
      (source) =>
        source.observationBatchId ===
          occurrence.observationBatchId &&
        source.scannerRunId === occurrence.scannerRunId
    );
  const findingEnd =
    finding.location.lineEnd ?? finding.location.lineStart;
  return (
    sourceBound &&
    freshness.coverageDecision.decisionDigest.length > 0 &&
    occurrence.tenantId === freshness.tenantId &&
    occurrence.repositoryBindingId ===
      freshness.repositoryBindingId &&
    occurrence.scanRequestId === freshness.scanRequestId &&
    occurrence.attemptId === freshness.attemptId &&
    observation.tenantId === freshness.tenantId &&
    observation.repositoryBindingId ===
      freshness.repositoryBindingId &&
    observation.scanRequestId === freshness.scanRequestId &&
    observation.attemptId === freshness.attemptId &&
    observation.scannerRunId === occurrence.scannerRunId &&
    observation.targetRef === freshness.targetRef &&
    observation.commitSha === freshness.commitSha &&
    observation.profileId === freshness.profileId &&
    observation.profileDigest === freshness.profileDigest &&
    observation.canonicalScanKey ===
      freshness.canonicalScanKey &&
    observation.planDigest === freshness.planDigest &&
    occurrence.capability === finding.capability &&
    occurrence.fingerprintVersion ===
      scopeFingerprintVersion &&
    occurrence.stableFingerprint ===
      finding.fingerprint.stableFingerprint &&
    occurrence.fingerprintDecisionDigest ===
      finding.fingerprint.decisionDigest &&
    lineage.id === occurrence.lineageId &&
    lineage.tenantId === freshness.tenantId &&
    lineage.repositoryBindingId ===
      freshness.repositoryBindingId &&
    lineage.capability === occurrence.capability &&
    lineage.fingerprintVersion ===
      occurrence.fingerprintVersion &&
    normalized.id === occurrence.normalizedFindingId &&
    normalized.tenantId === freshness.tenantId &&
    normalized.scanRequestId === freshness.scanRequestId &&
    normalized.scannerRunId === occurrence.scannerRunId &&
    normalized.filePath === finding.location.normalizedPath &&
    normalized.lineStart === finding.location.lineStart &&
    (normalized.lineEnd ?? normalized.lineStart) === findingEnd &&
    normalized.sastCapability === occurrence.capability &&
    normalized.sastFingerprintVersion ===
      occurrence.fingerprintVersion &&
    normalized.sastStableFingerprint ===
      occurrence.stableFingerprint &&
    normalized.sastFingerprintDecisionDigest ===
      occurrence.fingerprintDecisionDigest &&
    normalized.sastLineageId === occurrence.lineageId &&
    normalized.sastObservationBatchId ===
      occurrence.observationBatchId
  );
}

function coverageDecisionMatchesFreshness(
  freshness: {
    coverageDecisionId: string;
    coverageDecisionDigest: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    targetRef: string;
    commitSha: string;
    canonicalScanKey: string;
    planDigest: string;
    profileId: string;
    profileDigest: string;
    coverageDecision: {
      id: string;
      correlationBatchId: string;
      state: string;
      decisionDigest: string;
      correlationBatch: {
        id: string;
        sourceSetDigest: string;
      };
    };
  },
  coverage: Readonly<SastScanCoverageDecision>
): boolean {
  const scope = coverage.scope;
  return (
    coverage.coverageDecisionId === freshness.coverageDecisionId &&
    coverage.decisionDigest === freshness.coverageDecisionDigest &&
    freshness.coverageDecision.id === coverage.coverageDecisionId &&
    freshness.coverageDecision.decisionDigest ===
      coverage.decisionDigest &&
    freshness.coverageDecision.state === coverage.state &&
    freshness.coverageDecision.correlationBatchId ===
      scope.correlationBatchId &&
    freshness.coverageDecision.correlationBatch.id ===
      scope.correlationBatchId &&
    freshness.coverageDecision.correlationBatch.sourceSetDigest ===
      scope.correlationSourceSetDigest &&
    scope.tenantId === freshness.tenantId &&
    scope.repositoryBindingId === freshness.repositoryBindingId &&
    scope.scanRequestId === freshness.scanRequestId &&
    scope.attemptId === freshness.attemptId &&
    scope.targetRef === freshness.targetRef &&
    scope.commitSha === freshness.commitSha &&
    scope.canonicalScanKey === freshness.canonicalScanKey &&
    scope.planDigest === freshness.planDigest &&
    scope.profileId === freshness.profileId &&
    scope.profileDigest === freshness.profileDigest
  );
}

function validatePersistInput(input: {
  context: Readonly<SastAcceptedEvidenceContext>;
  result: Readonly<SastAcceptedEvidenceBuildResult>;
}): void {
  const decision = input.result.decision;
  if (
    !isSastAcceptedEvidenceBuildResultShapeValid(
      input.result,
      digest,
      SAST_ACCEPTED_EVIDENCE_POLICY
    ) ||
    stableJson(decision.scope) !==
      stableJson(input.context.scope) ||
    Date.parse(decision.decidedAt) <
      Date.parse(input.context.freshnessDecidedAt)
  ) {
    throw new SastAcceptedEvidencePersistenceError(
      'OUTPUT_INVALID'
    );
  }
}

function replayExisting(
  row: {
    decision: Prisma.JsonValue;
    evidencePack: null | {
      pack: Prisma.JsonValue;
      fragments: Array<{ fragment: Prisma.JsonValue }>;
    };
  },
  result: Readonly<SastAcceptedEvidenceBuildResult>
): PersistedSastAcceptedEvidence {
  const decision =
    row.decision as unknown as SastEvidenceBuildDecision;
  const pack = row.evidencePack?.pack as unknown;
  const storedResult = {
    decision,
    pack: row.evidencePack === null ? null : pack
  };
  if (
    !isSastAcceptedEvidenceBuildResultShapeValid(
      storedResult,
      digest,
      SAST_ACCEPTED_EVIDENCE_POLICY
    ) ||
    stableJson(decision) !== stableJson(result.decision) ||
    (result.pack === null) !== (row.evidencePack === null) ||
    (result.pack !== null &&
      (!isSastAcceptedEvidencePackShapeValid(
        pack,
        digest,
        SAST_ACCEPTED_EVIDENCE_POLICY
      ) ||
        stableJson(pack) !== stableJson(result.pack) ||
        row.evidencePack?.fragments.length !==
          result.pack.fragments.length ||
        row.evidencePack.fragments.some(
          (fragment, index) =>
            stableJson(fragment.fragment) !==
            stableJson(result.pack?.fragments[index])
        )))
  ) {
    throw new SastAcceptedEvidencePersistenceError(
      'REPLAY_CONFLICT'
    );
  }
  return {
    buildDecisionId: decision.buildDecisionId,
    decisionDigest: decision.decisionDigest,
    outcome: decision.outcome,
    evidencePackId: decision.evidencePackId,
    replayed: true
  };
}

function isRetryableTransactionError(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    (error.code === 'P2034' || error.code === 'P2002')
  );
}

function json(value: unknown): Prisma.InputJsonValue {
  return value as Prisma.InputJsonValue;
}

function digest(
  value: string
): ReturnType<SastScanFreshnessCanonicalDigester> {
  return (
    'sha256:' +
    createHash('sha256').update(value).digest('hex')
  ) as ReturnType<SastScanFreshnessCanonicalDigester>;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return '[' + value.map(stableJson).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return (
      '{' +
      Object.keys(record)
        .sort()
        .map(
          (key) =>
            JSON.stringify(key) + ':' + stableJson(record[key])
        )
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(value);
}
