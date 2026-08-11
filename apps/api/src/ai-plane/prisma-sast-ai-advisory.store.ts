import { createHash } from 'node:crypto';

import {
  isSastAiAdvisoryHandoffShapeValid,
  isSastEvidenceAccessDecisionShapeValid,
  isSastSecretRedactedFindingCandidateShapeValid,
  type AiAdvisoryResult,
  type SastAiAdvisoryHandoff,
  type SastAiAdvisoryNormalizedFinding,
  type SastEvidenceAccessDecision,
  type SastFindingLocation,
  type SastSecretRedactedFindingCandidate
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import {
  SastAiAdvisoryPersistenceError,
  SastAiAdvisoryStore,
  type PersistedSastAiAdvisoryHandoff
} from './sast-ai-advisory.store';

const SERIALIZABLE_RETRIES = 3;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 10_000;

@Injectable()
export class PrismaSastAiAdvisoryStore extends SastAiAdvisoryStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async loadNormalizedFinding(
    decision: Readonly<SastEvidenceAccessDecision>
  ): Promise<SastAiAdvisoryNormalizedFinding | null> {
    if (!isSastEvidenceAccessDecisionShapeValid(decision, digest)) {
      return null;
    }

    const row = await this.prisma.sastEvidenceAccessDecision.findUnique({
      where: { id: decision.accessDecisionId },
      select: {
        id: true,
        tenantId: true,
        repositoryBindingId: true,
        scanRequestId: true,
        attemptId: true,
        occurrenceId: true,
        evidencePackId: true,
        findingFingerprint: true,
        purpose: true,
        outcome: true,
        classification: true,
        decisionDigest: true,
        decision: true,
        buildDecision: {
          select: {
            normalizedFindingId: true,
            findingOccurrence: {
              select: {
                id: true,
                tenantId: true,
                repositoryBindingId: true,
                scanRequestId: true,
                attemptId: true,
                scannerRunId: true,
                normalizedFindingId: true,
                capability: true,
                stableFingerprint: true,
                sourceFinding: true,
                normalizedFinding: {
                  select: {
                    id: true,
                    tenantId: true,
                    scanRequestId: true,
                    scannerRunId: true,
                    title: true,
                    severity: true,
                    scannerProvenance: true,
                    filePath: true,
                    lineStart: true,
                    lineEnd: true,
                    sastCapability: true,
                    sastStableFingerprint: true
                  }
                }
              }
            }
          }
        }
      }
    });

    if (!row || !isStoredDecisionBound(row, decision)) {
      return null;
    }

    const occurrence = row.buildDecision.findingOccurrence;
    const finding = occurrence.normalizedFinding;
    const source = occurrence.sourceFinding;
    if (
      !isSastSecretRedactedFindingCandidateShapeValid(source, digest) ||
      !isSourceBound(source, row, occurrence, finding, decision)
    ) {
      return null;
    }

    return {
      normalizedFindingId: finding.id,
      occurrenceId: occurrence.id,
      tenantId: occurrence.tenantId,
      repositoryBindingId: occurrence.repositoryBindingId,
      scanRequestId: occurrence.scanRequestId,
      attemptId: occurrence.attemptId,
      scannerRunId: occurrence.scannerRunId,
      findingFingerprint:
        occurrence.stableFingerprint as `sha256:${string}`,
      capability: occurrence.capability,
      title: source.title,
      severity: source.severity,
      confidence: source.confidence,
      cweIds: [...source.cweIds],
      cveIds: [...source.cveIds],
      location: projectLocation(source.location),
      scanner: source.provenance.scanner,
      ruleSemanticId: source.identityMaterial.ruleSemanticId,
      ruleRevision: source.provenance.ruleRevision,
      secretRedactionApplied: true
    };
  }

  async persistHandoff(
    handoff: Readonly<SastAiAdvisoryHandoff>
  ): Promise<PersistedSastAiAdvisoryHandoff> {
    if (!isSastAiAdvisoryHandoffShapeValid(handoff, digest)) {
      throw new SastAiAdvisoryPersistenceError('OUTPUT_INVALID');
    }

    try {
      return await this.runSerializable(async (tx) => {
        const existing = await tx.sastAiAdvisoryHandoff.findUnique({
          where: { id: handoff.handoffId }
        });
        if (existing) return replayHandoff(existing, handoff);

        const created = await tx.sastAiAdvisoryHandoff.create({
          data: {
            id: handoff.handoffId,
            requestId: handoff.requestId,
            advisoryId: handoff.advisoryId,
            accessDecisionId: handoff.accessDecisionId,
            accessDecisionDigest: handoff.accessDecisionDigest,
            tenantId: handoff.tenantId,
            repositoryBindingId: handoff.repositoryBindingId,
            scanRequestId: handoff.scanRequestId,
            attemptId: handoff.attemptId,
            occurrenceId: handoff.normalizedFinding.occurrenceId,
            normalizedFindingId:
              handoff.normalizedFinding.normalizedFindingId,
            scannerRunId: handoff.normalizedFinding.scannerRunId,
            evidencePackId: handoff.evidencePackId,
            findingFingerprint:
              handoff.normalizedFinding.findingFingerprint,
            modelVersion: handoff.modelVersion,
            payloadExpiresAt: new Date(handoff.payloadExpiresAt),
            requestDigest: handoff.requestDigest,
            handoffDigest: handoff.handoffDigest,
            normalizedFindingAllowed: true,
            reducedEvidenceReferenceAllowed: true,
            aiPayloadAllowed: true,
            aiProviderCallAllowed: true,
            advisoryOnly: true,
            callerFindingAccepted: false,
            callerEvidenceAccepted: false,
            callerPromptAccepted: false,
            requestPayloadStored: false,
            rawSourceStored: false,
            secretValueStored: false,
            evidenceFragmentStored: false,
            retrievalAttempted: false,
            toolsInvoked: false,
            retrievalAllowed: false,
            toolsAllowed: false,
            policyAuthority: false,
            publicationAuthority: false,
            lifecycleMutationAuthority: false,
            scmWriteAuthority: false,
            createdAt: new Date(handoff.createdAt)
          }
        });
        return replayHandoff(created, handoff, false);
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw error;
      const existing =
        await this.prisma.sastAiAdvisoryHandoff.findUnique({
          where: { id: handoff.handoffId }
        });
      if (!existing) {
        throw new SastAiAdvisoryPersistenceError('REPLAY_CONFLICT');
      }
      return replayHandoff(existing, handoff);
    }
  }

  async loadAdvisory(input: {
    tenantId: string;
    advisoryId: string;
  }): Promise<AiAdvisoryResult | null> {
    const row = await this.prisma.aiAdvisoryMetadata.findFirst({
      where: {
        id: input.advisoryId,
        tenantId: input.tenantId
      },
      include: {
        sastHandoff: {
          select: { requestDigest: true }
        }
      }
    });
    return row ? advisoryFromRow(row) : null;
  }

  async persistAdvisory(input: {
    handoff: Readonly<SastAiAdvisoryHandoff>;
    advisory: Readonly<AiAdvisoryResult>;
  }): Promise<AiAdvisoryResult> {
    if (!isAdvisoryBound(input.handoff, input.advisory)) {
      throw new SastAiAdvisoryPersistenceError('OUTPUT_INVALID');
    }

    try {
      return await this.runSerializable(async (tx) => {
        const existing = await tx.aiAdvisoryMetadata.findUnique({
          where: { id: input.advisory.id },
          include: {
            sastHandoff: {
              select: { requestDigest: true }
            }
          }
        });
        if (existing) {
          return replayAdvisory(existing, input);
        }
        const created = await tx.aiAdvisoryMetadata.create({
          data: {
            id: input.advisory.id,
            sastHandoffId: input.handoff.handoffId,
            tenantId: input.advisory.tenantId,
            scanRequestId: input.advisory.scanRequestId,
            findingId: input.advisory.findingId,
            modelVersion: input.advisory.modelVersion,
            advisoryOnly: true,
            redactedEvidenceOnly: true,
            detectorSignals: input.advisory.detectorSignals,
            plannerSteps: input.advisory.plannerSteps,
            confidence: input.advisory.confidence,
            detectorAdvisories:
              input.advisory.detectorAdvisories === undefined
                ? Prisma.JsonNull
                : (input.advisory.detectorAdvisories as unknown as Prisma.InputJsonValue),
            plannerAdvisories:
              input.advisory.plannerAdvisories === undefined
                ? Prisma.JsonNull
                : (input.advisory.plannerAdvisories as unknown as Prisma.InputJsonValue),
            modelMetadata:
              input.advisory.modelMetadata === undefined
                ? Prisma.JsonNull
                : (input.advisory.modelMetadata as unknown as Prisma.InputJsonValue),
            fallback:
              input.advisory.fallback === undefined
                ? Prisma.JsonNull
                : (input.advisory.fallback as unknown as Prisma.InputJsonValue),
            createdAt: new Date(input.advisory.createdAt)
          },
          include: {
            sastHandoff: {
              select: { requestDigest: true }
            }
          }
        });
        return advisoryFromRow(created);
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw error;
      const existing = await this.loadAdvisory({
        tenantId: input.handoff.tenantId,
        advisoryId: input.handoff.advisoryId
      });
      if (!existing || !isAdvisoryBound(input.handoff, existing)) {
        throw new SastAiAdvisoryPersistenceError('REPLAY_CONFLICT');
      }
      return existing;
    }
  }

  private async runSerializable<T>(
    operation: (tx: Prisma.TransactionClient) => Promise<T>
  ): Promise<T> {
    for (let attempt = 1; attempt <= SERIALIZABLE_RETRIES; attempt += 1) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          maxWait: SERIALIZABLE_TIMEOUT_MILLISECONDS,
          timeout: SERIALIZABLE_TIMEOUT_MILLISECONDS
        });
      } catch (error) {
        if (!isSerializableConflict(error) || attempt === SERIALIZABLE_RETRIES) {
          throw error;
        }
        await new Promise((resolve) =>
          setTimeout(resolve, 20 * attempt + Math.floor(Math.random() * 20))
        );
      }
    }
    throw new SastAiAdvisoryPersistenceError('REPLAY_CONFLICT');
  }
}

function isStoredDecisionBound(
  row: {
    id: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    occurrenceId: string;
    evidencePackId: string;
    findingFingerprint: string;
    purpose: string;
    outcome: string;
    classification: string;
    decisionDigest: string;
    decision: unknown;
  },
  decision: Readonly<SastEvidenceAccessDecision>
): boolean {
  if (!isSastEvidenceAccessDecisionShapeValid(row.decision, digest)) {
    return false;
  }
  const stored = row.decision;
  return (
    stored.accessDecisionId === row.id &&
    stored.decisionDigest === row.decisionDigest &&
    stored.decisionDigest === decision.decisionDigest &&
    row.id === decision.accessDecisionId &&
    row.decisionDigest === decision.decisionDigest &&
    row.tenantId === decision.scope.tenantId &&
    row.repositoryBindingId === decision.scope.repositoryBindingId &&
    row.scanRequestId === decision.scope.scanRequestId &&
    row.attemptId === decision.scope.attemptId &&
    row.occurrenceId === decision.scope.occurrenceId &&
    row.evidencePackId === decision.scope.evidencePackId &&
    row.findingFingerprint === decision.scope.findingFingerprint &&
    row.purpose === 'AI_ADVISORY' &&
    row.outcome === 'ALLOWED' &&
    row.classification === 'AI_REDUCED_REFERENCE_SAFE'
  );
}

function isSourceBound(
  source: Readonly<SastSecretRedactedFindingCandidate>,
  row: {
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    occurrenceId: string;
    findingFingerprint: string;
    buildDecision: { normalizedFindingId: string };
  },
  occurrence: {
    id: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    scannerRunId: string;
    normalizedFindingId: string;
    capability: string;
    stableFingerprint: string;
  },
  finding: {
    id: string;
    tenantId: string;
    scanRequestId: string;
    scannerRunId: string;
    title: string;
    severity: string;
    scannerProvenance: string;
    filePath: string | null;
    lineStart: number | null;
    lineEnd: number | null;
    sastCapability: string | null;
    sastStableFingerprint: string | null;
  },
  decision: Readonly<SastEvidenceAccessDecision>
): boolean {
  const locationMatches =
    source.location.kind === 'FILE'
      ? finding.filePath === source.location.normalizedPath &&
        finding.lineStart === source.location.lineStart &&
        finding.lineEnd === (source.location.lineEnd ?? null)
      : finding.filePath === null &&
        finding.lineStart === null &&
        finding.lineEnd === null;
  return (
    occurrence.id === row.occurrenceId &&
    occurrence.id === decision.scope.occurrenceId &&
    occurrence.tenantId === row.tenantId &&
    occurrence.repositoryBindingId === row.repositoryBindingId &&
    occurrence.scanRequestId === row.scanRequestId &&
    occurrence.attemptId === row.attemptId &&
    occurrence.normalizedFindingId === row.buildDecision.normalizedFindingId &&
    occurrence.stableFingerprint === row.findingFingerprint &&
    finding.id === occurrence.normalizedFindingId &&
    finding.tenantId === occurrence.tenantId &&
    finding.scanRequestId === occurrence.scanRequestId &&
    finding.scannerRunId === occurrence.scannerRunId &&
    finding.title === source.title &&
    finding.severity === source.severity &&
    finding.scannerProvenance === source.provenance.scanner &&
    finding.sastCapability === occurrence.capability &&
    finding.sastCapability === source.capability &&
    finding.sastStableFingerprint === occurrence.stableFingerprint &&
    source.tenantId === occurrence.tenantId &&
    source.repositoryBindingId === occurrence.repositoryBindingId &&
    source.scanRequestId === occurrence.scanRequestId &&
    source.attemptId === occurrence.attemptId &&
    source.scannerRunId === occurrence.scannerRunId &&
    locationMatches
  );
}

function projectLocation(
  location: Readonly<SastFindingLocation>
): SastFindingLocation {
  if (location.kind === 'UNKNOWN') {
    return { kind: 'UNKNOWN', reasonCode: location.reasonCode };
  }
  return {
    kind: 'FILE',
    normalizedPath: location.normalizedPath,
    lineStart: location.lineStart,
    ...(location.lineEnd === undefined
      ? {}
      : { lineEnd: location.lineEnd }),
    ...(location.columnStart === undefined
      ? {}
      : { columnStart: location.columnStart }),
    ...(location.columnEnd === undefined
      ? {}
      : { columnEnd: location.columnEnd })
  };
}

function replayHandoff(
  row: {
    id: string;
    requestId: string;
    advisoryId: string;
    accessDecisionId: string;
    accessDecisionDigest: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    occurrenceId: string;
    normalizedFindingId: string;
    scannerRunId: string;
    evidencePackId: string;
    findingFingerprint: string;
    modelVersion: string;
    payloadExpiresAt: Date;
    requestDigest: string;
    handoffDigest: string;
    normalizedFindingAllowed: boolean;
    reducedEvidenceReferenceAllowed: boolean;
    aiPayloadAllowed: boolean;
    aiProviderCallAllowed: boolean;
    advisoryOnly: boolean;
    callerFindingAccepted: boolean;
    callerEvidenceAccepted: boolean;
    callerPromptAccepted: boolean;
    requestPayloadStored: boolean;
    rawSourceStored: boolean;
    secretValueStored: boolean;
    evidenceFragmentStored: boolean;
    retrievalAttempted: boolean;
    toolsInvoked: boolean;
    retrievalAllowed: boolean;
    toolsAllowed: boolean;
    policyAuthority: boolean;
    publicationAuthority: boolean;
    lifecycleMutationAuthority: boolean;
    scmWriteAuthority: boolean;
    createdAt: Date;
  },
  expected: Readonly<SastAiAdvisoryHandoff>,
  replayed = true
): PersistedSastAiAdvisoryHandoff {
  if (
    row.id !== expected.handoffId ||
    row.requestId !== expected.requestId ||
    row.advisoryId !== expected.advisoryId ||
    row.accessDecisionId !== expected.accessDecisionId ||
    row.accessDecisionDigest !== expected.accessDecisionDigest ||
    row.tenantId !== expected.tenantId ||
    row.repositoryBindingId !== expected.repositoryBindingId ||
    row.scanRequestId !== expected.scanRequestId ||
    row.attemptId !== expected.attemptId ||
    row.occurrenceId !== expected.normalizedFinding.occurrenceId ||
    row.normalizedFindingId !==
      expected.normalizedFinding.normalizedFindingId ||
    row.scannerRunId !== expected.normalizedFinding.scannerRunId ||
    row.evidencePackId !== expected.evidencePackId ||
    row.findingFingerprint !==
      expected.normalizedFinding.findingFingerprint ||
    row.modelVersion !== expected.modelVersion ||
    row.payloadExpiresAt.toISOString() !== expected.payloadExpiresAt ||
    row.requestDigest !== expected.requestDigest ||
    row.handoffDigest !== expected.handoffDigest ||
    row.normalizedFindingAllowed !== true ||
    row.reducedEvidenceReferenceAllowed !== true ||
    row.aiPayloadAllowed !== true ||
    row.aiProviderCallAllowed !== true ||
    row.advisoryOnly !== true ||
    row.callerFindingAccepted !== false ||
    row.callerEvidenceAccepted !== false ||
    row.callerPromptAccepted !== false ||
    row.requestPayloadStored !== false ||
    row.rawSourceStored !== false ||
    row.secretValueStored !== false ||
    row.evidenceFragmentStored !== false ||
    row.retrievalAttempted !== false ||
    row.toolsInvoked !== false ||
    row.retrievalAllowed !== false ||
    row.toolsAllowed !== false ||
    row.policyAuthority !== false ||
    row.publicationAuthority !== false ||
    row.lifecycleMutationAuthority !== false ||
    row.scmWriteAuthority !== false ||
    row.createdAt.toISOString() !== expected.createdAt
  ) {
    throw new SastAiAdvisoryPersistenceError('REPLAY_CONFLICT');
  }
  return { handoff: expected, replayed };
}

function replayAdvisory(
  row: Parameters<typeof advisoryFromRow>[0],
  expected: {
    handoff: Readonly<SastAiAdvisoryHandoff>;
    advisory: Readonly<AiAdvisoryResult>;
  }
): AiAdvisoryResult {
  const advisory = advisoryFromRow(row);
  if (
    !isAdvisoryBound(expected.handoff, advisory) ||
    advisory.modelVersion !== expected.advisory.modelVersion
  ) {
    throw new SastAiAdvisoryPersistenceError('REPLAY_CONFLICT');
  }
  return advisory;
}

function isAdvisoryBound(
  handoff: Readonly<SastAiAdvisoryHandoff>,
  advisory: Readonly<AiAdvisoryResult>
): boolean {
  return (
    advisory.id === handoff.advisoryId &&
    advisory.sastHandoffId === handoff.handoffId &&
    advisory.requestDigest === handoff.requestDigest &&
    advisory.tenantId === handoff.tenantId &&
    advisory.scanRequestId === handoff.scanRequestId &&
    advisory.findingId === handoff.normalizedFinding.normalizedFindingId &&
    advisory.advisoryOnly === true &&
    advisory.redactedEvidenceOnly === true
  );
}

function advisoryFromRow(row: {
  id: string;
  sastHandoffId: string | null;
  tenantId: string;
  scanRequestId: string;
  findingId: string;
  modelVersion: string;
  detectorSignals: unknown;
  plannerSteps: unknown;
  confidence: number;
  detectorAdvisories: unknown;
  plannerAdvisories: unknown;
  modelMetadata: unknown;
  fallback: unknown;
  createdAt: Date;
  sastHandoff?: { requestDigest: string } | null;
}): AiAdvisoryResult {
  return {
    id: row.id,
    ...(row.sastHandoffId
      ? { sastHandoffId: row.sastHandoffId }
      : {}),
    ...(row.sastHandoff?.requestDigest &&
    /^sha256:[a-f0-9]{64}$/u.test(row.sastHandoff.requestDigest)
      ? {
          requestDigest:
            row.sastHandoff.requestDigest as `sha256:${string}`
        }
      : {}),
    tenantId: row.tenantId,
    scanRequestId: row.scanRequestId,
    findingId: row.findingId,
    modelVersion: row.modelVersion,
    advisoryOnly: true,
    redactedEvidenceOnly: true,
    detectorSignals: stringArray(row.detectorSignals),
    plannerSteps: stringArray(row.plannerSteps),
    confidence: row.confidence,
    detectorAdvisories: arrayOrUndefined(row.detectorAdvisories) as
      AiAdvisoryResult['detectorAdvisories'],
    plannerAdvisories: arrayOrUndefined(row.plannerAdvisories) as
      AiAdvisoryResult['plannerAdvisories'],
    modelMetadata: objectOrUndefined(row.modelMetadata) as
      AiAdvisoryResult['modelMetadata'],
    fallback: objectOrUndefined(row.fallback) as
      AiAdvisoryResult['fallback'],
    createdAt: row.createdAt.toISOString()
  };
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : [];
}

function arrayOrUndefined(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function objectOrUndefined(value: unknown): object | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value
    : undefined;
}

function isSerializableConflict(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2034';
}

function isUniqueConflict(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2002';
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
