import { createHash } from 'node:crypto';

import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import {
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_FINDING_FINGERPRINT_VERSION,
  SAST_FINDING_LINEAGE_VERSION,
  SAST_PROFILE_IDS,
  SAST_SCAN_LANES,
  SAST_SCANNER_RESPONSIBILITIES,
  buildFindingFingerprintPreimage,
  buildSastFindingLifecycleContextPreimage,
  buildSastFindingLineageKeyPreimage,
  buildSastScanPlanDigestPreimage,
  canonicalizeSastFingerprintedFinding,
  isSastFindingLifecycleCoverageDecisionShapeValid,
  isSastFindingLifecycleContextInputValid,
  isSastFindingRenameAttestationShapeValid,
  isSastFingerprintedFindingShapeValid,
  isSastFingerprintedFindingBatchShapeValid,
  isSastScanPlanValid,
  projectRenamedSastFindingFingerprintInput,
  type SastCapability,
  type SastFindingLifecycleStatus,
  type SastFingerprintedFinding,
  type SastScanPlan
} from '@aegisai/shared';

import { PrismaService } from '../prisma/prisma.service';
import {
  SastFindingLineageDurableScopeError,
  SastFindingLineageObservationIncompleteError,
  SastFindingLineageReconciliationOrderError,
  SastFindingLineageRenameAmbiguousError,
  SastFindingLineageReplayConflictError,
  SastFindingLineageStore,
  type PersistSastFindingObservationInput,
  type PersistSastFindingReconciliationInput,
  type PersistedSastFindingObservation,
  type PersistedSastFindingReconciliation,
  type SastFindingLineageObservationScope,
  type SastFindingLineageScanContext,
  type SastFindingReconciliationScanContext,
  type SastFindingRenameCandidate
} from './sast-finding-lineage.store';

const SERIALIZABLE_ATTEMPTS = 3;
const SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000;
const CREATE_MANY_CHUNK_SIZE = 250;
const READ_MANY_CHUNK_SIZE = 10_000;
const FINDING_CAPABILITIES = [
  'SAST',
  'DEPENDENCY_VULNERABILITY',
  'SECRET_DETECTION',
  'IAC_MISCONFIGURATION'
] as const satisfies readonly Exclude<SastCapability, 'SBOM'>[];

type FindingCapability = (typeof FINDING_CAPABILITIES)[number];

interface PreparedIdentity {
  key: string;
  capability: FindingCapability;
  stableFingerprint: `sha256:${string}`;
  normalizedPath: string;
  rename?: Readonly<SastFindingRenameCandidate>;
}

interface ResolvedIdentity extends PreparedIdentity {
  lineageId: string;
  match: 'CREATED' | 'EXACT' | 'RENAMED';
  currentAliasExists: boolean;
}

@Injectable()
export class PrismaSastFindingLineageStore
  extends SastFindingLineageStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async loadObservationContext(
    scope: Readonly<SastFindingLineageObservationScope>
  ): Promise<SastFindingLineageScanContext | null> {
    return this.readObservationContext(
      this.prisma.scannerRun,
      scope
    );
  }

  async loadReconciliationContext(input: {
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
  }): Promise<SastFindingReconciliationScanContext | null> {
    return this.readReconciliationContext(
      this.prisma.sastScanAttempt,
      input
    );
  }

  async observe(
    input: Readonly<PersistSastFindingObservationInput>
  ): Promise<PersistedSastFindingObservation> {
    if (
      !isSastFingerprintedFindingBatchShapeValid(
        input.batch,
        digest,
        digest
      ) ||
      !isObservationPersistenceInputValid(input)
    ) {
      throw new SastFindingLineageDurableScopeError();
    }
    const identities = prepareIdentities(input);
    return this.runSerializable((transaction) =>
      this.observeInTransaction(transaction, input, identities)
    );
  }

  async reconcile(
    input: Readonly<PersistSastFindingReconciliationInput>
  ): Promise<PersistedSastFindingReconciliation> {
    if (
      !isSastFindingLifecycleCoverageDecisionShapeValid(
        input.decision,
        digest
      ) ||
      !isCanonicalIsoTimestamp(input.reconciledAt) ||
      Date.parse(input.reconciledAt) <
        Date.parse(input.decision.decidedAt) ||
      !isReconciliationPersistenceInputValid(input)
    ) {
      throw new SastFindingLineageDurableScopeError();
    }
    return this.runSerializable((transaction) =>
      this.reconcileInTransaction(transaction, input)
    );
  }

  private async observeInTransaction(
    transaction: Prisma.TransactionClient,
    input: Readonly<PersistSastFindingObservationInput>,
    identities: readonly Readonly<PreparedIdentity>[]
  ): Promise<PersistedSastFindingObservation> {
    const currentContext = await this.readObservationContext(
      transaction.scannerRun,
      input.batch.scope
    );
    if (
      !currentContext ||
      !sameObservationContext(currentContext, input.context)
    ) {
      throw new SastFindingLineageDurableScopeError();
    }
    if (
      (input.renameAttestation === undefined) !==
        (input.renameAttestationDigest === undefined) ||
      (input.renameAttestation !== undefined &&
        input.renameAttestation.attestationDigest !==
          input.renameAttestationDigest)
    ) {
      throw new SastFindingLineageDurableScopeError();
    }
    if (input.renameAttestation) {
      const previousScan = await transaction.scanRequest.findFirst({
        where: {
          id: input.renameAttestation.fromScanRequestId,
          tenantId: input.context.scope.tenantId,
          repositoryBindingId:
            input.context.scope.repositoryBindingId,
          targetRef: input.context.targetRef,
          commitSha: input.renameAttestation.fromCommitSha,
          status: 'COMPLETED'
        },
        select: {
          lane: true,
          targetRef: true,
          commitSha: true,
          canonicalKey: true,
          sastQueueReservation: {
            select: { immutablePlan: true }
          }
        }
      });
      const previousPlan = parsePlan(
        previousScan?.sastQueueReservation?.immutablePlan
      );
      if (
        !previousPlan ||
        !isPlanBoundToScanRequest(previousPlan, {
          tenantId: input.context.scope.tenantId,
          repositoryBindingId:
            input.context.scope.repositoryBindingId,
          scanRequestId:
            input.renameAttestation.fromScanRequestId,
          targetRef: previousScan?.targetRef,
          commitSha: previousScan?.commitSha,
          canonicalScanKey: previousScan?.canonicalKey,
          lane: previousScan?.lane
        }) ||
        previousPlan.profile.id !==
          input.renameAttestation.profileId ||
        previousPlan.profileDigest !==
          input.renameAttestation.profileDigest ||
        previousPlan.repositoryState.targetRef !==
          input.context.targetRef
      ) {
        throw new SastFindingLineageDurableScopeError();
      }
    }

    const existing =
      await transaction.sastFindingObservationBatch.findFirst({
        where: {
          tenantId: input.context.scope.tenantId,
          OR: [
            { id: input.observationBatchId },
            {
              sourceIdentityBatchDigest:
                input.batch.batchDigest
            },
            {
              scannerRunId:
                input.context.scope.scannerRunId
            }
          ]
        }
      });
    if (existing) {
      return this.replayObservation(
        transaction,
        input,
        existing,
        identities
      );
    }

    const resolved = await this.resolveIdentities(
      transaction,
      input,
      identities
    );
    const counts = {
      createdLineageCount: resolved.filter(
        (identity) => identity.match === 'CREATED'
      ).length,
      exactMatchCount: resolved.filter(
        (identity) => identity.match === 'EXACT'
      ).length,
      renamedMatchCount: resolved.filter(
        (identity) => identity.match === 'RENAMED'
      ).length
    };
    const observedAt = new Date(input.observedAt);
    const scope = input.context.scope;
    const lineageIds = resolved.map(
      (identity) => identity.lineageId
    );

    await transaction.sastFindingObservationBatch.create({
      data: {
        id: input.observationBatchId,
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        scannerRunId: scope.scannerRunId,
        lifecycleContextKey: input.lifecycleContextKey,
        targetRef: input.context.targetRef,
        commitSha: input.context.commitSha,
        lane: input.context.lane,
        scanner: input.context.scanner,
        capabilities: observedCapabilities(
          input.batch.findings
        ) as unknown as Prisma.InputJsonValue,
        profileId: input.context.profileId,
        profileDigest: input.context.profileDigest,
        canonicalScanKey: input.context.canonicalScanKey,
        planDigest: input.context.planDigest,
        sourceIdentityBatchDigest: input.batch.batchDigest,
        renameAttestationDigest:
          input.renameAttestationDigest ?? null,
        findingCount: input.batch.findings.length,
        distinctFingerprintCount: identities.length,
        ...counts,
        observedAt
      }
    });

    await this.createLineagesAndAliases(
      transaction,
      input,
      resolved,
      observedAt
    );
    await this.recordObservationStates(
      transaction,
      input,
      resolved,
      observedAt
    );
    await this.createOccurrences(
      transaction,
      input,
      resolved,
      observedAt
    );
    if (lineageIds.length > 0) {
      await transaction.sastFindingLineage.updateMany({
        where: {
          id: { in: lineageIds },
          tenantId: scope.tenantId,
          repositoryBindingId: scope.repositoryBindingId,
          lastObservedAt: { lt: observedAt }
        },
        data: { lastObservedAt: observedAt }
      });
    }
    await transaction.auditEvent.create({
      data: {
        id: deterministicId(
          'finding-audit',
          `${input.observationBatchId}\0OBSERVED`
        ),
        tenantId: scope.tenantId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        eventType: 'finding.lineage_observed',
        actor: 'scan-plane-finding-lineage',
        targetType: 'sast_finding_observation_batch',
        targetId: input.observationBatchId,
        occurredAt: observedAt,
        metadata: {
          version: SAST_FINDING_LINEAGE_VERSION,
          sourceIdentityBatchDigest: input.batch.batchDigest,
          lifecycleContextKey: input.lifecycleContextKey,
          findingCount: input.batch.findings.length,
          occurrenceCount: input.batch.findings.length,
          distinctFingerprintCount: identities.length,
          ...counts,
          renameAttestationVerified:
            input.renameAttestationDigest !== undefined
        }
      }
    });

    return {
      observationBatchId: input.observationBatchId,
      sourceIdentityBatchDigest: input.batch.batchDigest,
      lifecycleContextKey: input.lifecycleContextKey,
      findingCount: input.batch.findings.length,
      occurrenceCount: input.batch.findings.length,
      distinctFingerprintCount: identities.length,
      ...counts,
      replayed: false,
      observedAt: input.observedAt
    };
  }

  private async replayObservation(
    transaction: Prisma.TransactionClient,
    input: Readonly<PersistSastFindingObservationInput>,
    existing: {
      id: string;
      tenantId: string;
      repositoryBindingId: string;
      scanRequestId: string;
      attemptId: string;
      scannerRunId: string;
      lifecycleContextKey: string;
      targetRef: string;
      commitSha: string;
      lane: string;
      scanner: string;
      capabilities: Prisma.JsonValue;
      profileId: string;
      profileDigest: string;
      canonicalScanKey: string;
      planDigest: string;
      sourceIdentityBatchDigest: string;
      renameAttestationDigest: string | null;
      findingCount: number;
      distinctFingerprintCount: number;
      createdLineageCount: number;
      exactMatchCount: number;
      renamedMatchCount: number;
      observedAt: Date;
    },
    identities: readonly Readonly<PreparedIdentity>[]
  ): Promise<PersistedSastFindingObservation> {
    if (
      !observationBatchReplayMatches(
        existing,
        input,
        identities.length
      )
    ) {
      throw new SastFindingLineageReplayConflictError();
    }

    const resolved = await this.resolveIdentities(
      transaction,
      input,
      identities
    );
    const resolvedByIdentity = new Map(
      resolved.map((identity) => [identity.key, identity])
    );
    const occurrenceScope = {
      observationBatchId: existing.id,
      tenantId: existing.tenantId,
      repositoryBindingId: existing.repositoryBindingId,
      scanRequestId: existing.scanRequestId,
      attemptId: existing.attemptId,
      scannerRunId: existing.scannerRunId
    };
    const occurrenceCount =
      await transaction.sastFindingOccurrence.count({
        where: occurrenceScope
      });
    if (occurrenceCount !== existing.findingCount) {
      throw new SastFindingLineageReplayConflictError();
    }
    for (
      let start = 0;
      start < existing.findingCount;
      start += CREATE_MANY_CHUNK_SIZE
    ) {
      const end = Math.min(
        start + CREATE_MANY_CHUNK_SIZE,
        existing.findingCount
      );
      const occurrences =
        await transaction.sastFindingOccurrence.findMany({
          where: {
            ...occurrenceScope,
            ordinal: {
              gte: start,
              lt: end
            }
          },
          select: {
            id: true,
            tenantId: true,
            repositoryBindingId: true,
            scanRequestId: true,
            attemptId: true,
            scannerRunId: true,
            observationBatchId: true,
            lineageId: true,
            normalizedFindingId: true,
            ordinal: true,
            capability: true,
            fingerprintVersion: true,
            stableFingerprint: true,
            fingerprintDecisionDigest: true,
            sourceFinding: true,
            observedAt: true
          },
          orderBy: { ordinal: 'asc' }
        });
      if (
        occurrences.length !== end - start ||
        occurrences.some((occurrence, index) => {
          const ordinal = start + index;
          const finding = input.batch.findings[ordinal];
          if (!finding) return true;
          const resolvedIdentity = resolvedByIdentity.get(
            identityKey(
              finding.capability,
              finding.fingerprint.stableFingerprint
            )
          );
          return (
            !resolvedIdentity ||
            !occurrenceReplayMatches(
              occurrence,
              finding,
              resolvedIdentity.lineageId,
              input,
              existing.observedAt,
              ordinal
            )
          );
        })
      ) {
        throw new SastFindingLineageReplayConflictError();
      }
    }
    return {
      observationBatchId: existing.id,
      sourceIdentityBatchDigest:
        existing.sourceIdentityBatchDigest as `sha256:${string}`,
      lifecycleContextKey:
        existing.lifecycleContextKey as `sha256:${string}`,
      findingCount: existing.findingCount,
      occurrenceCount,
      distinctFingerprintCount:
        existing.distinctFingerprintCount,
      createdLineageCount: existing.createdLineageCount,
      exactMatchCount: existing.exactMatchCount,
      renamedMatchCount: existing.renamedMatchCount,
      replayed: true,
      observedAt: existing.observedAt.toISOString()
    };
  }

  private async resolveIdentities(
    transaction: Prisma.TransactionClient,
    input: Readonly<PersistSastFindingObservationInput>,
    identities: readonly Readonly<PreparedIdentity>[]
  ): Promise<ResolvedIdentity[]> {
    const scope = input.context.scope;
    const fingerprints = new Set<string>();
    for (const identity of identities) {
      fingerprints.add(identity.stableFingerprint);
      if (identity.rename) {
        fingerprints.add(
          identity.rename.previousStableFingerprint
        );
      }
    }
    const aliases: Array<{
      lineageId: string;
      capability: FindingCapability;
      stableFingerprint: string;
      normalizedPath: string;
    }> = [];
    for (const fingerprintChunk of chunks(
      [...fingerprints],
      READ_MANY_CHUNK_SIZE
    )) {
      aliases.push(
        ...(await transaction.sastFindingIdentityAlias.findMany({
          where: {
            tenantId: scope.tenantId,
            repositoryBindingId: scope.repositoryBindingId,
            fingerprintVersion:
              SAST_FINDING_FINGERPRINT_VERSION,
            stableFingerprint: {
              in: fingerprintChunk
            }
          },
          select: {
            lineageId: true,
            capability: true,
            stableFingerprint: true,
            normalizedPath: true
          }
        }))
      );
    }
    const aliasByIdentity = new Map(
      aliases.map((alias) => [
        identityKey(
          alias.capability,
          alias.stableFingerprint
        ),
        alias
      ])
    );
    const resolved: ResolvedIdentity[] = [];
    for (const identity of identities) {
      const exact = aliasByIdentity.get(identity.key);
      const predecessor = identity.rename
        ? aliasByIdentity.get(
            identityKey(
              identity.capability,
              identity.rename.previousStableFingerprint
            )
          )
        : undefined;
      if (identity.rename && !predecessor) {
        throw new SastFindingLineageRenameAmbiguousError();
      }
      if (
        (exact &&
          exact.normalizedPath !==
            identity.normalizedPath) ||
        (predecessor &&
          predecessor.normalizedPath !==
            identity.rename?.fromNormalizedPath)
      ) {
        throw new SastFindingLineageDurableScopeError();
      }
      if (
        exact &&
        predecessor &&
        exact.lineageId !== predecessor.lineageId
      ) {
        throw new SastFindingLineageRenameAmbiguousError();
      }
      if (predecessor) {
        resolved.push({
          ...identity,
          lineageId: predecessor.lineageId,
          match: 'RENAMED',
          currentAliasExists: exact !== undefined
        });
      } else if (exact) {
        resolved.push({
          ...identity,
          lineageId: exact.lineageId,
          match: 'EXACT',
          currentAliasExists: true
        });
      } else {
        resolved.push({
          ...identity,
          lineageId: lineageId(
            scope.tenantId,
            scope.repositoryBindingId,
            identity.capability,
            identity.stableFingerprint
          ),
          match: 'CREATED',
          currentAliasExists: false
        });
      }
    }

    const identityByLineage = new Map<string, string>();
    for (const identity of resolved) {
      const previous = identityByLineage.get(identity.lineageId);
      if (previous && previous !== identity.key) {
        throw new SastFindingLineageRenameAmbiguousError();
      }
      identityByLineage.set(identity.lineageId, identity.key);
    }

    const persistedLineages =
      resolved.length === 0
        ? []
        : await transaction.sastFindingLineage.findMany({
            where: {
              id: {
                in: resolved.map(
                  (identity) => identity.lineageId
                )
              }
            },
            select: {
              id: true,
              tenantId: true,
              repositoryBindingId: true,
              capability: true,
              fingerprintVersion: true
            }
          });
    const lineageById = new Map(
      persistedLineages.map((lineage) => [lineage.id, lineage])
    );
    for (const identity of resolved) {
      const persisted = lineageById.get(identity.lineageId);
      if (
        identity.match === 'CREATED'
          ? persisted !== undefined
          : !persisted ||
            persisted.tenantId !== scope.tenantId ||
            persisted.repositoryBindingId !==
              scope.repositoryBindingId ||
            persisted.capability !== identity.capability ||
            persisted.fingerprintVersion !==
              SAST_FINDING_FINGERPRINT_VERSION
      ) {
        throw new SastFindingLineageDurableScopeError();
      }
    }
    return resolved;
  }

  private async createLineagesAndAliases(
    transaction: Prisma.TransactionClient,
    input: Readonly<PersistSastFindingObservationInput>,
    identities: readonly Readonly<ResolvedIdentity>[],
    observedAt: Date
  ): Promise<void> {
    const scope = input.context.scope;
    const newLineages: Prisma.SastFindingLineageCreateManyInput[] =
      identities
        .filter((identity) => identity.match === 'CREATED')
        .map((identity) => ({
          id: identity.lineageId,
          tenantId: scope.tenantId,
          repositoryBindingId: scope.repositoryBindingId,
          capability: identity.capability,
          fingerprintVersion:
            SAST_FINDING_FINGERPRINT_VERSION,
          firstStableFingerprint:
            identity.stableFingerprint,
          firstObservedAt: observedAt,
          lastObservedAt: observedAt,
          createdAt: observedAt,
          updatedAt: observedAt
        }));
    if (newLineages.length > 0) {
      for (const rows of chunks(
        newLineages,
        CREATE_MANY_CHUNK_SIZE
      )) {
        await transaction.sastFindingLineage.createMany({
          data: rows
        });
      }
    }

    const aliases: Prisma.SastFindingIdentityAliasCreateManyInput[] =
      identities
        .filter((identity) => !identity.currentAliasExists)
        .map((identity) => ({
          id: deterministicId(
            'finding-alias',
            `${scope.tenantId}\0${scope.repositoryBindingId}\0${identity.capability}\0${SAST_FINDING_FINGERPRINT_VERSION}\0${identity.stableFingerprint}`
          ),
          tenantId: scope.tenantId,
          repositoryBindingId: scope.repositoryBindingId,
          lineageId: identity.lineageId,
          capability: identity.capability,
          fingerprintVersion:
            SAST_FINDING_FINGERPRINT_VERSION,
          stableFingerprint:
            identity.stableFingerprint,
          normalizedPath: identity.normalizedPath,
          renameAttestationDigest:
            identity.match === 'RENAMED'
              ? input.renameAttestationDigest
              : null,
          createdAt: observedAt
        }));
    if (aliases.length > 0) {
      for (const rows of chunks(
        aliases,
        CREATE_MANY_CHUNK_SIZE
      )) {
        await transaction.sastFindingIdentityAlias.createMany({
          data: rows
        });
      }
    }
  }

  private async recordObservationStates(
    transaction: Prisma.TransactionClient,
    input: Readonly<PersistSastFindingObservationInput>,
    identities: readonly Readonly<ResolvedIdentity>[],
    observedAt: Date
  ): Promise<void> {
    const scope = input.context.scope;
    const existingStates =
      identities.length === 0
        ? []
        : await transaction.sastFindingLifecycleState.findMany({
            where: {
              tenantId: scope.tenantId,
              repositoryBindingId: scope.repositoryBindingId,
              lifecycleContextKey:
                input.lifecycleContextKey,
              lineageId: {
                in: identities.map(
                  (identity) => identity.lineageId
                )
              }
            },
            select: {
              id: true,
              lineageId: true,
              status: true,
              revision: true,
              targetRef: true,
              lastObservedAt: true
            }
          });
    if (
      existingStates.some(
        (state) =>
          state.targetRef !== input.context.targetRef
      )
    ) {
      throw new SastFindingLineageDurableScopeError();
    }
    const stateByLineage = new Map(
      existingStates.map((state) => [state.lineageId, state])
    );
    const newStates: Prisma.SastFindingLifecycleStateCreateManyInput[] =
      [];
    const events: Prisma.SastFindingLifecycleEventCreateManyInput[] =
      [];
    const exactExistingStateIds: string[] = [];
    const renamedExistingStateIds: string[] = [];

    for (const identity of identities) {
      const existing = stateByLineage.get(identity.lineageId);
      const stateId =
        existing?.id ??
        deterministicId(
          'finding-state',
          `${input.lifecycleContextKey}\0${identity.lineageId}`
        );
      if (!existing) {
        const finalRevision =
          identity.match === 'RENAMED' ? 2 : 1;
        newStates.push({
          id: stateId,
          tenantId: scope.tenantId,
          repositoryBindingId: scope.repositoryBindingId,
          lineageId: identity.lineageId,
          lifecycleContextKey: input.lifecycleContextKey,
          targetRef: input.context.targetRef,
          status: 'OPEN',
          revision: finalRevision,
          lastObservedBatchId: input.observationBatchId,
          lastObservedScanRequestId: scope.scanRequestId,
          lastObservedCommitSha: input.context.commitSha,
          lastObservedAt: observedAt,
          lastReconciliationSequence: 0,
          fixedAt: null,
          reopenedAt: null,
          createdAt: observedAt,
          updatedAt: observedAt
        });
        events.push(
          lifecycleEvent({
            stateId,
            identity,
            input,
            kind: 'CREATED',
            previousStatus: null,
            nextStatus: 'OPEN',
            revision: 1,
            occurredAt: observedAt
          })
        );
        if (identity.match === 'RENAMED') {
          events.push(
            lifecycleEvent({
              stateId,
              identity,
              input,
              kind: 'RENAMED',
              previousStatus: 'OPEN',
              nextStatus: 'OPEN',
              revision: 2,
              occurredAt: observedAt
            })
          );
        }
      } else if (identity.match === 'RENAMED') {
        if (
          existing.lastObservedAt &&
          existing.lastObservedAt.getTime() >
            observedAt.getTime()
        ) {
          throw new SastFindingLineageReplayConflictError();
        }
        renamedExistingStateIds.push(existing.id);
        events.push(
          lifecycleEvent({
            stateId: existing.id,
            identity,
            input,
            kind: 'RENAMED',
            previousStatus: existing.status,
            nextStatus: existing.status,
            revision: existing.revision + 1,
            occurredAt: observedAt
          })
        );
      } else {
        exactExistingStateIds.push(existing.id);
      }
    }

    if (newStates.length > 0) {
      for (const rows of chunks(
        newStates,
        CREATE_MANY_CHUNK_SIZE
      )) {
        await transaction.sastFindingLifecycleState.createMany({
          data: rows
        });
      }
    }
    if (exactExistingStateIds.length > 0) {
      await transaction.sastFindingLifecycleState.updateMany({
        where: {
          id: { in: exactExistingStateIds },
          OR: [
            { lastObservedAt: null },
            { lastObservedAt: { lte: observedAt } }
          ]
        },
        data: {
          lastObservedBatchId: input.observationBatchId,
          lastObservedScanRequestId: scope.scanRequestId,
          lastObservedCommitSha: input.context.commitSha,
          lastObservedAt: observedAt
        }
      });
    }
    if (renamedExistingStateIds.length > 0) {
      const updated =
        await transaction.sastFindingLifecycleState.updateMany({
        where: {
          id: { in: renamedExistingStateIds },
          OR: [
            { lastObservedAt: null },
            { lastObservedAt: { lte: observedAt } }
          ]
        },
        data: {
          revision: { increment: 1 },
          lastObservedBatchId: input.observationBatchId,
          lastObservedScanRequestId: scope.scanRequestId,
          lastObservedCommitSha: input.context.commitSha,
          lastObservedAt: observedAt
        }
      });
      if (updated.count !== renamedExistingStateIds.length) {
        throw new SastFindingLineageReplayConflictError();
      }
    }
    if (events.length > 0) {
      for (const rows of chunks(
        events,
        CREATE_MANY_CHUNK_SIZE
      )) {
        await transaction.sastFindingLifecycleEvent.createMany({
          data: rows
        });
      }
    }
  }

  private async createOccurrences(
    transaction: Prisma.TransactionClient,
    input: Readonly<PersistSastFindingObservationInput>,
    identities: readonly Readonly<ResolvedIdentity>[],
    observedAt: Date
  ): Promise<void> {
    const resolvedByIdentity = new Map(
      identities.map((identity) => [identity.key, identity])
    );
    const normalizedRows: Prisma.NormalizedFindingCreateManyInput[] =
      [];
    const occurrenceRows: Prisma.SastFindingOccurrenceCreateManyInput[] =
      [];
    const scope = input.context.scope;
    for (
      let ordinal = 0;
      ordinal < input.batch.findings.length;
      ordinal += 1
    ) {
      const finding = input.batch.findings[ordinal];
      if (!finding) {
        throw new SastFindingLineageDurableScopeError();
      }
      const resolved = resolvedByIdentity.get(
        identityKey(
          finding.capability,
          finding.fingerprint.stableFingerprint
        )
      );
      if (!resolved) {
        throw new SastFindingLineageDurableScopeError();
      }
      const occurrenceId = deterministicId(
        'finding-occurrence',
        `${input.observationBatchId}\0${ordinal}\0${finding.fingerprint.decisionDigest}`
      );
      const normalizedFindingId = deterministicId(
        'normalized-finding',
        occurrenceId
      );
      const fileLocation =
        finding.location.kind === 'FILE'
          ? finding.location
          : null;
      normalizedRows.push({
        id: normalizedFindingId,
        tenantId: scope.tenantId,
        scanRequestId: scope.scanRequestId,
        scannerRunId: scope.scannerRunId,
        title: finding.title,
        severity: finding.severity,
        scannerProvenance: input.context.scanner,
        filePath: fileLocation?.normalizedPath ?? null,
        lineStart: fileLocation?.lineStart ?? null,
        lineEnd: fileLocation?.lineEnd ?? null,
        status: 'OPEN',
        metadata: normalizedFindingMetadata(
          finding,
          input.lifecycleContextKey
        ),
        sastCapability: finding.capability,
        sastFingerprintVersion:
          SAST_FINDING_FINGERPRINT_VERSION,
        sastStableFingerprint:
          finding.fingerprint.stableFingerprint,
        sastFingerprintDecisionDigest:
          finding.fingerprint.decisionDigest,
        sastLineageId: resolved.lineageId,
        sastObservationBatchId: input.observationBatchId,
        sastOccurrenceOrdinal: ordinal,
        createdAt: observedAt,
        updatedAt: observedAt
      });
      occurrenceRows.push({
        id: occurrenceId,
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        scannerRunId: scope.scannerRunId,
        observationBatchId: input.observationBatchId,
        lineageId: resolved.lineageId,
        normalizedFindingId,
        ordinal,
        capability: finding.capability,
        fingerprintVersion:
          SAST_FINDING_FINGERPRINT_VERSION,
        stableFingerprint:
          finding.fingerprint.stableFingerprint,
        fingerprintDecisionDigest:
          finding.fingerprint.decisionDigest,
        sourceFinding:
          finding as unknown as Prisma.InputJsonValue,
        observedAt,
        createdAt: observedAt
      });
    }
    for (const rows of chunks(
      normalizedRows,
      CREATE_MANY_CHUNK_SIZE
    )) {
      await transaction.normalizedFinding.createMany({
        data: rows
      });
    }
    for (const rows of chunks(
      occurrenceRows,
      CREATE_MANY_CHUNK_SIZE
    )) {
      await transaction.sastFindingOccurrence.createMany({
        data: rows
      });
    }
  }

  private async reconcileInTransaction(
    transaction: Prisma.TransactionClient,
    input: Readonly<PersistSastFindingReconciliationInput>
  ): Promise<PersistedSastFindingReconciliation> {
    const decision = input.decision;
    const currentContext = await this.readReconciliationContext(
      transaction.sastScanAttempt,
      {
        tenantId: decision.tenantId,
        repositoryBindingId: decision.repositoryBindingId,
        scanRequestId: decision.scanRequestId,
        attemptId: decision.attemptId
      }
    );
    if (
      !currentContext ||
      !sameReconciliationContext(currentContext, input.context)
    ) {
      throw new SastFindingLineageDurableScopeError();
    }

    const existing =
      await transaction.sastFindingLifecycleReconciliation.findFirst(
        {
          where: {
            OR: [
              { id: input.reconciliationId },
              {
                coverageDecisionDigest:
                  decision.decisionDigest
              },
              {
                tenantId: decision.tenantId,
                repositoryBindingId:
                  decision.repositoryBindingId,
                lifecycleContextKey:
                  decision.lifecycleContextKey,
                sequence: decision.sequence
              }
            ]
          }
        }
      );
    if (existing) {
      if (
        existing.id !== input.reconciliationId ||
        existing.coverageDecisionDigest !==
          decision.decisionDigest ||
        existing.tenantId !== decision.tenantId ||
        existing.repositoryBindingId !==
          decision.repositoryBindingId ||
        existing.scanRequestId !== decision.scanRequestId ||
        existing.attemptId !== decision.attemptId ||
        existing.lifecycleContextKey !==
          decision.lifecycleContextKey ||
        existing.sequence !== decision.sequence ||
        existing.profileId !== decision.profileId ||
        existing.profileDigest !== decision.profileDigest ||
        existing.eligibleLineageCount !==
          decision.eligibleLineageIds.length ||
        !isSastFindingLifecycleCoverageDecisionShapeValid(
          existing.coverageDecision,
          digest
        ) ||
        existing.coverageDecision.decisionDigest !==
          decision.decisionDigest
      ) {
        throw new SastFindingLineageReplayConflictError();
      }
      return reconciliationFromRow(existing, true);
    }

    const latest =
      await transaction.sastFindingLifecycleReconciliation.findFirst(
        {
          where: {
            tenantId: decision.tenantId,
            repositoryBindingId:
              decision.repositoryBindingId,
            lifecycleContextKey:
              decision.lifecycleContextKey
          },
          orderBy: { sequence: 'desc' }
        }
      );
    if (
      (latest &&
        (decision.sequence !== latest.sequence + 1 ||
          decision.previousScanRequestId !==
            latest.scanRequestId ||
          Date.parse(input.reconciledAt) <=
            latest.reconciledAt.getTime())) ||
      (!latest && decision.sequence !== 1)
    ) {
      throw new SastFindingLineageReconciliationOrderError();
    }
    const previousScan = await transaction.scanRequest.findFirst({
      where: {
        id: decision.previousScanRequestId,
        tenantId: decision.tenantId,
        repositoryBindingId: decision.repositoryBindingId,
        targetRef: input.context.targetRef,
        commitSha: decision.previousCommitSha,
        status: 'COMPLETED'
      },
      select: {
        lane: true,
        targetRef: true,
        commitSha: true,
        canonicalKey: true,
        sastQueueReservation: {
          select: { immutablePlan: true }
        }
      }
    });
    const previousPlan = parsePlan(
      previousScan?.sastQueueReservation?.immutablePlan
    );
    if (
      !previousPlan ||
      !isPlanBoundToScanRequest(previousPlan, {
        tenantId: decision.tenantId,
        repositoryBindingId:
          decision.repositoryBindingId,
        scanRequestId: decision.previousScanRequestId,
        targetRef: previousScan?.targetRef,
        commitSha: previousScan?.commitSha,
        canonicalScanKey: previousScan?.canonicalKey,
        lane: previousScan?.lane
      }) ||
      previousPlan.profile.id !== decision.profileId ||
      previousPlan.profileDigest !== decision.profileDigest
    ) {
      throw new SastFindingLineageDurableScopeError();
    }

    const batches =
      await transaction.sastFindingObservationBatch.findMany({
        where: {
          tenantId: decision.tenantId,
          repositoryBindingId: decision.repositoryBindingId,
          scanRequestId: decision.scanRequestId,
          attemptId: decision.attemptId,
          lifecycleContextKey:
            decision.lifecycleContextKey,
          profileId: decision.profileId,
          profileDigest: decision.profileDigest
        },
        select: {
          id: true,
          sourceIdentityBatchDigest: true,
          capabilities: true,
          scanner: true,
          targetRef: true,
          commitSha: true,
          lane: true,
          profileId: true,
          profileDigest: true,
          canonicalScanKey: true,
          planDigest: true,
          observedAt: true
        }
      });
    const decisionDecidedAt = Date.parse(decision.decidedAt);
    const reconciledAtTime = Date.parse(input.reconciledAt);
    const durableBatchInvalid = batches.some((batch) => {
      try {
        readCapabilities(batch.capabilities, batch.scanner);
      } catch {
        return true;
      }
      return (
        batch.targetRef !== input.context.targetRef ||
        batch.commitSha !== decision.commitSha ||
        batch.lane !== input.context.lane ||
        batch.profileId !== decision.profileId ||
        batch.profileDigest !== decision.profileDigest ||
        batch.canonicalScanKey !==
          decision.canonicalScanKey ||
        batch.planDigest !== decision.planDigest ||
        batch.observedAt.getTime() > decisionDecidedAt ||
        batch.observedAt.getTime() > reconciledAtTime
      );
    });
    const observedBatchDigests = batches
      .map((batch) => batch.sourceIdentityBatchDigest)
      .sort();
    if (
      durableBatchInvalid ||
      !sameStringArray(
        observedBatchDigests,
        decision.expectedObservationBatchDigests
      )
    ) {
      throw new SastFindingLineageObservationIncompleteError();
    }
    const relevantBatches = batches;

    const eligibleIds = decision.eligibleLineageIds;
    const lineages =
      eligibleIds.length === 0
        ? []
        : await transaction.sastFindingLineage.findMany({
            where: {
              id: { in: eligibleIds },
              tenantId: decision.tenantId,
              repositoryBindingId:
                decision.repositoryBindingId,
              capability: {
                in: decision.completeCapabilities
              }
            },
            select: {
              id: true,
              capability: true,
              fingerprintVersion: true
            }
          });
    if (
      lineages.length !== eligibleIds.length ||
      lineages.some(
        (lineage) =>
          lineage.fingerprintVersion !==
            SAST_FINDING_FINGERPRINT_VERSION ||
          !decision.completeCapabilities.includes(
            lineage.capability
          )
      )
    ) {
      throw new SastFindingLineageObservationIncompleteError();
    }

    const observedRows =
      relevantBatches.length === 0
        ? []
        : await transaction.sastFindingOccurrence.findMany({
            where: {
              observationBatchId: {
                in: relevantBatches.map((batch) => batch.id)
              },
              capability: {
                in: decision.completeCapabilities
              }
            },
            select: {
              lineageId: true,
              capability: true,
              fingerprintVersion: true,
              lineage: {
                select: {
                  capability: true,
                  fingerprintVersion: true
                }
              }
            },
            distinct: ['lineageId']
          });
    const eligible = new Set(eligibleIds);
    if (
      observedRows.some(
        (row) =>
          !eligible.has(row.lineageId) ||
          row.capability !== row.lineage.capability ||
          row.fingerprintVersion !==
            SAST_FINDING_FINGERPRINT_VERSION ||
          row.lineage.fingerprintVersion !==
            SAST_FINDING_FINGERPRINT_VERSION
      )
    ) {
      throw new SastFindingLineageObservationIncompleteError();
    }
    const observed = new Set(
      observedRows.map((row) => row.lineageId)
    );
    const states =
      eligibleIds.length === 0
        ? []
        : await transaction.sastFindingLifecycleState.findMany({
            where: {
              tenantId: decision.tenantId,
              repositoryBindingId:
                decision.repositoryBindingId,
              lifecycleContextKey:
                decision.lifecycleContextKey,
              lineageId: { in: eligibleIds }
            },
            select: {
              id: true,
              lineageId: true,
              status: true,
              revision: true,
              targetRef: true,
              lastReconciliationSequence: true
            }
          });
    const expectedPreviousSequence = latest?.sequence ?? 0;
    if (
      states.length !== eligibleIds.length ||
      states.some(
        (state) =>
          state.targetRef !== input.context.targetRef ||
          state.lastReconciliationSequence >
            expectedPreviousSequence
      )
    ) {
      throw new SastFindingLineageObservationIncompleteError();
    }

    const fixed = states.filter(
      (state) =>
        state.status === 'OPEN' && !observed.has(state.lineageId)
    );
    const reopened = states.filter(
      (state) =>
        state.status === 'FIXED' && observed.has(state.lineageId)
    );
    const unchangedOpen = states.filter(
      (state) =>
        state.status === 'OPEN' && observed.has(state.lineageId)
    );
    const unchangedFixed = states.filter(
      (state) =>
        state.status === 'FIXED' &&
        !observed.has(state.lineageId)
    );
    const reconciledAt = new Date(input.reconciledAt);

    await updateLifecycleStates(
      transaction,
      fixed,
      reopened,
      unchangedOpen,
      unchangedFixed,
      decision.sequence,
      reconciledAt
    );
    const counts = {
      eligibleLineageCount: eligibleIds.length,
      observedLineageCount: observed.size,
      fixedCount: fixed.length,
      reopenedCount: reopened.length,
      unchangedOpenCount: unchangedOpen.length,
      unchangedFixedCount: unchangedFixed.length
    };
    await transaction.sastFindingLifecycleReconciliation.create({
      data: {
        id: input.reconciliationId,
        tenantId: decision.tenantId,
        repositoryBindingId: decision.repositoryBindingId,
        scanRequestId: decision.scanRequestId,
        attemptId: decision.attemptId,
        lifecycleContextKey:
          decision.lifecycleContextKey,
        sequence: decision.sequence,
        profileId: decision.profileId,
        profileDigest: decision.profileDigest,
        coverageDecision:
          decision as unknown as Prisma.InputJsonValue,
        coverageDecisionDigest: decision.decisionDigest,
        ...counts,
        reconciledAt
      }
    });
    const transitionEvents = [
      ...fixed.map((state) =>
        reconciliationEvent(
          state,
          input,
          'FIXED',
          'OPEN',
          'FIXED',
          reconciledAt
        )
      ),
      ...reopened.map((state) =>
        reconciliationEvent(
          state,
          input,
          'REOPENED',
          'FIXED',
          'OPEN',
          reconciledAt
        )
      )
    ];
    if (transitionEvents.length > 0) {
      for (const rows of chunks(
        transitionEvents,
        CREATE_MANY_CHUNK_SIZE
      )) {
        await transaction.sastFindingLifecycleEvent.createMany({
          data: rows
        });
      }
    }
    await transaction.auditEvent.create({
      data: {
        id: deterministicId(
          'finding-audit',
          `${input.reconciliationId}\0RECONCILED`
        ),
        tenantId: decision.tenantId,
        scanRequestId: decision.scanRequestId,
        attemptId: decision.attemptId,
        eventType: 'finding.lifecycle_reconciled',
        actor: 'scan-plane-finding-lineage',
        targetType: 'sast_finding_lifecycle_reconciliation',
        targetId: input.reconciliationId,
        occurredAt: reconciledAt,
        metadata: {
          version: SAST_FINDING_LINEAGE_VERSION,
          coverageDecisionDigest: decision.decisionDigest,
          sourceCoverageDecisionDigest:
            decision.sourceCoverageDecisionDigest,
          lifecycleContextKey:
            decision.lifecycleContextKey,
          sequence: decision.sequence,
          ...counts
        }
      }
    });
    return {
      reconciliationId: input.reconciliationId,
      coverageDecisionDigest: decision.decisionDigest,
      lifecycleContextKey:
        decision.lifecycleContextKey,
      sequence: decision.sequence,
      ...counts,
      replayed: false,
      reconciledAt: input.reconciledAt
    };
  }

  private async readObservationContext(
    delegate: Prisma.TransactionClient['scannerRun'],
    scope: Readonly<SastFindingLineageObservationScope>
  ): Promise<SastFindingLineageScanContext | null> {
    const row = await delegate.findFirst({
      where: {
        id: scope.scannerRunId,
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        status: 'COMPLETED',
        artifactIngestion: {
          status: 'ACCEPTED',
          dispositionDecision: {
            disposition: 'ACCEPTED',
            normalizationEligible: true
          }
        }
      },
      select: {
        scanner: true,
        scannerVersion: true,
        scannerImageDigest: true,
        ruleBundleDigest: true,
        databaseDigest: true,
        schemaBundleDigest: true,
        normalizerBundleDigest: true,
        profileId: true,
        profileDigest: true,
        preflightAttestationRef: true,
        preflightInventoryDigest: true,
        artifactSchema: true,
        artifactSchemaVersion: true,
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
        },
        artifactIngestion: {
          select: {
            id: true,
            envelopeDigest: true,
            observedContentDigest: true,
            retentionExpiresAt: true,
            dispositionDecision: {
              select: {
                validationResultDigest: true,
                decisionDigest: true,
                retentionExpiresAt: true
              }
            }
          }
        }
      }
    });
    if (!row) return null;
    const plan = parsePlan(
      row.scanRequest.sastQueueReservation?.immutablePlan
    );
    const ingestion = row.artifactIngestion;
    const disposition = ingestion?.dispositionDecision;
    const findingScanner = isFindingScannerKind(row.scanner)
      ? row.scanner
      : null;
    const scannerRuntime =
      plan && findingScanner
        ? plan.scannerSet.scanners[findingScanner]
        : null;
    const expectedRuleBundle =
      plan && findingScanner
        ? plan.scannerSet.ruleBundles.find(
            (bundle) => bundle.scanner === findingScanner
          )
        : undefined;
    const expectedArtifactSchema = findingScanner
      ? SAST_SCANNER_RESPONSIBILITIES[findingScanner]
          .outputSchema
      : null;
    if (
      !plan ||
      !ingestion ||
      !disposition ||
      !ingestion.observedContentDigest ||
      !ingestion.retentionExpiresAt ||
      !disposition.retentionExpiresAt ||
      ingestion.retentionExpiresAt.getTime() !==
        disposition.retentionExpiresAt.getTime() ||
      !isDigest(row.scannerImageDigest) ||
      !isDigest(row.schemaBundleDigest) ||
      !isDigest(row.normalizerBundleDigest) ||
      !isDigest(row.profileDigest) ||
      !isDigest(row.preflightInventoryDigest) ||
      !isDigest(ingestion.envelopeDigest) ||
      !isDigest(ingestion.observedContentDigest) ||
      !isDigest(disposition.validationResultDigest) ||
      !isDigest(disposition.decisionDigest) ||
      typeof row.preflightAttestationRef !== 'string' ||
      row.preflightAttestationRef.length === 0 ||
      typeof row.artifactSchema !== 'string' ||
      row.artifactSchema.length === 0 ||
      typeof row.artifactSchemaVersion !== 'string' ||
      row.artifactSchemaVersion.length === 0 ||
      !row.profileId ||
      !SAST_PROFILE_IDS.includes(
        row.profileId as (typeof SAST_PROFILE_IDS)[number]
      ) ||
      !SAST_SCAN_LANES.includes(row.scanRequest.lane) ||
      !findingScanner ||
      !scannerRuntime ||
      !expectedRuleBundle ||
      !isDigest(row.ruleBundleDigest) ||
      (row.scanner === 'TRIVY'
        ? !isDigest(row.databaseDigest)
        : row.databaseDigest !== null) ||
      plan.tenantId !== scope.tenantId ||
      plan.scanRequestId !== scope.scanRequestId ||
      plan.repositoryState.repositoryBindingId !==
        scope.repositoryBindingId ||
      plan.repositoryState.targetRef !==
        row.scanRequest.targetRef ||
      plan.repositoryState.fixedCommitSha !==
        row.scanRequest.commitSha ||
      plan.canonicalScanKey !== row.scanRequest.canonicalKey ||
      plan.profile.lane !== row.scanRequest.lane ||
      plan.profile.id !== row.profileId ||
      plan.profileDigest !== row.profileDigest ||
      !(
        plan.profile.requiredScanners.includes(
          findingScanner
        ) ||
        plan.profile.optionalScanners.includes(
          findingScanner
        )
      ) ||
      row.scannerVersion !== scannerRuntime.version ||
      row.scannerImageDigest !== scannerRuntime.digest ||
      row.ruleBundleDigest !== expectedRuleBundle.digest ||
      (findingScanner === 'TRIVY'
        ? row.databaseDigest !==
          plan.scannerSet.vulnerabilityDatabase.digest
        : row.databaseDigest !== null) ||
      row.schemaBundleDigest !==
        plan.scannerSet.schemaBundle.digest ||
      row.normalizerBundleDigest !==
        plan.scannerSet.normalizerBundle.digest ||
      row.preflightAttestationRef !==
        plan.repositoryState.attestationRef ||
      row.preflightInventoryDigest !==
        plan.repositoryState.inventoryDigest ||
      row.artifactSchema !== expectedArtifactSchema ||
      row.artifactSchemaVersion !==
        SAST_ARTIFACT_SCHEMA_VERSIONS[
          expectedArtifactSchema
        ]
    ) {
      return null;
    }
    return {
      scope: { ...scope },
      targetRef: row.scanRequest.targetRef,
      lane: row.scanRequest.lane,
      commitSha: row.scanRequest.commitSha,
      canonicalScanKey:
        row.scanRequest.canonicalKey as `sha256:${string}`,
      planDigest: digest(
        buildSastScanPlanDigestPreimage(plan)
      ),
      profileId:
        row.profileId as (typeof SAST_PROFILE_IDS)[number],
      profileDigest: row.profileDigest,
      scanner: findingScanner,
      source: {
        ingestionId: ingestion.id,
        scannerVersion: row.scannerVersion,
        scannerImageDigest: row.scannerImageDigest,
        ...(isDigest(row.ruleBundleDigest)
          ? { ruleBundleDigest: row.ruleBundleDigest }
          : {}),
        ...(isDigest(row.databaseDigest)
          ? {
              vulnerabilityDatabaseDigest:
                row.databaseDigest
            }
          : {}),
        schemaBundleDigest: row.schemaBundleDigest,
        normalizerBundleDigest:
          row.normalizerBundleDigest,
        preflightAttestationRef:
          row.preflightAttestationRef,
        preflightInventoryDigest:
          row.preflightInventoryDigest,
        artifactSchema: row.artifactSchema,
        artifactSchemaVersion:
          row.artifactSchemaVersion,
        envelopeDigest: ingestion.envelopeDigest,
        artifactDigest: ingestion.observedContentDigest,
        validationResultDigest:
          disposition.validationResultDigest,
        dispositionDecisionDigest:
          disposition.decisionDigest,
        retentionExpiresAt:
          ingestion.retentionExpiresAt.toISOString()
      }
    };
  }

  private async readReconciliationContext(
    delegate: Prisma.TransactionClient['sastScanAttempt'],
    input: {
      tenantId: string;
      repositoryBindingId: string;
      scanRequestId: string;
      attemptId: string;
    }
  ): Promise<SastFindingReconciliationScanContext | null> {
    const row = await delegate.findFirst({
      where: {
        id: input.attemptId,
        tenantId: input.tenantId,
        repositoryBindingId: input.repositoryBindingId,
        scanRequestId: input.scanRequestId,
        stage: {
          in: ['SCANNING', 'CLEANUP_PENDING', 'COMPLETED']
        },
        scanRequest: {
          status: { in: ['RUNNING', 'COMPLETED'] }
        }
      },
      select: {
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
    if (!row) return null;
    const plan = parsePlan(
      row.scanRequest.sastQueueReservation?.immutablePlan
    );
    if (
      !plan ||
      plan.tenantId !== input.tenantId ||
      plan.scanRequestId !== input.scanRequestId ||
      plan.repositoryState.repositoryBindingId !==
        input.repositoryBindingId ||
      plan.repositoryState.targetRef !==
        row.scanRequest.targetRef ||
      plan.repositoryState.fixedCommitSha !==
        row.scanRequest.commitSha ||
      plan.canonicalScanKey !== row.scanRequest.canonicalKey ||
      plan.profile.lane !== row.scanRequest.lane
    ) {
      return null;
    }
    return {
      ...input,
      targetRef: row.scanRequest.targetRef,
      lane: row.scanRequest.lane,
      commitSha: row.scanRequest.commitSha,
      canonicalScanKey:
        row.scanRequest.canonicalKey as `sha256:${string}`,
      planDigest: digest(
        buildSastScanPlanDigestPreimage(plan)
      ),
      profileId: plan.profile.id,
      profileDigest: plan.profileDigest
    };
  }

  private async runSerializable<T>(
    operation: (
      transaction: Prisma.TransactionClient
    ) => Promise<T>
  ): Promise<T> {
    let lastError: unknown;
    for (
      let attempt = 0;
      attempt < SERIALIZABLE_ATTEMPTS;
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
        if (!isRetryableTransactionError(error)) throw error;
      }
    }
    throw lastError;
  }
}

async function updateLifecycleStates(
  transaction: Prisma.TransactionClient,
  fixed: readonly { id: string }[],
  reopened: readonly { id: string }[],
  unchangedOpen: readonly { id: string }[],
  unchangedFixed: readonly { id: string }[],
  sequence: number,
  reconciledAt: Date
): Promise<void> {
  const previousSequence = sequence - 1;
  if (fixed.length > 0) {
    const updated =
      await transaction.sastFindingLifecycleState.updateMany({
      where: {
        id: { in: fixed.map((state) => state.id) },
        status: 'OPEN',
        lastReconciliationSequence: {
          lte: previousSequence
        }
      },
      data: {
        status: 'FIXED',
        revision: { increment: 1 },
        lastReconciliationSequence: sequence,
        fixedAt: reconciledAt,
        updatedAt: reconciledAt
      }
    });
    if (updated.count !== fixed.length) {
      throw new SastFindingLineageReconciliationOrderError();
    }
  }
  if (reopened.length > 0) {
    const updated =
      await transaction.sastFindingLifecycleState.updateMany({
      where: {
        id: { in: reopened.map((state) => state.id) },
        status: 'FIXED',
        lastReconciliationSequence: {
          lte: previousSequence
        }
      },
      data: {
        status: 'OPEN',
        revision: { increment: 1 },
        lastReconciliationSequence: sequence,
        fixedAt: null,
        reopenedAt: reconciledAt,
        updatedAt: reconciledAt
      }
    });
    if (updated.count !== reopened.length) {
      throw new SastFindingLineageReconciliationOrderError();
    }
  }
  if (unchangedOpen.length > 0) {
    const updated =
      await transaction.sastFindingLifecycleState.updateMany({
      where: {
        id: {
          in: unchangedOpen.map((state) => state.id)
        },
        status: 'OPEN',
        lastReconciliationSequence: {
          lte: previousSequence
        }
      },
      data: {
        lastReconciliationSequence: sequence,
        updatedAt: reconciledAt
      }
    });
    if (updated.count !== unchangedOpen.length) {
      throw new SastFindingLineageReconciliationOrderError();
    }
  }
  if (unchangedFixed.length > 0) {
    const updated =
      await transaction.sastFindingLifecycleState.updateMany({
      where: {
        id: {
          in: unchangedFixed.map((state) => state.id)
        },
        status: 'FIXED',
        lastReconciliationSequence: {
          lte: previousSequence
        }
      },
      data: {
        lastReconciliationSequence: sequence,
        updatedAt: reconciledAt
      }
    });
    if (updated.count !== unchangedFixed.length) {
      throw new SastFindingLineageReconciliationOrderError();
    }
  }
}

function isObservationPersistenceInputValid(
  input: Readonly<PersistSastFindingObservationInput>
): boolean {
  if (
    !observationBatchMatchesContext(
      input.batch,
      input.context
    ) ||
    !isCanonicalIsoTimestamp(input.observedAt) ||
    Date.parse(input.observedAt) >=
      Date.parse(input.context.source.retentionExpiresAt)
  ) {
    return false;
  }
  const lifecycleContext = {
    tenantId: input.context.scope.tenantId,
    repositoryBindingId:
      input.context.scope.repositoryBindingId,
    targetRef: input.context.targetRef
  };
  if (
    !isSastFindingLifecycleContextInputValid(
      lifecycleContext
    ) ||
    digest(
      buildSastFindingLifecycleContextPreimage(
        lifecycleContext
      )
    ) !== input.lifecycleContextKey
  ) {
    return false;
  }
  if (input.renameAttestation === undefined) {
    return (
      input.renameAttestationDigest === undefined &&
      input.renameCandidates.length === 0
    );
  }
  const attestation = input.renameAttestation;
  if (
    !isSastFindingRenameAttestationShapeValid(
      attestation,
      digest
    ) ||
    input.renameAttestationDigest !==
      attestation.attestationDigest ||
    attestation.tenantId !==
      input.context.scope.tenantId ||
    attestation.repositoryBindingId !==
      input.context.scope.repositoryBindingId ||
    attestation.lifecycleContextKey !==
      input.lifecycleContextKey ||
    attestation.toScanRequestId !==
      input.context.scope.scanRequestId ||
    attestation.toCommitSha !== input.context.commitSha ||
    attestation.profileId !== input.context.profileId ||
    attestation.profileDigest !==
      input.context.profileDigest ||
    Date.parse(attestation.issuedAt) >
      Date.parse(input.observedAt)
  ) {
    return false;
  }
  const entries = new Map(
    attestation.entries.map((entry) => [
      entry.toNormalizedPath,
      entry
    ])
  );
  const expected = new Map<
    string,
    SastFindingRenameCandidate
  >();
  for (const finding of input.batch.findings) {
    const entry = entries.get(
      finding.fingerprint.normalizedPath
    );
    if (!entry) continue;
    const key = identityKey(
      finding.capability,
      finding.fingerprint.stableFingerprint
    );
    expected.set(key, {
      capability: finding.capability,
      currentStableFingerprint:
        finding.fingerprint.stableFingerprint,
      previousStableFingerprint: digest(
        buildFindingFingerprintPreimage(
          projectRenamedSastFindingFingerprintInput(
            finding.fingerprint,
            entry.fromNormalizedPath
          )
        )
      ),
      fromNormalizedPath: entry.fromNormalizedPath,
      toNormalizedPath: entry.toNormalizedPath
    });
  }
  const expectedCandidates = [...expected.values()].sort(
    compareRenameCandidates
  );
  return (
    expectedCandidates.length > 0 &&
    JSON.stringify(expectedCandidates) ===
      JSON.stringify(input.renameCandidates)
  );
}

function isReconciliationPersistenceInputValid(
  input: Readonly<PersistSastFindingReconciliationInput>
): boolean {
  const context = input.context;
  const lifecycleContext = {
    tenantId: context.tenantId,
    repositoryBindingId: context.repositoryBindingId,
    targetRef: context.targetRef
  };
  return (
    isSastFindingLifecycleContextInputValid(
      lifecycleContext
    ) &&
    digest(
      buildSastFindingLifecycleContextPreimage(
        lifecycleContext
      )
    ) === input.decision.lifecycleContextKey &&
    input.decision.tenantId === context.tenantId &&
    input.decision.repositoryBindingId ===
      context.repositoryBindingId &&
    input.decision.scanRequestId === context.scanRequestId &&
    input.decision.attemptId === context.attemptId &&
    input.decision.commitSha === context.commitSha &&
    input.decision.canonicalScanKey ===
      context.canonicalScanKey &&
    input.decision.planDigest === context.planDigest &&
    input.decision.profileId === context.profileId &&
    input.decision.profileDigest === context.profileDigest
  );
}

function observationBatchMatchesContext(
  batch: Readonly<PersistSastFindingObservationInput['batch']>,
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
    batch.ruleBundleDigest ===
      context.source.ruleBundleDigest &&
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

function compareRenameCandidates(
  left: Readonly<SastFindingRenameCandidate>,
  right: Readonly<SastFindingRenameCandidate>
): number {
  return JSON.stringify([
    left.capability,
    left.currentStableFingerprint
  ]).localeCompare(
    JSON.stringify([
      right.capability,
      right.currentStableFingerprint
    ])
  );
}

function prepareIdentities(
  input: Readonly<PersistSastFindingObservationInput>
): PreparedIdentity[] {
  const renameByCurrent = new Map(
    input.renameCandidates.map((candidate) => [
      identityKey(
        candidate.capability,
        candidate.currentStableFingerprint
      ),
      candidate
    ])
  );
  const identities = new Map<string, PreparedIdentity>();
  for (const finding of input.batch.findings) {
    const key = identityKey(
      finding.capability,
      finding.fingerprint.stableFingerprint
    );
    if (!identities.has(key)) {
      identities.set(key, {
        key,
        capability: finding.capability,
        stableFingerprint:
          finding.fingerprint.stableFingerprint,
        normalizedPath:
          finding.fingerprint.normalizedPath,
        ...(renameByCurrent.has(key)
          ? { rename: renameByCurrent.get(key) }
          : {})
      });
    }
  }
  if (
    [...renameByCurrent.keys()].some(
      (key) => !identities.has(key)
    )
  ) {
    throw new SastFindingLineageDurableScopeError();
  }
  return [...identities.values()].sort((left, right) =>
    left.key.localeCompare(right.key)
  );
}

function lifecycleEvent(input: {
  stateId: string;
  identity: Readonly<ResolvedIdentity>;
  input: Readonly<PersistSastFindingObservationInput>;
  kind: 'CREATED' | 'RENAMED';
  previousStatus: SastFindingLifecycleStatus | null;
  nextStatus: SastFindingLifecycleStatus;
  revision: number;
  occurredAt: Date;
}): Prisma.SastFindingLifecycleEventCreateManyInput {
  const scope = input.input.context.scope;
  return {
    id: deterministicId(
      'finding-event',
      `${input.stateId}\0${input.revision}\0${input.kind}\0${input.input.observationBatchId}`
    ),
    tenantId: scope.tenantId,
    repositoryBindingId: scope.repositoryBindingId,
    lineageId: input.identity.lineageId,
    lifecycleStateId: input.stateId,
    lifecycleContextKey: input.input.lifecycleContextKey,
    kind: input.kind,
    previousStatus: input.previousStatus,
    nextStatus: input.nextStatus,
    revision: input.revision,
    observationBatchId: input.input.observationBatchId,
    reconciliationId: null,
    renameAttestationDigest:
      input.kind === 'RENAMED'
        ? input.input.renameAttestationDigest
        : null,
    occurredAt: input.occurredAt,
    createdAt: input.occurredAt
  };
}

function reconciliationEvent(
  state: {
    id: string;
    lineageId: string;
    revision: number;
  },
  input: Readonly<PersistSastFindingReconciliationInput>,
  kind: 'FIXED' | 'REOPENED',
  previousStatus: SastFindingLifecycleStatus,
  nextStatus: SastFindingLifecycleStatus,
  occurredAt: Date
): Prisma.SastFindingLifecycleEventCreateManyInput {
  return {
    id: deterministicId(
      'finding-event',
      `${state.id}\0${state.revision + 1}\0${kind}\0${input.reconciliationId}`
    ),
    tenantId: input.decision.tenantId,
    repositoryBindingId:
      input.decision.repositoryBindingId,
    lineageId: state.lineageId,
    lifecycleStateId: state.id,
    lifecycleContextKey:
      input.decision.lifecycleContextKey,
    kind,
    previousStatus,
    nextStatus,
    revision: state.revision + 1,
    observationBatchId: null,
    reconciliationId: input.reconciliationId,
    renameAttestationDigest: null,
    occurredAt,
    createdAt: occurredAt
  };
}

function normalizedFindingMetadata(
  finding: Readonly<SastFingerprintedFinding>,
  lifecycleContextKey: `sha256:${string}`
): Prisma.InputJsonValue {
  return {
    version: SAST_FINDING_LINEAGE_VERSION,
    lifecycleContextKey,
    description: finding.description,
    confidence: finding.confidence,
    cweIds: [...finding.cweIds],
    cveIds: [...finding.cveIds],
    location: finding.location,
    identityMaterial: finding.identityMaterial,
    provenance: finding.provenance,
    notes: [...finding.notes],
    lifecycleStatusAuthority: false,
    lifecycleStatusStoredSeparately: true
  } as unknown as Prisma.InputJsonValue;
}

function reconciliationFromRow(
  row: {
    id: string;
    coverageDecisionDigest: string;
    lifecycleContextKey: string;
    sequence: number;
    eligibleLineageCount: number;
    observedLineageCount: number;
    fixedCount: number;
    reopenedCount: number;
    unchangedOpenCount: number;
    unchangedFixedCount: number;
    reconciledAt: Date;
  },
  replayed: boolean
): PersistedSastFindingReconciliation {
  return {
    reconciliationId: row.id,
    coverageDecisionDigest:
      row.coverageDecisionDigest as `sha256:${string}`,
    lifecycleContextKey:
      row.lifecycleContextKey as `sha256:${string}`,
    sequence: row.sequence,
    eligibleLineageCount: row.eligibleLineageCount,
    observedLineageCount: row.observedLineageCount,
    fixedCount: row.fixedCount,
    reopenedCount: row.reopenedCount,
    unchangedOpenCount: row.unchangedOpenCount,
    unchangedFixedCount: row.unchangedFixedCount,
    replayed,
    reconciledAt: row.reconciledAt.toISOString()
  };
}

function observationBatchReplayMatches(
  existing: {
    id: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    scannerRunId: string;
    lifecycleContextKey: string;
    targetRef: string;
    commitSha: string;
    lane: string;
    scanner: string;
    capabilities: Prisma.JsonValue;
    profileId: string;
    profileDigest: string;
    canonicalScanKey: string;
    planDigest: string;
    sourceIdentityBatchDigest: string;
    renameAttestationDigest: string | null;
    findingCount: number;
    distinctFingerprintCount: number;
    createdLineageCount: number;
    exactMatchCount: number;
    renamedMatchCount: number;
    observedAt: Date;
  },
  input: Readonly<PersistSastFindingObservationInput>,
  identityCount: number
): boolean {
  let capabilities: FindingCapability[];
  try {
    capabilities = readCapabilities(
      existing.capabilities,
      existing.scanner
    );
  } catch {
    return false;
  }
  const scope = input.context.scope;
  return (
    existing.id === input.observationBatchId &&
    existing.tenantId === scope.tenantId &&
    existing.repositoryBindingId ===
      scope.repositoryBindingId &&
    existing.scanRequestId === scope.scanRequestId &&
    existing.attemptId === scope.attemptId &&
    existing.scannerRunId === scope.scannerRunId &&
    existing.lifecycleContextKey ===
      input.lifecycleContextKey &&
    existing.targetRef === input.context.targetRef &&
    existing.commitSha === input.context.commitSha &&
    existing.lane === input.context.lane &&
    existing.scanner === input.context.scanner &&
    sameStringArray(
      capabilities,
      observedCapabilities(input.batch.findings)
    ) &&
    existing.profileId === input.context.profileId &&
    existing.profileDigest === input.context.profileDigest &&
    existing.canonicalScanKey ===
      input.context.canonicalScanKey &&
    existing.planDigest === input.context.planDigest &&
    existing.sourceIdentityBatchDigest ===
      input.batch.batchDigest &&
    existing.renameAttestationDigest ===
      (input.renameAttestationDigest ?? null) &&
    existing.findingCount === input.batch.findings.length &&
    existing.distinctFingerprintCount === identityCount &&
    existing.createdLineageCount >= 0 &&
    existing.exactMatchCount >= 0 &&
    existing.renamedMatchCount >= 0 &&
    existing.createdLineageCount +
      existing.exactMatchCount +
      existing.renamedMatchCount ===
      identityCount &&
    existing.observedAt instanceof Date &&
    Number.isFinite(existing.observedAt.getTime())
  );
}

function occurrenceReplayMatches(
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
    ordinal: number;
    capability: FindingCapability;
    fingerprintVersion: string;
    stableFingerprint: string;
    fingerprintDecisionDigest: string;
    sourceFinding: Prisma.JsonValue;
    observedAt: Date;
  },
  finding: Readonly<SastFingerprintedFinding>,
  lineageId: string,
  input: Readonly<PersistSastFindingObservationInput>,
  observedAt: Date,
  ordinal: number
): boolean {
  const scope = input.context.scope;
  const occurrenceId = deterministicId(
    'finding-occurrence',
    `${input.observationBatchId}\0${ordinal}\0${finding.fingerprint.decisionDigest}`
  );
  return (
    occurrence.id === occurrenceId &&
    occurrence.tenantId === scope.tenantId &&
    occurrence.repositoryBindingId ===
      scope.repositoryBindingId &&
    occurrence.scanRequestId === scope.scanRequestId &&
    occurrence.attemptId === scope.attemptId &&
    occurrence.scannerRunId === scope.scannerRunId &&
    occurrence.observationBatchId ===
      input.observationBatchId &&
    occurrence.lineageId === lineageId &&
    occurrence.normalizedFindingId ===
      deterministicId('normalized-finding', occurrenceId) &&
    occurrence.ordinal === ordinal &&
    occurrence.capability === finding.capability &&
    occurrence.fingerprintVersion ===
      SAST_FINDING_FINGERPRINT_VERSION &&
    occurrence.stableFingerprint ===
      finding.fingerprint.stableFingerprint &&
    occurrence.fingerprintDecisionDigest ===
      finding.fingerprint.decisionDigest &&
    occurrence.observedAt.getTime() === observedAt.getTime() &&
    samePersistedFinding(occurrence.sourceFinding, finding)
  );
}

function samePersistedFinding(
  persisted: Prisma.JsonValue,
  expected: Readonly<SastFingerprintedFinding>
): boolean {
  try {
    return (
      isSastFingerprintedFindingShapeValid(
        persisted,
        digest,
        digest
      ) &&
      canonicalizeSastFingerprintedFinding(persisted) ===
        canonicalizeSastFingerprintedFinding(expected)
    );
  } catch {
    return false;
  }
}

function isPlanBoundToScanRequest(
  plan: Readonly<SastScanPlan>,
  input: {
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    targetRef: unknown;
    commitSha: unknown;
    canonicalScanKey: unknown;
    lane: unknown;
  }
): boolean {
  return (
    plan.tenantId === input.tenantId &&
    plan.scanRequestId === input.scanRequestId &&
    plan.repositoryState.repositoryBindingId ===
      input.repositoryBindingId &&
    plan.repositoryState.targetRef === input.targetRef &&
    plan.repositoryState.fixedCommitSha === input.commitSha &&
    plan.canonicalScanKey === input.canonicalScanKey &&
    plan.profile.lane === input.lane
  );
}

function authoritativeScannerCapabilities(
  scanner: string
): FindingCapability[] {
  if (scanner === 'OPENGREP') return ['SAST'];
  if (scanner === 'TRIVY') {
    return [
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION'
    ];
  }
  throw new SastFindingLineageDurableScopeError();
}

function readCapabilities(
  value: Prisma.JsonValue,
  scanner: string
): FindingCapability[] {
  if (
    !Array.isArray(value) ||
    value.some(
      (candidate) =>
        typeof candidate !== 'string' ||
        !FINDING_CAPABILITIES.includes(
          candidate as FindingCapability
        )
    )
  ) {
    throw new SastFindingLineageDurableScopeError();
  }
  const capabilities = value as FindingCapability[];
  if (
    !sameStringArray(
      capabilities,
      FINDING_CAPABILITIES.filter((capability) =>
        capabilities.includes(capability)
      )
    ) ||
    capabilities.some(
      (capability) =>
        !authoritativeScannerCapabilities(scanner).includes(
          capability
        )
    )
  ) {
    throw new SastFindingLineageDurableScopeError();
  }
  return capabilities;
}

function observedCapabilities(
  findings: readonly Readonly<SastFingerprintedFinding>[]
): FindingCapability[] {
  const observed = new Set(
    findings.map((finding) => finding.capability)
  );
  return FINDING_CAPABILITIES.filter((capability) =>
    observed.has(capability)
  );
}

function parsePlan(value: Prisma.JsonValue | undefined): SastScanPlan | null {
  const candidate = value as unknown as SastScanPlan;
  return candidate && isSastScanPlanValid(candidate)
    ? candidate
    : null;
}

function identityKey(
  capability: string,
  stableFingerprint: string
): string {
  return `${capability}\0${stableFingerprint}`;
}

function lineageId(
  tenantId: string,
  repositoryBindingId: string,
  capability: FindingCapability,
  stableFingerprint: `sha256:${string}`
): string {
  return deterministicId(
    'finding-lineage',
    buildSastFindingLineageKeyPreimage({
      tenantId,
      repositoryBindingId,
      capability,
      fingerprintVersion:
        SAST_FINDING_FINGERPRINT_VERSION,
      stableFingerprint
    })
  );
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

function isDigest(value: unknown): value is `sha256:${string}` {
  return (
    typeof value === 'string' &&
    /^sha256:[a-f0-9]{64}$/u.test(value)
  );
}

function isCanonicalIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return (
    Number.isFinite(parsed) &&
    new Date(parsed).toISOString() === value
  );
}

function isFindingScannerKind(
  value: string
): value is 'OPENGREP' | 'TRIVY' {
  return value === 'OPENGREP' || value === 'TRIVY';
}

function sameObservationContext(
  left: Readonly<SastFindingLineageScanContext>,
  right: Readonly<SastFindingLineageScanContext>
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameReconciliationContext(
  left: Readonly<SastFindingReconciliationScanContext>,
  right: Readonly<SastFindingReconciliationScanContext>
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameStringArray(
  left: readonly string[],
  right: readonly string[]
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function chunks<T>(
  values: readonly T[],
  size: number
): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < values.length; index += size) {
    result.push(values.slice(index, index + size));
  }
  return result;
}

function isRetryableTransactionError(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    (error.code === 'P2034' || error.code === 'P2002')
  );
}
