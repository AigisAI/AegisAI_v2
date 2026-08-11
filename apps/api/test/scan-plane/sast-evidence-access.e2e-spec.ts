import { createHash } from 'node:crypto';

import {
  SAST_APPROVED_PROFILE_DIGESTS,
  buildSastAcceptedEvidence,
  buildSastEvidenceDeletionProof,
  buildSastEvidenceDeletionSchedule,
  canonicalizeSastEvidenceCandidate,
  type SastAcceptedEvidenceBuildResult,
  type SastAcceptedEvidenceScope,
  type SastEvidenceAccessDecision,
  type SastEvidenceDeletionProof,
  type SastEvidenceDeletionReceipt,
  type SastRedactedEvidenceCandidate,
  type SastRedactedEvidenceCandidateCore
} from '@aegisai/shared';

import { SastEvidenceAccessService } from '../../src/scan-plane/sast-evidence-access.service';
import {
  SastEvidenceAccessPersistenceError,
  SastEvidenceAccessStore,
  sastEvidenceAccessScopeFromResult,
  type PersistedSastEvidenceAccessDecision,
  type SastEvidenceAccessContext,
  type SastEvidenceDeletionCandidate
} from '../../src/scan-plane/sast-evidence-access.store';
import { SastEvidenceDeletionAuthority } from '../../src/scan-plane/sast-evidence-deletion.authority';
import { SastEvidenceDeletionService } from '../../src/scan-plane/sast-evidence-deletion.service';
import {
  SastEvidenceSecretRegistry,
  type SastEvidenceSecretRegistryResult
} from '../../src/scan-plane/sast-evidence-secret-registry';

const CREATED_AT = '2026-08-10T04:40:00.000Z';
const BEFORE_EXPIRY = '2026-08-17T04:39:59.000Z';
const EXPIRES_AT = '2026-08-17T04:40:00.000Z';
const PLATFORM_SECRET = 'platform-secret-value';
const ENTROPY_SECRET = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY';

describe('SastEvidenceAccessService', () => {
  it('rebinds T041 evidence and performs access-time platform, format, and entropy redaction', async () => {
    const context = accessContext(
      acceptedEvidence([
        'safe line',
        `password = "${PLATFORM_SECRET}"`,
        ENTROPY_SECRET
      ].join('\n'))
    );
    const store = new MemoryAccessStore(context);
    const registry = new MemorySecretRegistry({
      status: 'VERIFIED',
      registryVersion: 'platform-secret-registry-v1',
      platformSecretValues: [PLATFORM_SECRET]
    });
    const service = new SastEvidenceAccessService(store, registry);

    const result = await service.readDashboard(
      request(context),
      clock(CREATED_AT, CREATED_AT, CREATED_AT)
    );

    expect(result.outcome).toBe('ALLOWED');
    if (result.outcome !== 'ALLOWED') return;
    const serialized = JSON.stringify(result.dashboardEvidence);
    expect(serialized).toContain('[REDACTED]');
    expect(serialized).not.toContain(PLATFORM_SECRET);
    expect(serialized).not.toContain(ENTROPY_SECRET);
    expect(result.decision.classification).toBe('DASHBOARD_SAFE');
    expect(result.decision.authority).toEqual(
      expect.objectContaining({
        dashboardReadAllowed: true,
        reducedEvidenceReferenceAllowed: false,
        aiPayloadAllowed: false,
        aiProviderCallAllowed: false,
        policyAuthority: false,
        publicationAuthority: false,
        lifecycleMutationAuthority: false,
        scmWriteAuthority: false
      })
    );
    expect(result.decision.audit).toEqual(
      expect.objectContaining({
        rawSourceStored: false,
        secretValueStored: false,
        preRedactionPayloadStored: false,
        matchedValueDigestStored: false,
        dashboardPayloadPersisted: false
      })
    );
    expect(JSON.stringify(store.decisions)).not.toContain(
      PLATFORM_SECRET
    );
    expect(context.result?.pack).toEqual(
      expect.objectContaining({
        dashboardSafe: false,
        aiSafe: false,
        classificationDecisionRef: null,
        deletionScheduleRef: null
      })
    );
  });

  it('keeps dashboard, AI reference, payload, and provider authority independent', async () => {
    const context = accessContext(acceptedEvidence('safe content'));
    const store = new MemoryAccessStore(context);
    const registry = verifiedRegistry();
    const service = new SastEvidenceAccessService(store, registry);

    const denied = await service.classifyForAi(
      request(context),
      () => CREATED_AT
    );
    expect(denied).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_OPT_IN_REQUIRED'
    });
    expect(registry.calls).toBe(0);

    context.tenantAiAdvisoryOptIn = true;
    context.repositoryAiAdvisoryOptIn = true;
    const allowed = await service.classifyForAi(
      request(context),
      () => CREATED_AT
    );
    expect(allowed.outcome).toBe('ALLOWED');
    if (allowed.outcome !== 'ALLOWED') return;
    expect(allowed.dashboardEvidence).toBeNull();
    expect(allowed.reducedEvidenceReference).toEqual(
      expect.objectContaining({
        aiPayloadCreated: false,
        aiProviderCalled: false,
        retrievalAllowed: false,
        toolsAllowed: false,
        advisoryOnly: true
      })
    );
    expect(allowed.decision.authority.dashboardReadAllowed).toBe(false);
    expect(
      allowed.decision.authority.reducedEvidenceReferenceAllowed
    ).toBe(true);
    expect(allowed.decision.authority.aiPayloadAllowed).toBe(false);
    expect(
      Date.parse(
        allowed.reducedEvidenceReference!.payloadExpiresAt
      ) - Date.parse(allowed.decision.decidedAt)
    ).toBeLessThanOrEqual(24 * 60 * 60 * 1000);
  });

  it('denies expired-at-start and expired-during-read without returning content', async () => {
    const atStart = accessContext(acceptedEvidence('safe content'));
    const first = await new SastEvidenceAccessService(
      new MemoryAccessStore(atStart),
      verifiedRegistry()
    ).readDashboard(request(atStart), () => EXPIRES_AT);
    expect(first).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_EXPIRED',
      dashboardEvidence: null
    });

    const during = accessContext(acceptedEvidence('safe content'));
    const second = await new SastEvidenceAccessService(
      new MemoryAccessStore(during),
      verifiedRegistry()
    ).readDashboard(
      request(during),
      clock(BEFORE_EXPIRY, BEFORE_EXPIRY, EXPIRES_AT)
    );
    expect(second).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_EXPIRED',
      dashboardEvidence: null
    });
  });

  it('denies late readers when the secret registry drifts or deletion is claimed', async () => {
    const driftContext = accessContext(
      acceptedEvidence('safe content')
    );
    const drift = await new SastEvidenceAccessService(
      new MemoryAccessStore(driftContext),
      new SequenceSecretRegistry([
        verifiedRegistryResult('platform-secret-registry-v1'),
        verifiedRegistryResult('platform-secret-registry-v2')
      ])
    ).readDashboard(
      request(driftContext),
      clock(CREATED_AT, CREATED_AT, CREATED_AT)
    );
    expect(drift).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_CLASSIFICATION_STALE',
      dashboardEvidence: null
    });

    const claimedContext = accessContext(
      acceptedEvidence('safe content')
    );
    const claimed = await new SastEvidenceAccessService(
      new MemoryAccessStore(claimedContext),
      new SequenceSecretRegistry(
        [verifiedRegistryResult('platform-secret-registry-v1')],
        (call) => {
          if (call === 2) {
            claimedContext.deletionState = 'DELETION_PENDING';
          }
        }
      )
    ).readDashboard(
      request(claimedContext),
      clock(CREATED_AT, CREATED_AT, CREATED_AT)
    );
    expect(claimed).toMatchObject({
      outcome: 'DENIED',
      dashboardEvidence: null
    });

    const aiContext = accessContext(acceptedEvidence('safe content'));
    aiContext.tenantAiAdvisoryOptIn = true;
    aiContext.repositoryAiAdvisoryOptIn = true;
    const aiClaimed = await new SastEvidenceAccessService(
      new MemoryAccessStore(aiContext),
      new SequenceSecretRegistry(
        [verifiedRegistryResult('platform-secret-registry-v1')],
        (call) => {
          if (call === 2) {
            aiContext.deletionState = 'DELETION_PENDING';
          }
        }
      )
    ).classifyForAi(request(aiContext), clock(CREATED_AT, CREATED_AT));
    expect(aiClaimed).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_CLASSIFICATION_STALE',
      reducedEvidenceReference: null
    });
  });

  it('fails closed on unavailable secret authority, unsafe identifiers, and cross-tenant access', async () => {
    const context = accessContext(acceptedEvidence('safe content'));
    const unavailable = await new SastEvidenceAccessService(
      new MemoryAccessStore(context),
      new MemorySecretRegistry({ status: 'UNAVAILABLE' })
    ).classifyForAi(request(context), () => CREATED_AT);
    expect(unavailable).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_OPT_IN_REQUIRED'
    });

    context.tenantAiAdvisoryOptIn = true;
    context.repositoryAiAdvisoryOptIn = true;
    const unavailableAfterOptIn =
      await new SastEvidenceAccessService(
        new MemoryAccessStore(context),
        new MemorySecretRegistry({ status: 'UNAVAILABLE' })
      ).classifyForAi(request(context), () => CREATED_AT);
    expect(unavailableAfterOptIn).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_SECRET_AUTHORITY_UNAVAILABLE'
    });

    const unsafeRegistryContext = accessContext(
      acceptedEvidence('safe content')
    );
    const unsafeRegistryStore = new MemoryAccessStore(
      unsafeRegistryContext
    );
    const unsafeRegistry = await new SastEvidenceAccessService(
      unsafeRegistryStore,
      new MemorySecretRegistry({
        status: 'VERIFIED',
        registryVersion: PLATFORM_SECRET,
        platformSecretValues: [PLATFORM_SECRET]
      })
    ).readDashboard(
      request(unsafeRegistryContext),
      clock(CREATED_AT, CREATED_AT, CREATED_AT)
    );
    expect(unsafeRegistry).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_REDACTION_FAILED'
    });
    expect(JSON.stringify(unsafeRegistryStore.decisions)).not.toContain(
      PLATFORM_SECRET
    );

    const unsafeResult = acceptedEvidence('safe content', {
      normalizedPath:
        'src/aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY.java'
    });
    const unsafeContext = accessContext(unsafeResult);
    const unsafe = await new SastEvidenceAccessService(
      new MemoryAccessStore(unsafeContext),
      verifiedRegistry()
    ).readDashboard(
      request(unsafeContext),
      clock(CREATED_AT, CREATED_AT, CREATED_AT)
    );
    expect(unsafe).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_IDENTIFIER_UNSAFE'
    });

    const registeredPathContext = accessContext(
      acceptedEvidence('safe content', {
        normalizedPath: 'src/tenant-secret-path/App.java'
      })
    );
    const registeredPath = await new SastEvidenceAccessService(
      new MemoryAccessStore(registeredPathContext),
      new MemorySecretRegistry({
        status: 'VERIFIED',
        registryVersion: 'platform-secret-registry-v1',
        platformSecretValues: ['tenant-secret-path']
      })
    ).readDashboard(
      request(registeredPathContext),
      clock(CREATED_AT, CREATED_AT, CREATED_AT)
    );
    expect(registeredPath).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_IDENTIFIER_UNSAFE',
      dashboardEvidence: null
    });

    const crossTenant = await new SastEvidenceAccessService(
      new MemoryAccessStore(context),
      verifiedRegistry()
    ).readDashboard(
      { ...request(context), tenantId: 'tenant-2' },
      () => CREATED_AT
    );
    expect(crossTenant).toMatchObject({
      outcome: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_CONTEXT_UNAVAILABLE'
    });
  });

  it('returns one canonical decision for concurrent exact classification', async () => {
    const context = accessContext(acceptedEvidence('safe content'));
    context.tenantAiAdvisoryOptIn = true;
    context.repositoryAiAdvisoryOptIn = true;
    const store = new MemoryAccessStore(context);
    const service = new SastEvidenceAccessService(
      store,
      verifiedRegistry()
    );
    const [left, right] = await Promise.all([
      service.classifyForAi(request(context), () => CREATED_AT),
      service.classifyForAi(request(context), () => CREATED_AT)
    ]);

    expect(left.outcome).toBe('ALLOWED');
    expect(right.outcome).toBe('ALLOWED');
    if (left.outcome !== 'ALLOWED' || right.outcome !== 'ALLOWED') {
      return;
    }
    expect(left.decision).toEqual(right.decision);
    expect([left.replayed, right.replayed].sort()).toEqual([
      false,
      true
    ]);
    expect(store.decisions).toHaveLength(1);
  });
});

describe('SastEvidenceDeletionService', () => {
  it('claims by deterministic operation, deletes content, and retains one bounded proof', async () => {
    const context = accessContext(acceptedEvidence('safe content'));
    const store = new MemoryAccessStore(context);
    const authority = new MemoryDeletionAuthority(EXPIRES_AT);
    const service = new SastEvidenceDeletionService(store, authority);

    await expect(
      service.processNext(
        new Date(EXPIRES_AT),
        'worker-1',
        () => EXPIRES_AT
      )
    ).resolves.toBe('DELETED');
    expect(authority.calls).toHaveLength(1);
    expect(authority.calls[0]?.operationId).toBe(
      context.schedule.operationId
    );
    expect(context.result).toBeNull();
    expect(context.deletionState).toBe('DELETED');
    expect(context.deletionProof).toEqual(
      expect.objectContaining({
        contentDeleted: true,
        fragmentsDeleted: true,
        buildDecisionRetained: true,
        accessAuthorityRevoked: true
      })
    );
    await expect(
      service.processNext(
        new Date(EXPIRES_AT),
        'worker-2',
        () => EXPIRES_AT
      )
    ).resolves.toBe('IDLE');
    expect(authority.calls).toHaveLength(1);
  });

  it('releases the claim when deletion authority is unavailable or the clock rolls back', async () => {
    const unavailableContext = accessContext(
      acceptedEvidence('safe content')
    );
    const unavailableStore = new MemoryAccessStore(
      unavailableContext
    );
    const unavailable = new SastEvidenceDeletionService(
      unavailableStore,
      new RejectingDeletionAuthority()
    );
    await expect(
      unavailable.processNext(
        new Date(EXPIRES_AT),
        'worker-1',
        () => EXPIRES_AT
      )
    ).resolves.toBe('RETRY_SCHEDULED');
    expect(unavailableContext.deletionState).toBe('ACTIVE');
    expect(unavailableContext.result?.pack).not.toBeNull();

    const rollbackContext = accessContext(
      acceptedEvidence('safe content')
    );
    const rollback = new SastEvidenceDeletionService(
      new MemoryAccessStore(rollbackContext),
      new MemoryDeletionAuthority(EXPIRES_AT)
    );
    await expect(
      rollback.processNext(
        new Date(EXPIRES_AT),
        'worker-1',
        () => BEFORE_EXPIRY
      )
    ).resolves.toBe('RETRY_SCHEDULED');
    expect(rollbackContext.deletionState).toBe('ACTIVE');
    expect(rollbackContext.deletionProof).toBeNull();
  });

  it('fences concurrent workers and rejects a changed receipt after exact proof replay', async () => {
    const concurrentContext = accessContext(
      acceptedEvidence('safe content')
    );
    const concurrentAuthority = new MemoryDeletionAuthority(
      EXPIRES_AT
    );
    const concurrentService = new SastEvidenceDeletionService(
      new MemoryAccessStore(concurrentContext),
      concurrentAuthority
    );
    const results = await Promise.all([
      concurrentService.processNext(
        new Date(EXPIRES_AT),
        'worker-1',
        () => EXPIRES_AT
      ),
      concurrentService.processNext(
        new Date(EXPIRES_AT),
        'worker-2',
        () => EXPIRES_AT
      )
    ]);
    expect(results.sort()).toEqual(['DELETED', 'IDLE']);
    expect(concurrentAuthority.calls).toHaveLength(1);

    const replayContext = accessContext(
      acceptedEvidence('safe content')
    );
    const replayStore = new MemoryAccessStore(replayContext);
    const candidate = await replayStore.claimDeletion({
      referenceTime: EXPIRES_AT,
      leaseOwner: 'worker-1',
      leaseExpiresAt: '2026-08-17T04:41:00.000Z'
    });
    expect(candidate).not.toBeNull();
    if (!candidate) return;
    const receipt = deletionReceipt(
      replayContext.schedule.operationId,
      'receipt-a'
    );
    const proof = buildSastEvidenceDeletionProof({
      schedule: replayContext.schedule,
      receipt,
      digestCanonical: digest
    });
    await expect(
      replayStore.finalizeDeletion({ candidate, receipt, proof })
    ).resolves.toMatchObject({ replayed: false });
    await expect(
      replayStore.finalizeDeletion({ candidate, receipt, proof })
    ).resolves.toMatchObject({ replayed: true });

    const changedReceipt = deletionReceipt(
      replayContext.schedule.operationId,
      'receipt-b'
    );
    const changedProof = buildSastEvidenceDeletionProof({
      schedule: replayContext.schedule,
      receipt: changedReceipt,
      digestCanonical: digest
    });
    expect(() =>
      replayStore.finalizeDeletion({
        candidate,
        receipt: changedReceipt,
        proof: changedProof
      })
    ).toThrow(SastEvidenceAccessPersistenceError);
  });
});

class MemoryAccessStore extends SastEvidenceAccessStore {
  readonly decisions: SastEvidenceAccessDecision[] = [];
  private candidate: SastEvidenceDeletionCandidate | null = null;

  constructor(private readonly context: SastEvidenceAccessContext) {
    super();
  }

  load(input: {
    tenantId: string;
    repositoryBindingId: string;
    evidencePackId: string;
  }): Promise<SastEvidenceAccessContext | null> {
    const scope = this.context.schedule.scope;
    return Promise.resolve(
      input.tenantId === scope.tenantId &&
        input.repositoryBindingId === scope.repositoryBindingId &&
        input.evidencePackId === scope.evidencePackId
        ? this.context
        : null
    );
  }

  persistDecision(input: {
    decision: Readonly<SastEvidenceAccessDecision>;
  }): Promise<PersistedSastEvidenceAccessDecision> {
    const existing = this.decisions.find(
      (decision) =>
        decision.accessDecisionId === input.decision.accessDecisionId
    );
    if (existing) {
      if (JSON.stringify(existing) !== JSON.stringify(input.decision)) {
        throw new SastEvidenceAccessPersistenceError(
          'REPLAY_CONFLICT'
        );
      }
      return Promise.resolve({ decision: existing, replayed: true });
    }
    const decision = structuredClone(input.decision);
    this.decisions.push(decision);
    return Promise.resolve({ decision, replayed: false });
  }

  confirmAccess(input: {
    tenantId: string;
    repositoryBindingId: string;
    evidencePackId: string;
    accessDecisionId: string;
    secretRegistryVersion: string;
    redactedProjectionDigest: `sha256:${string}`;
    referenceTime: string;
  }): Promise<SastEvidenceAccessContext | null> {
    const decision = this.decisions.find(
      (candidate) =>
        candidate.accessDecisionId === input.accessDecisionId &&
        candidate.secretRegistryVersion ===
          input.secretRegistryVersion &&
        candidate.redactedProjectionDigest ===
          input.redactedProjectionDigest
    );
    return Promise.resolve(
      decision &&
        this.context.deletionState === 'ACTIVE' &&
        Date.parse(input.referenceTime) <
          Date.parse(this.context.schedule.deleteAfter)
        ? this.context
        : null
    );
  }

  backfillDeletionSchedules(): Promise<number> {
    return Promise.resolve(0);
  }

  claimDeletion(input: {
    referenceTime: string;
    leaseOwner: string;
    leaseExpiresAt: string;
  }): Promise<SastEvidenceDeletionCandidate | null> {
    if (
      this.context.deletionState !== 'ACTIVE' ||
      !this.context.result?.pack ||
      Date.parse(input.referenceTime) <
        Date.parse(this.context.schedule.deleteAfter)
    ) {
      return Promise.resolve(null);
    }
    this.context.deletionState = 'DELETION_PENDING';
    this.candidate = {
      schedule: this.context.schedule,
      leaseOwner: input.leaseOwner,
      leaseToken: '00000000-0000-4000-8000-000000000001',
      leaseExpiresAt: input.leaseExpiresAt
    };
    return Promise.resolve(this.candidate);
  }

  finalizeDeletion(input: {
    candidate: Readonly<SastEvidenceDeletionCandidate>;
    receipt: Readonly<SastEvidenceDeletionReceipt>;
    proof: Readonly<SastEvidenceDeletionProof>;
  }): Promise<{ proof: SastEvidenceDeletionProof; replayed: boolean }> {
    if (this.context.deletionProof) {
      if (
        JSON.stringify(this.context.deletionProof) ===
        JSON.stringify(input.proof)
      ) {
        return Promise.resolve({
          proof: this.context.deletionProof,
          replayed: true
        });
      }
      throw new SastEvidenceAccessPersistenceError(
        'REPLAY_CONFLICT'
      );
    }
    if (
      !this.candidate ||
      this.candidate.leaseToken !== input.candidate.leaseToken ||
      input.receipt.operationId !==
        this.context.schedule.operationId
    ) {
      throw new SastEvidenceAccessPersistenceError('LEASE_LOST');
    }
    this.context.result = null;
    this.context.deletionState = 'DELETED';
    this.context.deletionProof = structuredClone(input.proof);
    this.candidate = null;
    return Promise.resolve({
      proof: this.context.deletionProof,
      replayed: false
    });
  }

  releaseDeletion(input: {
    candidate: Readonly<SastEvidenceDeletionCandidate>;
  }): Promise<void> {
    if (
      !this.candidate ||
      this.candidate.leaseToken !== input.candidate.leaseToken
    ) {
      throw new SastEvidenceAccessPersistenceError('LEASE_LOST');
    }
    this.candidate = null;
    this.context.deletionState = 'ACTIVE';
    return Promise.resolve();
  }
}

class MemorySecretRegistry extends SastEvidenceSecretRegistry {
  calls = 0;

  constructor(
    private readonly result: SastEvidenceSecretRegistryResult
  ) {
    super();
  }

  read(): Promise<SastEvidenceSecretRegistryResult> {
    this.calls += 1;
    return Promise.resolve(this.result);
  }
}

class SequenceSecretRegistry extends SastEvidenceSecretRegistry {
  private calls = 0;

  constructor(
    private readonly results: readonly SastEvidenceSecretRegistryResult[],
    private readonly onRead?: (call: number) => void
  ) {
    super();
  }

  read(): Promise<SastEvidenceSecretRegistryResult> {
    this.calls += 1;
    this.onRead?.(this.calls);
    return Promise.resolve(
      this.results[Math.min(this.calls - 1, this.results.length - 1)]!
    );
  }
}

class MemoryDeletionAuthority extends SastEvidenceDeletionAuthority {
  readonly calls: Array<{ operationId: string }> = [];

  constructor(private readonly completedAt: string) {
    super();
  }

  delete(input: { operationId: string }): Promise<SastEvidenceDeletionReceipt> {
    this.calls.push(input);
    return Promise.resolve({
      operationId: input.operationId,
      providerReceiptRef: id(
        'sast-evidence-delete-receipt',
        'receipt'
      ),
      providerReceiptDigest: digest('receipt'),
      completedAt: this.completedAt
    });
  }
}

class RejectingDeletionAuthority extends SastEvidenceDeletionAuthority {
  delete(): Promise<SastEvidenceDeletionReceipt> {
    return Promise.reject(new Error('unavailable'));
  }
}

function accessContext(
  result: SastAcceptedEvidenceBuildResult
): SastEvidenceAccessContext {
  if (!result.pack) throw new Error('Expected accepted evidence.');
  const schedule = buildSastEvidenceDeletionSchedule({
    scope: sastEvidenceAccessScopeFromResult(result),
    scheduledAt: result.pack.createdAt,
    deleteAfter: result.pack.expiresAt,
    digestCanonical: digest
  });
  return {
    result,
    schedule,
    deletionState: 'ACTIVE',
    deletionProof: null,
    tenantAiAdvisoryOptIn: false,
    repositoryAiAdvisoryOptIn: false,
    freshnessEligible: true,
    coverageComplete: true
  };
}

function acceptedEvidence(
  content: string,
  overrides: Partial<Pick<SastAcceptedEvidenceScope, 'normalizedPath'>> = {}
): SastAcceptedEvidenceBuildResult {
  const boundedContent =
    content.split('\n').length === 3
      ? content
      : [content, 'safe line 2', 'safe line 3'].join('\n');
  const scope: SastAcceptedEvidenceScope = {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    targetRef: 'refs/pull/1/head',
    commitSha: 'a'.repeat(40),
    canonicalScanKey: digest('canonical-scan'),
    planDigest: digest('plan'),
    profileId: 'JAVA_FAST_V1',
    profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
    freshnessDecisionId: id('sast-freshness', 'freshness'),
    freshnessDecisionDigest: digest('freshness-decision'),
    coverageDecisionId: id('sast-coverage', 'coverage'),
    coverageDecisionDigest: digest('coverage-decision'),
    occurrenceId: id('finding-occurrence', 'occurrence'),
    observationBatchId: id('finding-observation', 'observation'),
    normalizedFindingId: 'normalized-finding-1',
    lineageId: id('finding-lineage', 'lineage'),
    findingFingerprint: digest('finding'),
    fingerprintVersion: 'sast-fingerprint-v1',
    capability: 'SAST',
    normalizedPath:
      overrides.normalizedPath ?? 'src/main/java/App.java',
    findingStartLine: 11,
    findingEndLine: 11,
    policyVersion: 'sast-evidence-policy-v1'
  };
  const core: SastRedactedEvidenceCandidateCore = {
    candidateId: id('sast-evidence-candidate', 'candidate'),
    role: 'PRIMARY',
    normalizedPath: scope.normalizedPath,
    startLine: 10,
    endLine: 12,
    anchorStartLine: 11,
    anchorEndLine: 11,
    sourceFileLineCount: 100,
    redactedContent: boundedContent,
    byteSize: Buffer.byteLength(boundedContent, 'utf8'),
    sourceContentDigest: digest(boundedContent),
    contentDigest: digest(boundedContent),
    sourceAttestationRef: 'source-attestation://candidate',
    scannerRedactionDecisionRef: 'scanner-redaction://candidate',
    platformRedactionDecisionRef: 'platform-redaction://candidate',
    secretRedactionApplied: true,
    rawSourceStored: false
  };
  const candidate: SastRedactedEvidenceCandidate = {
    ...core,
    candidateDigest: digest(
      canonicalizeSastEvidenceCandidate(core)
    )
  };
  return buildSastAcceptedEvidence({
    scope,
    candidates: [candidate],
    decidedAt: CREATED_AT,
    digestCanonical: digest
  });
}

function request(context: SastEvidenceAccessContext) {
  return {
    tenantId: context.schedule.scope.tenantId,
    repositoryBindingId:
      context.schedule.scope.repositoryBindingId,
    evidencePackId: context.schedule.scope.evidencePackId
  };
}

function verifiedRegistry(): MemorySecretRegistry {
  return new MemorySecretRegistry(
    verifiedRegistryResult('platform-secret-registry-v1')
  );
}

function verifiedRegistryResult(
  registryVersion: string
): SastEvidenceSecretRegistryResult {
  return {
    status: 'VERIFIED',
    registryVersion,
    platformSecretValues: []
  };
}

function deletionReceipt(
  operationId: string,
  value: string
): SastEvidenceDeletionReceipt {
  return {
    operationId,
    providerReceiptRef: id(
      'sast-evidence-delete-receipt',
      value
    ),
    providerReceiptDigest: digest(value),
    completedAt: EXPIRES_AT
  };
}

function clock(...values: string[]): () => string {
  let index = 0;
  return () => values[Math.min(index++, values.length - 1)]!;
}

function id(prefix: string, value: string): string {
  return `${prefix}://${hex(value)}`;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${hex(value)}`;
}

function hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
