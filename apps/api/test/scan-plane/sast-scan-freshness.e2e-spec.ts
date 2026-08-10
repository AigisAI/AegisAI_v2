import { createHash } from 'node:crypto';

import {
  SAST_FINDING_LIFECYCLE_COVERAGE_VERSION,
  canonicalizeSastFindingLifecycleCoverageDecision,
  type SastFindingLifecycleCoverageDecision,
  type SastScanFreshnessDecision,
  type SastScanRetryDecision
} from '@aegisai/shared';

import {
  SastLatestTargetAuthority,
  UnavailableSastLatestTargetAuthority
} from '../../src/scan-plane/sast-latest-target-authority';
import {
  UnavailableSastRetryRuntimeAuthority
} from '../../src/scan-plane/sast-retry-runtime-authority';
import { SastScanFreshnessService } from '../../src/scan-plane/sast-scan-freshness.service';
import {
  SastScanFreshnessStore,
  type SastScanFreshnessContext,
  type SastScanRetryDurableContext
} from '../../src/scan-plane/sast-scan-freshness.store';

const DECIDED_AT = '2026-08-10T03:00:01.000Z';

describe('SastScanFreshnessService', () => {
  it('persists fresh comparable eligibility without publishing or creating AI payloads', async () => {
    const context = freshnessContext();
    const store = new MemoryFreshnessStore(context);
    const service = new SastScanFreshnessService(
      store,
      new VerifiedTargetAuthority(context.scope.commitSha),
      new UnavailableSastRetryRuntimeAuthority()
    );

    const result = await service.evaluate(
      context.scope.coverageDecisionId,
      () => DECIDED_AT
    );

    expect(result.outcome).toBe('EVALUATED');
    if (result.outcome !== 'EVALUATED') return;
    expect(result.decision).toMatchObject({
      latestTargetAuthority: 'VERIFIED',
      staleStatus: 'FRESH',
      comparabilityStatus: 'COMPARABLE',
      externalCommentEligible: true,
      blockingStatusEligible: true,
      lifecycleMutationAllowed: true,
      aiAdvisoryAllowed: false,
      publicationAttempted: false,
      reasonCodes: []
    });
    expect(store.persistedFreshness?.observation).not.toBeNull();
    expect(store.persistedFreshness?.decision).toEqual(result.decision);
  });

  it('denies a stale target head even with complete comparable coverage', async () => {
    const context = freshnessContext();
    const service = new SastScanFreshnessService(
      new MemoryFreshnessStore(context),
      new VerifiedTargetAuthority('c'.repeat(40)),
      new UnavailableSastRetryRuntimeAuthority()
    );
    const result = await service.evaluate(
      context.scope.coverageDecisionId,
      () => DECIDED_AT
    );

    expect(result.outcome).toBe('EVALUATED');
    if (result.outcome !== 'EVALUATED') return;
    expect(result.decision.staleStatus).toBe('STALE');
    expect(result.decision.externalCommentEligible).toBe(false);
    expect(result.decision.lifecycleMutationAllowed).toBe(false);
    expect(result.decision.reasonCodes).toEqual([
      'TARGET_HEAD_MISMATCH',
      'PUBLICATION_FAIL_CLOSED'
    ]);
  });

  it('fails closed when the latest-target authority is unavailable', async () => {
    const context = freshnessContext();
    const result = await new SastScanFreshnessService(
      new MemoryFreshnessStore(context),
      new UnavailableSastLatestTargetAuthority(),
      new UnavailableSastRetryRuntimeAuthority()
    ).evaluate(context.scope.coverageDecisionId, () => DECIDED_AT);

    expect(result.outcome).toBe('EVALUATED');
    if (result.outcome !== 'EVALUATED') return;
    expect(result.decision.latestTargetAuthority).toBe('UNAVAILABLE');
    expect(result.decision.staleStatus).toBe('UNKNOWN');
    expect(result.decision.externalCommentEligible).toBe(false);
    expect(result.decision.aiAdvisoryAllowed).toBe(false);
  });

  it('rejects an observation captured before terminal coverage', async () => {
    const context = freshnessContext();
    const store = new MemoryFreshnessStore(context);
    const result = await new SastScanFreshnessService(
      store,
      new VerifiedTargetAuthority(
        context.scope.commitSha,
        2,
        '2026-08-10T02:59:59.000Z'
      ),
      new UnavailableSastRetryRuntimeAuthority()
    ).evaluate(context.scope.coverageDecisionId, () => DECIDED_AT);

    expect(result.outcome).toBe('EVALUATED');
    if (result.outcome !== 'EVALUATED') return;
    expect(result.decision.latestTargetAuthority).toBe('INVALID');
    expect(result.decision.externalCommentEligible).toBe(false);
    expect(store.persistedFreshness?.observation).toBeNull();
  });

  it('replays the exact canonical decision without observing the provider again', async () => {
    const context = freshnessContext();
    const target = new VerifiedTargetAuthority(context.scope.commitSha);
    const store = new MemoryFreshnessStore(context);
    const first = await new SastScanFreshnessService(
      store,
      target,
      new UnavailableSastRetryRuntimeAuthority()
    ).evaluate(context.scope.coverageDecisionId, () => DECIDED_AT);
    expect(first.outcome).toBe('EVALUATED');
    if (first.outcome !== 'EVALUATED') return;
    store.context.existingDecision = first.decision;

    const second = await new SastScanFreshnessService(
      store,
      target,
      new UnavailableSastRetryRuntimeAuthority()
    ).evaluate(context.scope.coverageDecisionId, () => DECIDED_AT);

    expect(second).toMatchObject({ outcome: 'EVALUATED', replayed: true });
    expect(target.calls).toBe(1);
  });

  it('lets T037 consume only a canonical decision reverified by the T040 store', async () => {
    const store = new MemoryFreshnessStore(freshnessContext());
    store.lifecycleVerification = 'MATCHED';
    const decision = lifecycleDecision();
    const service = new SastScanFreshnessService(
      store,
      new VerifiedTargetAuthority(freshnessContext().scope.commitSha),
      new UnavailableSastRetryRuntimeAuthority()
    );

    await expect(service.verify(decision)).resolves.toBe('VERIFIED');
    expect(store.lifecycleDecision).toEqual(decision);
    await expect(
      service.verify({ ...decision, stale: true } as never)
    ).resolves.toBe('REJECTED');
  });

  it('rechecks the provider head at lifecycle consumption time', async () => {
    const store = new MemoryFreshnessStore(freshnessContext());
    store.lifecycleVerification = 'MATCHED';
    const decision = lifecycleDecision();
    const service = new SastScanFreshnessService(
      store,
      new VerifiedTargetAuthority('d'.repeat(40)),
      new UnavailableSastRetryRuntimeAuthority()
    );

    await expect(service.verify(decision)).resolves.toBe('REJECTED');
    expect(store.lifecycleDecision).toBeUndefined();
  });

  it('rejects a same-sequence lifecycle observation replay', async () => {
    const store = new MemoryFreshnessStore(freshnessContext());
    store.lifecycleVerification = 'MATCHED';
    const decision = lifecycleDecision();
    const service = new SastScanFreshnessService(
      store,
      new VerifiedTargetAuthority(
        freshnessContext().scope.commitSha,
        1
      ),
      new UnavailableSastRetryRuntimeAuthority()
    );

    await expect(service.verify(decision)).resolves.toBe('REJECTED');
    expect(store.lifecycleDecision).toBeUndefined();
  });
});

class VerifiedTargetAuthority extends SastLatestTargetAuthority {
  calls = 0;

  constructor(
    private readonly headCommitSha: string,
    private readonly sequence = 2,
    private readonly observedAt = DECIDED_AT
  ) {
    super();
  }

  async observe() {
    this.calls += 1;
    return {
      status: 'VERIFIED' as const,
      headCommitSha: this.headCommitSha,
      sequence: this.sequence,
      observerRef: 'scm-head-authority://test',
      observedAt: this.observedAt
    };
  }
}

class MemoryFreshnessStore extends SastScanFreshnessStore {
  persistedFreshness?: {
    observation: unknown;
    decision: Readonly<SastScanFreshnessDecision>;
  };
  lifecycleVerification: 'MATCHED' | 'REJECTED' = 'REJECTED';
  lifecycleDecision?: Readonly<SastFindingLifecycleCoverageDecision>;

  constructor(readonly context: SastScanFreshnessContext) {
    super();
  }

  async loadContext() {
    return this.context;
  }

  async persistFreshness(input: {
    observation: unknown;
    decision: Readonly<SastScanFreshnessDecision>;
  }) {
    this.persistedFreshness = input;
    return {
      freshnessDecisionId: input.decision.freshnessDecisionId,
      decisionDigest: input.decision.decisionDigest,
      replayed: false
    };
  }

  async verifyLifecycleSource(
    decision: Readonly<SastFindingLifecycleCoverageDecision>
  ) {
    this.lifecycleDecision = decision;
    return this.lifecycleVerification;
  }

  async loadRetryContext(): Promise<SastScanRetryDurableContext | null> {
    return null;
  }

  async persistRetryDecision(input: {
    decision: Readonly<SastScanRetryDecision>;
  }) {
    return {
      retryDecisionId: input.decision.retryDecisionId,
      decisionDigest: input.decision.decisionDigest,
      retryAllowed: input.decision.retryAllowed,
      replayed: false
    };
  }
}

function freshnessContext(): SastScanFreshnessContext {
  return {
    coverageComplete: true,
    coverageCompletedAt: '2026-08-10T03:00:00.000Z',
    scope: {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      provider: 'GITHUB',
      targetRef: 'refs/heads/main',
      commitSha: 'b'.repeat(40),
      scanRequestId: 'scan-current',
      attemptId: 'attempt-current',
      attemptNumber: 1,
      coverageDecisionId: id('sast-coverage', 'current'),
      coverageDecisionDigest: digest('coverage-current'),
      lifecycleContextKey: digest('lifecycle'),
      canonicalScanKey: digest('canonical'),
      planDigest: digest('plan'),
      profileId: 'JAVA_DEEP_V1',
      profileDigest: digest('profile'),
      profileFamily: 'JAVA',
      requiredCapabilities: [
        'SAST',
        'DEPENDENCY_VULNERABILITY',
        'SECRET_DETECTION',
        'IAC_MISCONFIGURATION',
        'SBOM'
      ],
      fingerprintVersion: 'sast-fingerprint-v1',
      lifecycleEligibilityScope: digest('eligibility')
    },
    comparison: {
      coverageDecisionId: id('sast-coverage', 'previous'),
      coverageDecisionDigest: digest('coverage-previous'),
      scanRequestId: 'scan-previous',
      commitSha: 'a'.repeat(40),
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      targetRef: 'refs/heads/main',
      profileId: 'JAVA_DEEP_V1',
      profileDigest: digest('profile-previous'),
      profileFamily: 'JAVA',
      requiredCapabilities: [
        'SAST',
        'DEPENDENCY_VULNERABILITY',
        'SECRET_DETECTION',
        'IAC_MISCONFIGURATION',
        'SBOM'
      ],
      fingerprintVersion: 'sast-fingerprint-v1',
      lifecycleEligibilityScope: digest('eligibility'),
      completedAt: '2026-08-09T03:00:00.000Z'
    },
    latestObservation: {
      observationId: id('sast-target-observation', 'previous'),
      sequence: 1,
      observedAt: '2026-08-09T03:00:00.000Z'
    },
    existingDecision: null
  };
}

function lifecycleDecision(): SastFindingLifecycleCoverageDecision {
  const context = freshnessContext();
  const core = {
    version: SAST_FINDING_LIFECYCLE_COVERAGE_VERSION,
    tenantId: context.scope.tenantId,
    repositoryBindingId: context.scope.repositoryBindingId,
    scanRequestId: context.scope.scanRequestId,
    attemptId: context.scope.attemptId,
    canonicalScanKey: context.scope.canonicalScanKey,
    planDigest: context.scope.planDigest,
    commitSha: context.scope.commitSha,
    lifecycleContextKey: context.scope.lifecycleContextKey,
    profileId: context.scope.profileId,
    profileDigest: context.scope.profileDigest,
    state: 'COMPLETE' as const,
    stale: false as const,
    comparable: true as const,
    sequence: 2,
    previousScanRequestId: context.comparison!.scanRequestId,
    previousCommitSha: context.comparison!.commitSha,
    completeCapabilities: [
      'SAST',
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION'
    ] as SastFindingLifecycleCoverageDecision['completeCapabilities'],
    eligibleLineageIds: [],
    expectedObservationBatchDigests: [digest('observation-batch')],
    sourceCoverageDecisionDigest:
      context.scope.coverageDecisionDigest,
    sourceCoverageDecisionRef: context.scope.coverageDecisionId,
    completedAt: DECIDED_AT,
    decidedAt: DECIDED_AT
  };
  return {
    ...core,
    decisionDigest: digest(
      canonicalizeSastFindingLifecycleCoverageDecision(core)
    )
  };
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function id(prefix: string, value: string): string {
  return `${prefix}://${createHash('sha256').update(value).digest('hex')}`;
}
