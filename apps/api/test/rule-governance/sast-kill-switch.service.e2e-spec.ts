import { createHash } from 'node:crypto';

import {
  buildSastKillSwitchEvaluation,
  buildSastKillSwitchEvaluationContext,
  buildSastKillSwitchEmergencySuspensionReceipt,
  buildSastKillSwitchHeadBinding,
  type SastKillSwitchControlDecision,
  type SastKillSwitchControlDecisionInput,
  type SastKillSwitchEmergencySuspensionReceipt,
  type SastKillSwitchEvaluationContext,
  type SastKillSwitchEvaluationResult,
  type SastKillSwitchGate,
  type SastKillSwitchVerification,
  type SastScanPlan
} from '@aegisai/shared';

import { SastKillSwitchClock } from '../../src/rule-governance/sast-kill-switch.clock';
import {
  SastKillSwitchCanarySuspensionService,
  SastKillSwitchCanarySuspensionSignalError
} from '../../src/rule-governance/sast-kill-switch-canary-suspension.service';
import {
  SastKillSwitchService,
  SastKillSwitchServiceError
} from '../../src/rule-governance/sast-kill-switch.service';
import {
  SastKillSwitchSignatureAuthority,
  SastKillSwitchSignatureAuthorityError,
  type SastKillSwitchSignatureVerificationFacts
} from '../../src/rule-governance/sast-kill-switch-signature.authority';
import {
  SastKillSwitchStore,
  type PersistedSastKillSwitchDecision,
  type SastKillSwitchPersistedPlanScope
} from '../../src/rule-governance/sast-kill-switch.store';
import type { SastRuleBundleLifecycleAuthorityInput } from '../../src/rule-governance/sast-rule-bundle-lifecycle.authority';

describe('SastKillSwitchService T049 authority', () => {
  it('registers only an exact trusted content-free verification', async () => {
    const store = new InMemoryKillSwitchStore();
    const service = new SastKillSwitchService(
      store,
      new AcceptingSignatureAuthority(),
      new FixedClock('2026-08-19T00:01:00.000Z')
    );

    const persisted = await service.registerDecision(decisionInput());

    expect(persisted.replayed).toBe(false);
    expect(persisted.decision).toMatchObject({
      action: 'ACTIVATE',
      sequence: 1,
      source: 'PLATFORM_MANAGED',
      customerInputAccepted: false
    });
    expect(persisted.verification).toMatchObject({
      decisionId: persisted.decision.decisionId,
      decisionDigest: persisted.decision.decisionDigest,
      signatureVerified: true,
      provenanceVerified: true,
      trustedSigner: true,
      signatureBytesStored: false,
      provenancePayloadStored: false
    });
    expect(persisted.decision).not.toHaveProperty('sourceContent');
    expect(persisted.decision).not.toHaveProperty('findingContent');
    expect(persisted.decision).not.toHaveProperty('secretValue');
    expect(persisted.verification).not.toHaveProperty('signatureBytes');
    expect(persisted.verification).not.toHaveProperty('provenancePayload');
  });

  it('fails closed when the production signature authority is unavailable', async () => {
    const service = new SastKillSwitchService(
      new InMemoryKillSwitchStore(),
      new UnavailableSignatureAuthority(),
      new FixedClock('2026-08-19T00:01:00.000Z')
    );

    await expect(service.registerDecision(decisionInput())).rejects.toMatchObject<
      Partial<SastKillSwitchServiceError>
    >({ reason: 'SIGNATURE_UNAVAILABLE' });
  });

  it('rejects caller-selected stale or future boundary time', async () => {
    const store = new InMemoryKillSwitchStore();
    const service = new SastKillSwitchService(
      store,
      new AcceptingSignatureAuthority(),
      new FixedClock('2026-08-19T00:01:00.000Z')
    );
    const context = killSwitchContext();

    await expect(
      service.evaluateContext({
        gate: 'COVERAGE',
        context,
        evaluatedAt: '2026-08-19T00:00:54.999Z'
      })
    ).rejects.toMatchObject({ reason: 'AUTHORITY_UNAVAILABLE' });
    await expect(
      service.evaluateContext({
        gate: 'COVERAGE',
        context,
        evaluatedAt: '2026-08-19T00:01:00.001Z'
      })
    ).rejects.toMatchObject({ reason: 'AUTHORITY_UNAVAILABLE' });

    await expect(
      service.evaluateContext({
        gate: 'COVERAGE',
        context,
        evaluatedAt: '2026-08-19T00:00:55.000Z'
      })
    ).resolves.toMatchObject({ receipt: { outcome: 'CLEAR' } });
  });

  it('returns an exact digest-bound lifecycle receipt evaluated at the transition instant', async () => {
    const store = new InMemoryKillSwitchStore();
    const service = new SastKillSwitchService(
      store,
      new AcceptingSignatureAuthority(),
      new FixedClock('2026-08-19T00:02:00.000Z')
    );
    const input: SastRuleBundleLifecycleAuthorityInput = {
      authority: 'EMERGENCY_SUSPENSION',
      manifestId: 'manifest-1',
      manifestDigest: sha('manifest'),
      bundleId: 'bundle-1',
      bundleDigest: sha('bundle'),
      fromState: 'ACTIVE',
      toState: 'SUSPENDED',
      promotionEvidenceId: 'evidence-1',
      promotionEvidenceDigest: sha('evidence'),
      requestedAt: '2026-08-19T00:01:30.000Z'
    };

    const receipt = await service.authorizeEmergencySuspension(input);

    expect(store.suspensionVerifiedAt).toBe(input.requestedAt);
    expect(receipt).toMatchObject({
      authority: 'EMERGENCY_SUSPENSION',
      requestedAt: input.requestedAt,
      verifiedAt: input.requestedAt
    });
    expect(receipt.receiptRef).toBe(
      `sast-kill-switch-suspension://authority/${receipt.receiptDigest}`
    );
    expect(receipt.receiptRef.endsWith(receipt.receiptDigest)).toBe(true);
    expect(receipt.receiptRef).toMatch(
      /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\/sha256:[a-f0-9]{64}$/u
    );
  });

  it('derives a zero-tolerance suspension target only from the locked T048 ledger', async () => {
    const canaryDecisionId =
      `sast-rule-bundle-canary-step-decision://${hex('canary-decision')}`;
    const canaryDecisionDigest = sha('canary-decision');
    const rolloutId = `sast-rule-bundle-canary-rollout://${hex('rollout')}`;
    const rolloutDigest = sha('rollout');
    const candidateManifestId = 'manifest-1';
    const candidateManifestDigest = sha('manifest');
    const candidateBundleId = 'bundle-1';
    const candidateBundleDigest = sha('bundle');
    const transitionId = 'transition-3';
    const transitionDigest = sha('transition');
    const decision = {
      id: canaryDecisionId,
      decisionDigest: canaryDecisionDigest,
      rolloutId,
      rolloutDigest,
      candidateManifestId,
      candidateManifestDigest,
      candidateBundleDigest,
      profileId: 'JAVA_DEEP_V1',
      profileDigest: sha('profile'),
      outcome: 'PAUSED',
      reasonCodeCount: 1,
      evaluatedAt: new Date('2026-08-19T00:00:00.000Z')
    };
    const rollout = {
      id: rolloutId,
      rolloutDigest,
      candidateManifestId,
      candidateManifestDigest,
      candidateBundleId,
      candidateBundleDigest,
      profileId: decision.profileId,
      profileDigest: decision.profileDigest,
      canaryTransitionId: transitionId,
      canaryTransitionDigest: transitionDigest
    };
    const tx = {
      $queryRaw: jest
        .fn()
        .mockResolvedValueOnce([
          {
            manifestId: candidateManifestId,
            manifestDigest: candidateManifestDigest,
            bundleId: candidateBundleId,
            bundleDigest: candidateBundleDigest,
            transitionId,
            transitionDigest,
            lifecycleState: 'CANARY'
          }
        ])
        .mockResolvedValueOnce([
          {
            rolloutId,
            rolloutDigest,
            latestDecisionId: canaryDecisionId,
            latestDecisionDigest: canaryDecisionDigest,
            latestOutcome: 'PAUSED'
          }
        ]),
      sastRuleBundleCanaryStepDecision: {
        findUnique: jest.fn().mockResolvedValue(decision)
      },
      sastRuleBundleCanaryRollout: {
        findUnique: jest.fn().mockResolvedValue(rollout)
      },
      sastRuleBundleCanaryStepDecisionReason: {
        findMany: jest.fn().mockResolvedValue([
          { position: 0, reasonCode: 'ZERO_TOLERANCE_EVENT_RECORDED' }
        ])
      }
    };
    const prisma = {
      sastRuleBundleCanaryStepDecision: {
        findUnique: jest.fn().mockResolvedValue({
          rolloutId,
          candidateManifestId
        })
      },
      $transaction: jest.fn(async (operation: (value: typeof tx) => unknown) =>
        operation(tx)
      )
    };
    const service = new SastKillSwitchCanarySuspensionService(prisma as never);

    const signal = await service.resolve({
      version: 'sast-kill-switch-canary-suspension-request-v1',
      canaryDecisionId,
      canaryDecisionDigest
    });

    expect(signal).toMatchObject({
      trigger: 'ZERO_TOLERANCE',
      candidateManifestId,
      candidateManifestDigest,
      candidateBundleId,
      candidateBundleDigest,
      lifecycleTransitionId: transitionId,
      lifecycleTransitionDigest: transitionDigest,
      customerTargetAccepted: false
    });
    expect(tx.$queryRaw).toHaveBeenCalledTimes(2);

    await expect(
      service.resolve({
        version: 'sast-kill-switch-canary-suspension-request-v1',
        canaryDecisionId,
        canaryDecisionDigest,
        candidateBundleDigest: sha('caller-target')
      } as never)
    ).rejects.toMatchObject<Partial<SastKillSwitchCanarySuspensionSignalError>>({
      reason: 'INPUT_INVALID'
    });
  });
});

class FixedClock extends SastKillSwitchClock {
  constructor(private readonly value: string) {
    super();
  }

  now(): Date {
    return new Date(this.value);
  }
}

class AcceptingSignatureAuthority extends SastKillSwitchSignatureAuthority {
  async verify(
    decision: Readonly<SastKillSwitchControlDecision>
  ): Promise<SastKillSwitchSignatureVerificationFacts> {
    return {
      signerIdentity: 'spiffe://aegis/security-on-call',
      signatureRef: decision.signatureRef,
      provenanceRef: decision.provenanceRef,
      signatureVerified: true,
      provenanceVerified: true,
      trustedSigner: true,
      signatureBytesStored: false,
      provenancePayloadStored: false
    };
  }
}

class UnavailableSignatureAuthority extends SastKillSwitchSignatureAuthority {
  async verify(): Promise<never> {
    throw new SastKillSwitchSignatureAuthorityError('UNAVAILABLE');
  }
}

class InMemoryKillSwitchStore extends SastKillSwitchStore {
  suspensionVerifiedAt: string | null = null;

  async appendDecision(
    decision: Readonly<SastKillSwitchControlDecision>,
    verification: Readonly<SastKillSwitchVerification>
  ): Promise<PersistedSastKillSwitchDecision> {
    return {
      decision: structuredClone(decision),
      verification: structuredClone(verification),
      replayed: false
    };
  }

  async evaluate(
    context: Readonly<SastKillSwitchEvaluationContext>,
    gate: SastKillSwitchGate,
    evaluatedAt: string
  ): Promise<SastKillSwitchEvaluationResult> {
    const head = buildSastKillSwitchHeadBinding(
      {
        selectorKey: `sast-kill-switch-selector://${hex('head')}`,
        scope: 'GLOBAL',
        sequence: 0,
        decisionId: null,
        decisionDigest: null,
        action: null,
        active: false,
        effectiveAt: null,
        expiresAt: null
      },
      digest
    );
    if (!head) throw new Error('invalid head fixture');
    const result = buildSastKillSwitchEvaluation(
      { context, gate, heads: [head], evaluatedAt },
      digest
    );
    if (!result) throw new Error('invalid evaluation fixture');
    return { ...result, replayed: false };
  }

  async loadPersistedPlan(
    scope: Readonly<SastKillSwitchPersistedPlanScope>
  ): Promise<SastScanPlan | null> {
    void scope;
    throw new Error('not used');
  }

  async authorizeEmergencySuspension(
    input: Readonly<SastRuleBundleLifecycleAuthorityInput>,
    verifiedAt: string
  ): Promise<SastKillSwitchEmergencySuspensionReceipt> {
    this.suspensionVerifiedAt = verifiedAt;
    const receipt = buildSastKillSwitchEmergencySuspensionReceipt(
      {
        manifestId: input.manifestId,
        manifestDigest: input.manifestDigest,
        bundleId: input.bundleId,
        bundleDigest: input.bundleDigest,
        fromState: input.fromState as 'CANARY' | 'ACTIVE',
        toState: 'SUSPENDED',
        lifecycleSequence: 4,
        lifecycleTransitionId: 'transition-4',
        lifecycleTransitionDigest: sha('transition'),
        promotionEvidenceId: input.promotionEvidenceId,
        promotionEvidenceDigest: input.promotionEvidenceDigest,
        triggerSelectorKey: `sast-kill-switch-selector://${hex('selector')}`,
        triggerDecisionId: `sast-kill-switch-decision://${hex('decision')}`,
        triggerDecisionDigest: sha('decision'),
        activeDecisionCount: 1,
        activeDecisionSetDigest: sha('active-set'),
        requestedAt: input.requestedAt,
        verifiedAt
      },
      digest
    );
    if (!receipt) throw new Error('invalid fixture receipt');
    return receipt;
  }
}

function decisionInput(): SastKillSwitchControlDecisionInput {
  return {
    selector: { scope: 'GLOBAL', runtime: 'SAST' },
    sequence: 1,
    previousDecisionId: null,
    previousDecisionDigest: null,
    action: 'ACTIVATE',
    reasonCode: 'SECURITY_INCIDENT',
    incidentRef: reference('incident'),
    actorRef: reference('actor'),
    actorRole: 'SECURITY_ON_CALL',
    effectiveAt: '2026-08-19T00:00:00.000Z',
    reviewBy: '2026-08-20T00:00:00.000Z',
    expiresAt: '2026-08-21T00:00:00.000Z',
    rollbackTargetRef: reference('rollback'),
    signatureRef: reference('signature'),
    provenanceRef: reference('provenance'),
    auditRef: reference('audit')
  };
}

function killSwitchContext(): SastKillSwitchEvaluationContext {
  const context = buildSastKillSwitchEvaluationContext(
    {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repo-1',
      scanRequestId: 'scan-1',
      profileId: 'JAVA_FAST_V1',
      profileDigest: sha('profile'),
      scannerSetDigest: sha('scanner-set'),
      scanners: [{ scanner: 'OPENGREP', scannerVersion: '1.0.0' }],
      ruleBundles: [],
      requiredCapabilities: ['SAST']
    },
    digest
  );
  if (!context) throw new Error('invalid context fixture');
  return context;
}

function reference(seed: string): string {
  return `immutable://${seed}/sha256:${hex(seed)}`;
}

function sha(seed: string): `sha256:${string}` {
  return `sha256:${hex(seed)}`;
}

function digest(value: string): `sha256:${string}` {
  return sha(value);
}

function hex(seed: string): string {
  return createHash('sha256').update(seed).digest('hex');
}
