import { createHash } from 'node:crypto';

import {
  SAST_RULE_BUNDLE_ROLLBACK_REQUEST_VERSION,
  buildSastRuleBundleLifecycleTransition,
  buildSastRuleBundleManifest,
  buildSastRuleBundlePromotionApproval,
  buildSastRuleBundlePromotionEvidence,
  buildSastRuleBundleSupplyChainAttestation,
  type SastRuleBundleLifecycleTransition,
  type SastRuleBundlePromotionApproval,
  type SastRuleBundlePromotionEvidence,
  type SastRuleBundleRollbackApproval,
  type SastRuleBundleRollbackCommand,
  type SastRuleBundleRollbackReceipt,
  type SastRuleBundleRollbackVerification
} from '@aegisai/shared';

import type { SastRuleBundleLifecycleAuthorityInput } from '../../src/rule-governance/sast-rule-bundle-lifecycle.authority';
import { SastRuleBundleLifecycleStore } from '../../src/rule-governance/sast-rule-bundle-lifecycle.store';
import {
  SastRuleBundleManifestStore,
  type PersistedSastRuleBundleCompatibilityReceipt,
  type PersistedVerifiedSastRuleBundle
} from '../../src/rule-governance/sast-rule-bundle-manifest.store';
import { SastRuleBundleRollbackClock } from '../../src/rule-governance/sast-rule-bundle-rollback.clock';
import {
  SastRuleBundleRollbackSignatureAuthority,
  UnavailableSastRuleBundleRollbackSignatureAuthority
} from '../../src/rule-governance/sast-rule-bundle-rollback-signature.authority';
import {
  SastRuleBundleRollbackService,
  type SastRuleBundleRollbackServiceError
} from '../../src/rule-governance/sast-rule-bundle-rollback.service';
import {
  SastRuleBundleRollbackPersistenceError,
  SastRuleBundleRollbackStore,
  type PersistedSastRuleBundleRollbackApproval,
  type PersistedSastRuleBundleRollbackCommand,
  type PersistedSastRuleBundleRollbackReceipt,
  type SastRuleBundleRollbackCommandSnapshot
} from '../../src/rule-governance/sast-rule-bundle-rollback.store';

describe('SastRuleBundleRollbackService T050 authority', () => {
  it('derives the last-known-good target, records dual control, and authorizes only rollback', async () => {
    const fixture = fixtures();
    const clock = new MutableClock('2026-08-19T01:31:00.000Z');
    const store = new InMemoryRollbackStore();
    const service = rollbackService(fixture, store, clock);

    const persisted = await service.registerCommand(request(fixture));

    expect(persisted.command).toMatchObject({
      candidateManifestId: fixture.candidate.manifest.manifestId,
      baselineManifestId: fixture.baseline.manifest.manifestId,
      baselineBundleDigest: fixture.baseline.manifest.bundleDigest,
      rollbackTargetDerived: true,
      customerTargetAccepted: false
    });
    expect(persisted.command.baselineBundleDigest).toBe(
      fixture.candidate.manifest.rollbackTargetDigest
    );

    clock.value = '2026-08-19T01:32:00.000Z';
    await service.registerApproval(
      rollbackApproval(persisted.command, 'SECURITY_ENGINEERING', 'security', clock.value)
    );
    clock.value = '2026-08-19T01:33:00.000Z';
    await service.registerApproval(
      rollbackApproval(persisted.command, 'SCAN_PLATFORM', 'platform', clock.value)
    );
    clock.value = '2026-08-19T01:34:00.000Z';

    const receipt = await service.authorizeLifecycleTransition(
      authorityInput(persisted.command, clock.value)
    );

    expect(receipt).toMatchObject({
      authority: 'ROLLBACK',
      manifestId: fixture.candidate.manifest.manifestId,
      fromState: 'SUSPENDED',
      toState: 'ROLLED_BACK',
      requestedAt: clock.value,
      verifiedAt: clock.value
    });
    expect(receipt.receiptRef.endsWith(receipt.receiptDigest)).toBe(true);
    expect(store.receipt).toMatchObject({
      baselineManifestId: fixture.baseline.manifest.manifestId,
      baselineMutationAuthorized: false,
      historicalMutationAuthorized: false,
      scannerSetMutationAuthorized: false,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      scmWriteAuthority: false
    });
  });

  it('fails closed when the signature authority is not installed', async () => {
    const fixture = fixtures();
    const service = rollbackService(
      fixture,
      new InMemoryRollbackStore(),
      new MutableClock('2026-08-19T01:31:00.000Z'),
      new UnavailableSastRuleBundleRollbackSignatureAuthority()
    );

    await expect(service.registerCommand(request(fixture))).rejects.toMatchObject<
      Partial<SastRuleBundleRollbackServiceError>
    >({ reason: 'SIGNATURE_UNAVAILABLE' });
  });

  it('rejects a caller-selected rollback baseline before reading trusted state', async () => {
    const fixture = fixtures();
    const store = new InMemoryRollbackStore();
    const service = rollbackService(
      fixture,
      store,
      new MutableClock('2026-08-19T01:31:00.000Z')
    );
    const callerSelectedRequest = {
      ...request(fixture),
      baselineManifestId: fixture.baseline.manifest.manifestId,
      baselineBundleDigest: fixture.baseline.manifest.bundleDigest
    };

    await expect(
      service.registerCommand(callerSelectedRequest)
    ).rejects.toMatchObject<Partial<SastRuleBundleRollbackServiceError>>({
      reason: 'INPUT_INVALID'
    });
    expect(store.command).toBeNull();
  });

  it('rejects self approval and a second platform-side role', async () => {
    const fixture = fixtures();
    const clock = new MutableClock('2026-08-19T01:31:00.000Z');
    const store = new InMemoryRollbackStore();
    const service = rollbackService(fixture, store, clock);
    const command = (await service.registerCommand(request(fixture))).command;

    clock.value = '2026-08-19T01:32:00.000Z';
    await expect(
      service.registerApproval({
        ...rollbackApproval(
          command,
          'SECURITY_ENGINEERING',
          'self',
          clock.value
        ),
        approverRef: command.actorRef
      })
    ).rejects.toMatchObject<Partial<SastRuleBundleRollbackServiceError>>({
      reason: 'APPROVAL_INVALID'
    });

    await service.registerApproval(
      rollbackApproval(command, 'SCAN_PLATFORM', 'platform', clock.value)
    );
    await expect(
      service.registerApproval(
        rollbackApproval(
          command,
          'SECURITY_OPERATIONS',
          'operations',
          clock.value
        )
      )
    ).rejects.toMatchObject<Partial<SastRuleBundleRollbackServiceError>>({
      reason: 'APPROVAL_INVALID'
    });
  });

  it('issues no receipt when the active baseline changes before authorization', async () => {
    const fixture = fixtures();
    const clock = new MutableClock('2026-08-19T01:31:00.000Z');
    const store = new InMemoryRollbackStore();
    const service = rollbackService(fixture, store, clock);
    const command = (await service.registerCommand(request(fixture))).command;
    clock.value = '2026-08-19T01:32:00.000Z';
    await service.registerApproval(
      rollbackApproval(command, 'SECURITY_ENGINEERING', 'security', clock.value)
    );
    clock.value = '2026-08-19T01:33:00.000Z';
    await service.registerApproval(
      rollbackApproval(command, 'SECURITY_OPERATIONS', 'operations', clock.value)
    );
    fixture.lifecycle.snapshots.delete(fixture.baseline.manifest.manifestId);
    clock.value = '2026-08-19T01:34:00.000Z';

    await expect(
      service.authorizeLifecycleTransition(authorityInput(command, clock.value))
    ).rejects.toMatchObject<Partial<SastRuleBundleRollbackServiceError>>({
      reason: 'STATE_STALE'
    });
    expect(store.receipt).toBeNull();
  });

  it('issues no receipt when the baseline remains present but is no longer active', async () => {
    const fixture = fixtures();
    const clock = new MutableClock('2026-08-19T01:31:00.000Z');
    const store = new InMemoryRollbackStore();
    const service = rollbackService(fixture, store, clock);
    const command = (await service.registerCommand(request(fixture))).command;
    clock.value = '2026-08-19T01:32:00.000Z';
    await service.registerApproval(
      rollbackApproval(command, 'SECURITY_ENGINEERING', 'security', clock.value)
    );
    clock.value = '2026-08-19T01:33:00.000Z';
    await service.registerApproval(
      rollbackApproval(command, 'SECURITY_OPERATIONS', 'operations', clock.value)
    );
    const baselineSnapshot = fixture.lifecycle.snapshots.get(
      fixture.baseline.manifest.manifestId
    );
    if (!baselineSnapshot) throw new Error('baseline fixture missing');
    fixture.lifecycle.snapshots.set(fixture.baseline.manifest.manifestId, {
      ...baselineSnapshot,
      transition: lifecycleTransition({
        evidence: baselineSnapshot.evidence,
        approvals: baselineSnapshot.approvals,
        sequence: baselineSnapshot.transition.sequence + 1,
        fromState: 'ACTIVE',
        toState: 'RETIRED',
        transitionedAt: '2026-08-19T01:25:00.000Z',
        previous: baselineSnapshot.transition,
        externalAuthority: 'NONE'
      })
    });
    clock.value = '2026-08-19T01:34:00.000Z';

    await expect(
      service.authorizeLifecycleTransition(authorityInput(command, clock.value))
    ).rejects.toMatchObject<Partial<SastRuleBundleRollbackServiceError>>({
      reason: 'STATE_STALE'
    });
    expect(store.receipt).toBeNull();
  });

  it('accepts command and approval at the exact fifteen-minute boundary', async () => {
    const fixture = fixtures();
    const clock = new MutableClock('2026-08-19T01:45:00.000Z');
    const store = new InMemoryRollbackStore();
    const service = rollbackService(fixture, store, clock);
    const command = (await service.registerCommand(request(fixture))).command;

    await expect(
      service.registerApproval(
        rollbackApproval(command, 'SECURITY_ENGINEERING', 'security', clock.value)
      )
    ).resolves.toMatchObject({ replayed: false });
  });

  it('rejects command and approval one millisecond after the incident window', async () => {
    const lateCommandFixture = fixtures();
    const lateCommandStore = new InMemoryRollbackStore();
    const lateCommandService = rollbackService(
      lateCommandFixture,
      lateCommandStore,
      new MutableClock('2026-08-19T01:45:00.001Z')
    );

    await expect(
      lateCommandService.registerCommand(request(lateCommandFixture))
    ).rejects.toMatchObject<Partial<SastRuleBundleRollbackServiceError>>({
      reason: 'INPUT_INVALID'
    });
    expect(lateCommandStore.command).toBeNull();

    const lateApprovalFixture = fixtures();
    const lateApprovalClock = new MutableClock('2026-08-19T01:31:00.000Z');
    const lateApprovalService = rollbackService(
      lateApprovalFixture,
      new InMemoryRollbackStore(),
      lateApprovalClock
    );
    const command = (
      await lateApprovalService.registerCommand(request(lateApprovalFixture))
    ).command;
    lateApprovalClock.value = '2026-08-19T01:45:00.001Z';

    await expect(
      lateApprovalService.registerApproval(
        rollbackApproval(
          command,
          'SECURITY_ENGINEERING',
          'security',
          lateApprovalClock.value
        )
      )
    ).rejects.toMatchObject<Partial<SastRuleBundleRollbackServiceError>>({
      reason: 'APPROVAL_INVALID'
    });
  });
});

class InMemoryRollbackStore extends SastRuleBundleRollbackStore {
  command: SastRuleBundleRollbackCommand | null = null;
  verification: SastRuleBundleRollbackVerification | null = null;
  approvals: SastRuleBundleRollbackApproval[] = [];
  receipt: SastRuleBundleRollbackReceipt | null = null;

  async registerCommand(input: {
    command: Readonly<SastRuleBundleRollbackCommand>;
    verification: Readonly<SastRuleBundleRollbackVerification>;
  }): Promise<PersistedSastRuleBundleRollbackCommand> {
    this.command = structuredClone(input.command);
    this.verification = structuredClone(input.verification);
    return {
      command: structuredClone(input.command),
      verification: structuredClone(input.verification),
      replayed: false
    };
  }

  async findCommandForCandidate(
    manifestId: string
  ): Promise<SastRuleBundleRollbackCommandSnapshot | null> {
    return this.command?.candidateManifestId === manifestId
      ? this.snapshot()
      : null;
  }

  async findCommand(
    commandId: string
  ): Promise<SastRuleBundleRollbackCommandSnapshot | null> {
    return this.command?.commandId === commandId ? this.snapshot() : null;
  }

  async registerApproval(
    approval: Readonly<SastRuleBundleRollbackApproval>
  ): Promise<PersistedSastRuleBundleRollbackApproval> {
    const existing = this.approvals.find(
      (current) => current.approvalId === approval.approvalId
    );
    if (existing) {
      if (existing.approvalDigest !== approval.approvalDigest) {
        throw new SastRuleBundleRollbackPersistenceError('REPLAY_CONFLICT');
      }
      return { approval: structuredClone(existing), replayed: true };
    }
    this.approvals.push(structuredClone(approval));
    return { approval: structuredClone(approval), replayed: false };
  }

  async registerReceipt(
    receipt: Readonly<SastRuleBundleRollbackReceipt>
  ): Promise<PersistedSastRuleBundleRollbackReceipt> {
    if (this.receipt) {
      if (this.receipt.receiptDigest !== receipt.receiptDigest) {
        throw new SastRuleBundleRollbackPersistenceError('REPLAY_CONFLICT');
      }
      return { receipt: structuredClone(this.receipt), replayed: true };
    }
    this.receipt = structuredClone(receipt);
    return { receipt: structuredClone(receipt), replayed: false };
  }

  private snapshot(): SastRuleBundleRollbackCommandSnapshot {
    if (!this.command || !this.verification) {
      throw new SastRuleBundleRollbackPersistenceError('LEDGER_CORRUPT');
    }
    return {
      command: structuredClone(this.command),
      verification: structuredClone(this.verification),
      approvals: structuredClone(this.approvals),
      receipt: structuredClone(this.receipt)
    };
  }
}

class InMemoryManifestStore extends SastRuleBundleManifestStore {
  constructor(
    private readonly manifests: Map<string, PersistedVerifiedSastRuleBundle>
  ) {
    super();
  }

  async registerVerified(): Promise<PersistedVerifiedSastRuleBundle> {
    throw new Error('not used');
  }

  async findVerified(
    manifestId: string
  ): Promise<PersistedVerifiedSastRuleBundle | null> {
    return structuredClone(this.manifests.get(manifestId) ?? null);
  }

  async recordCompatibilityReceipt(): Promise<PersistedSastRuleBundleCompatibilityReceipt> {
    throw new Error('not used');
  }
}

class InMemoryLifecycleStore extends SastRuleBundleLifecycleStore {
  snapshots = new Map<
    string,
    {
      transition: SastRuleBundleLifecycleTransition;
      evidence: SastRuleBundlePromotionEvidence;
      approvals: SastRuleBundlePromotionApproval[];
    }
  >();

  async findLatestLifecycleSnapshot(manifestId: string) {
    return structuredClone(this.snapshots.get(manifestId) ?? null);
  }

  async registerPromotionEvidence(): Promise<never> {
    throw new Error('not used');
  }

  async findPromotionEvidence(): Promise<never> {
    throw new Error('not used');
  }

  async registerPromotionApproval(): Promise<never> {
    throw new Error('not used');
  }

  async findPromotionApprovals(): Promise<never> {
    throw new Error('not used');
  }

  async appendLifecycleTransition(): Promise<never> {
    throw new Error('not used');
  }

  async recordLifecycleSelections(): Promise<never> {
    throw new Error('not used');
  }
}

class AcceptingRollbackSignatureAuthority extends SastRuleBundleRollbackSignatureAuthority {
  async verify(command: Readonly<SastRuleBundleRollbackCommand>) {
    return {
      signerIdentity: 'kms://aegis/security/rollback-signer',
      signatureRef: command.signatureRef,
      provenanceRef: command.provenanceRef,
      signatureVerified: true as const,
      provenanceVerified: true as const,
      trustedSigner: true as const,
      signatureBytesStored: false as const,
      provenancePayloadStored: false as const
    };
  }
}

class MutableClock extends SastRuleBundleRollbackClock {
  constructor(public value: string) {
    super();
  }

  now(): Date {
    return new Date(this.value);
  }
}

interface RollbackFixtures {
  candidate: PersistedVerifiedSastRuleBundle;
  baseline: PersistedVerifiedSastRuleBundle;
  manifests: InMemoryManifestStore;
  lifecycle: InMemoryLifecycleStore;
  candidateSnapshot: {
    transition: SastRuleBundleLifecycleTransition;
    evidence: SastRuleBundlePromotionEvidence;
    approvals: SastRuleBundlePromotionApproval[];
  };
}

function fixtures(): RollbackFixtures {
  const bundleId = 'sast-rule-bundle://opengrep/default';
  const candidate = verifiedBundle(
    'candidate',
    '3.0.0',
    bundleId,
    sha('candidate-bundle'),
    sha('baseline-bundle')
  );
  const baseline = verifiedBundle(
    'baseline',
    '2.0.0',
    bundleId,
    sha('baseline-bundle'),
    sha('older-bundle')
  );
  const older = verifiedBundle(
    'older',
    '1.0.0',
    bundleId,
    sha('older-bundle'),
    sha('oldest-bundle')
  );
  const candidateEvidence = evidence(candidate, baseline, 'candidate');
  const candidateApprovals = promotionApprovals(candidateEvidence, 'candidate');
  const active = lifecycleTransition({
    evidence: candidateEvidence,
    approvals: candidateApprovals,
    sequence: 3,
    fromState: 'CANARY',
    toState: 'ACTIVE',
    transitionedAt: '2026-08-19T01:10:00.000Z',
    externalAuthority: 'CANARY_OBSERVATION',
    externalDigest: sha('candidate-canary-authority')
  });
  const suspended = lifecycleTransition({
    evidence: candidateEvidence,
    approvals: candidateApprovals,
    sequence: 4,
    fromState: 'ACTIVE',
    toState: 'SUSPENDED',
    transitionedAt: '2026-08-19T01:20:00.000Z',
    previous: active,
    externalAuthority: 'EMERGENCY_SUSPENSION',
    externalDigest: sha('candidate-suspension-authority')
  });

  const baselineEvidence = evidence(baseline, older, 'baseline');
  const baselineApprovals = promotionApprovals(baselineEvidence, 'baseline');
  const baselineActive = lifecycleTransition({
    evidence: baselineEvidence,
    approvals: baselineApprovals,
    sequence: 3,
    fromState: 'CANARY',
    toState: 'ACTIVE',
    transitionedAt: '2026-08-19T01:05:00.000Z',
    externalAuthority: 'CANARY_OBSERVATION',
    externalDigest: sha('baseline-canary-authority')
  });

  const lifecycle = new InMemoryLifecycleStore();
  const candidateSnapshot = {
    transition: suspended,
    evidence: candidateEvidence,
    approvals: candidateApprovals
  };
  lifecycle.snapshots.set(candidate.manifest.manifestId, candidateSnapshot);
  lifecycle.snapshots.set(baseline.manifest.manifestId, {
    transition: baselineActive,
    evidence: baselineEvidence,
    approvals: baselineApprovals
  });
  return {
    candidate,
    baseline,
    manifests: new InMemoryManifestStore(
      new Map([
        [candidate.manifest.manifestId, candidate],
        [baseline.manifest.manifestId, baseline],
        [older.manifest.manifestId, older]
      ])
    ),
    lifecycle,
    candidateSnapshot
  };
}

function rollbackService(
  fixture: RollbackFixtures,
  store: SastRuleBundleRollbackStore,
  clock: SastRuleBundleRollbackClock,
  signature: SastRuleBundleRollbackSignatureAuthority =
    new AcceptingRollbackSignatureAuthority()
) {
  return new SastRuleBundleRollbackService(
    store,
    fixture.manifests,
    fixture.lifecycle,
    signature,
    clock
  );
}

function request(fixture: RollbackFixtures) {
  return {
    version: SAST_RULE_BUNDLE_ROLLBACK_REQUEST_VERSION,
    candidateManifestId: fixture.candidate.manifest.manifestId,
    suspendedTransitionId: fixture.candidateSnapshot.transition.transitionId,
    suspendedTransitionDigest:
      fixture.candidateSnapshot.transition.transitionDigest,
    incidentRef: reference('rollback-incident'),
    actorRef: 'staff://security/on-call',
    actorRole: 'SECURITY_ON_CALL' as const,
    reasonRef: reference('rollback-reason'),
    auditRef: reference('rollback-audit'),
    signatureRef: reference('rollback-signature'),
    provenanceRef: reference('rollback-provenance'),
    commandedAt: '2026-08-19T01:30:00.000Z'
  };
}

function rollbackApproval(
  command: Readonly<SastRuleBundleRollbackCommand>,
  role: 'SECURITY_ENGINEERING' | 'SCAN_PLATFORM' | 'SECURITY_OPERATIONS',
  slug: string,
  approvedAt: string
) {
  return {
    commandId: command.commandId,
    commandDigest: command.commandDigest,
    role,
    approverRef: `staff://${slug}/approver`,
    approvalRef: reference(`rollback-approval-${slug}`),
    approvedAt
  };
}

function authorityInput(
  command: Readonly<SastRuleBundleRollbackCommand>,
  requestedAt: string
): SastRuleBundleLifecycleAuthorityInput {
  return {
    authority: 'ROLLBACK',
    manifestId: command.candidateManifestId,
    manifestDigest: command.candidateManifestDigest,
    bundleId: command.candidateBundleId,
    bundleDigest: command.candidateBundleDigest,
    fromState: 'SUSPENDED',
    toState: 'ROLLED_BACK',
    promotionEvidenceId: command.promotionEvidenceId,
    promotionEvidenceDigest: command.promotionEvidenceDigest,
    actorRef: command.actorRef,
    reasonRef: command.reasonRef,
    auditRef: command.auditRef,
    requestedAt
  };
}

function verifiedBundle(
  slug: string,
  bundleVersion: string,
  bundleId: string,
  bundleDigest: `sha256:${string}`,
  rollbackTargetDigest: `sha256:${string}`
): PersistedVerifiedSastRuleBundle {
  const manifest = buildSastRuleBundleManifest(
    {
      bundleId,
      bundleVersion,
      lifecycleState: 'ACTIVE',
      scanner: 'OPENGREP',
      builtAt: '2026-08-19T00:00:00.000Z',
      sourceRevision: sha(`${slug}-revision`).slice('sha256:'.length),
      bundleDigest,
      members: [
        { memberId: `rules/${slug}.yml`, digest: sha(`${slug}-member`) }
      ],
      rules: [
        {
          ruleId: `t050.rollback.${slug}`,
          ruleRevision: bundleVersion,
          ruleSemanticId: `aegis.t050.rollback.${slug}`,
          metadataDigest: sha(`${slug}-metadata`)
        }
      ],
      compatibility: {
        scannerVersions: ['1.22.0'],
        scannerImageDigests: [sha('scanner-image')],
        wrapperDigests: [sha('wrapper')],
        schemaBundleDigests: [sha('schema')],
        normalizerBundleDigests: [sha('normalizer')],
        profileIds: ['JAVA_FAST_V1']
      },
      qualityEvidence: {
        goldenCorpusResultRef: reference(`${slug}-golden`),
        regressionCorpusResultRef: reference(`${slug}-regression`),
        maliciousCorpusResultRef: reference(`${slug}-malicious`),
        performanceCorpusResultRef: reference(`${slug}-performance`)
      },
      signerIdentity: 'sast-signer://t050-tests/rules',
      signatureRef: reference(`${slug}-signature`),
      provenanceRef: reference(`${slug}-provenance`),
      compatibilityRef: reference(`${slug}-compatibility`),
      rolloutPolicyRef: reference(`${slug}-rollout`),
      killSwitchNamespace: 'sast-kill-switch://rule-bundles/t050-tests',
      killSwitchRef: reference(`${slug}-kill-switch`),
      rollbackTargetDigest
    },
    digest
  );
  if (!manifest) throw new Error('manifest fixture invalid');
  const attestation = buildSastRuleBundleSupplyChainAttestation({
    manifest,
    verifiedAt: '2026-08-19T00:05:00.000Z',
    digestCanonical: digest
  });
  if (!attestation) throw new Error('attestation fixture invalid');
  return { manifest, attestation, replayed: false };
}

function evidence(
  candidate: PersistedVerifiedSastRuleBundle,
  baseline: PersistedVerifiedSastRuleBundle,
  slug: string
): SastRuleBundlePromotionEvidence {
  const value = buildSastRuleBundlePromotionEvidence(
    {
      manifestId: candidate.manifest.manifestId,
      manifestDigest: candidate.manifest.manifestDigest,
      verificationId: candidate.attestation.verificationId,
      verificationDigest: candidate.attestation.attestationDigest,
      bundleId: candidate.manifest.bundleId,
      bundleDigest: candidate.manifest.bundleDigest,
      profileId: 'JAVA_FAST_V1',
      candidateAuthorRef: `sast-actor://authors/${slug}`,
      baselineManifestId: baseline.manifest.manifestId,
      baselineManifestDigest: baseline.manifest.manifestDigest,
      baselineBundleDigest: baseline.manifest.bundleDigest,
      rollbackTargetDigest: candidate.manifest.rollbackTargetDigest,
      environmentRef: reference(`${slug}-environment`),
      corpusReferences: {
        goldenCorpusRef: reference(`${slug}-golden`),
        priorMustDetectCorpusRef: reference(`${slug}-prior`),
        maliciousCorpusRef: reference(`${slug}-malicious`),
        parserCorpusRef: reference(`${slug}-parser`),
        fingerprintCorpusRef: reference(`${slug}-fingerprint`),
        coverageCorpusRef: reference(`${slug}-coverage`),
        performanceCorpusRef: reference(`${slug}-performance`)
      },
      measurements: {
        positiveCases: 200,
        negativeCases: 200,
        performanceRuns: 30,
        goldenPassedCases: 400,
        goldenTotalCases: 400,
        priorMustDetectPassedCases: 200,
        priorMustDetectTotalCases: 200,
        mustDetectTruePositiveCases: 190,
        mustDetectExpectedCases: 200,
        criticalHighTruePositiveCases: 180,
        criticalHighReportedCases: 200,
        maliciousPassedCases: 40,
        maliciousTotalCases: 40,
        parserRejectedCases: 40,
        parserExpectedRejectCases: 40,
        fingerprintPassedCases: 40,
        fingerprintTotalCases: 40,
        coveragePassedCases: 40,
        coverageTotalCases: 40,
        falsePositiveIncreaseBasisPoints: 200,
        scannerFailureRateBasisPoints: 200,
        p95LatencyIncreaseBasisPoints: 2_000,
        candidateP95LatencyMilliseconds: 600_000,
        crossTenantEvents: 0,
        secretLeakEvents: 0,
        sandboxEscapeEvents: 0,
        stalePublicationEvents: 0
      },
      measuredAt: '2026-08-19T01:00:00.000Z'
    },
    digest
  );
  if (!value) throw new Error('evidence fixture invalid');
  return value;
}

function promotionApprovals(
  promotionEvidence: SastRuleBundlePromotionEvidence,
  slug: string
): SastRuleBundlePromotionApproval[] {
  return (['SECURITY_ENGINEERING', 'SCAN_PLATFORM'] as const).map(
    (role, index) => {
      const value = buildSastRuleBundlePromotionApproval(
        {
          evidenceId: promotionEvidence.evidenceId,
          evidenceDigest: promotionEvidence.evidenceDigest,
          manifestId: promotionEvidence.manifestId,
          manifestDigest: promotionEvidence.manifestDigest,
          bundleDigest: promotionEvidence.bundleDigest,
          candidateAuthorRef: promotionEvidence.candidateAuthorRef,
          role,
          approverRef: `sast-approver://${slug}/${index}`,
          approvalRef: reference(`${slug}-promotion-${index}`),
          approvedAt: `2026-08-19T01:0${index + 1}:00.000Z`
        },
        digest
      );
      if (!value) throw new Error('approval fixture invalid');
      return value;
    }
  );
}

function lifecycleTransition(input: {
  evidence: SastRuleBundlePromotionEvidence;
  approvals: SastRuleBundlePromotionApproval[];
  sequence: number;
  fromState: 'CANARY' | 'ACTIVE';
  toState: 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  transitionedAt: string;
  previous?: SastRuleBundleLifecycleTransition;
  externalAuthority: 'NONE' | 'CANARY_OBSERVATION' | 'EMERGENCY_SUSPENSION';
  externalDigest?: `sha256:${string}`;
}): SastRuleBundleLifecycleTransition {
  const value = buildSastRuleBundleLifecycleTransition(
    {
      manifestId: input.evidence.manifestId,
      manifestDigest: input.evidence.manifestDigest,
      bundleId: input.evidence.bundleId,
      bundleDigest: input.evidence.bundleDigest,
      sequence: input.sequence,
      fromState: input.fromState,
      toState: input.toState,
      previousTransitionId: input.previous?.transitionId ??
        lifecycleId(`previous-${input.evidence.manifestId}-${input.sequence}`),
      previousTransitionDigest: input.previous?.transitionDigest ??
        sha(`previous-${input.evidence.manifestId}-${input.sequence}`),
      promotionEvidenceId: input.evidence.evidenceId,
      promotionEvidenceDigest: input.evidence.evidenceDigest,
      candidateAuthorRef: input.evidence.candidateAuthorRef,
      approvals: input.approvals.map((approval) => ({
        approvalId: approval.approvalId,
        approvalDigest: approval.approvalDigest,
        role: approval.role,
        approverRef: approval.approverRef,
        approvedAt: approval.approvedAt
      })),
      externalAuthority: input.externalAuthority,
      externalAuthorityReceiptRef:
        input.externalAuthority === 'NONE'
          ? null
          : `sast-authority://${input.externalAuthority.toLowerCase()}/${input.externalDigest}`,
      externalAuthorityReceiptDigest:
        input.externalAuthority === 'NONE' ? null : input.externalDigest ?? null,
      actorRef: 'sast-actor://rule-governance/controller',
      reasonRef: reference(`lifecycle-${input.sequence}-reason`),
      auditRef: reference(`lifecycle-${input.sequence}-audit`),
      transitionedAt: input.transitionedAt
    },
    digest
  );
  if (!value) throw new Error('transition fixture invalid');
  return value;
}

function lifecycleId(seed: string): string {
  return `sast-rule-bundle-lifecycle-transition://${suffix(seed)}`;
}

function reference(seed: string): string {
  return `sast-reference://rollback/${seed}/${sha(seed)}`;
}

function digest(value: string): `sha256:${string}` {
  return sha(value);
}

function sha(value: string): `sha256:${string}` {
  return `sha256:${suffix(value)}`;
}

function suffix(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
