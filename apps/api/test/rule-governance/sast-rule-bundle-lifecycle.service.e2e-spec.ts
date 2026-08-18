import { createHash } from 'node:crypto';

import {
  buildSastRuleBundleManifest,
  buildSastRuleBundleSupplyChainAttestation,
  type SastRuleBundleLifecycleSelectionReceipt,
  type SastRuleBundleLifecycleTransition,
  type SastRuleBundleManifest,
  type SastRuleBundlePromotionApproval,
  type SastRuleBundlePromotionEvidence,
  type VerifiedScannerSetDescriptor
} from '@aegisai/shared';

import {
  SastRuleBundleLifecycleAuthority,
  UnavailableSastRuleBundleLifecycleAuthority,
  type SastRuleBundleLifecycleAuthorityInput,
  type SastRuleBundleLifecycleAuthorityReceipt
} from '../../src/rule-governance/sast-rule-bundle-lifecycle.authority';
import { SastRuleBundleLifecycleClock } from '../../src/rule-governance/sast-rule-bundle-lifecycle.clock';
import { SastRuleBundleLifecycleGateError } from '../../src/rule-governance/sast-rule-bundle-lifecycle.gate';
import {
  SastRuleBundleLifecycleService,
  SastRuleBundleLifecycleServiceError
} from '../../src/rule-governance/sast-rule-bundle-lifecycle.service';
import {
  SastRuleBundleLifecyclePersistenceError,
  SastRuleBundleLifecycleStore,
  type PersistedSastRuleBundleLifecycleSelection,
  type PersistedSastRuleBundleLifecycleTransition,
  type PersistedSastRuleBundlePromotionApproval,
  type PersistedSastRuleBundlePromotionEvidence,
  type SastRuleBundleLifecycleLedgerSnapshot
} from '../../src/rule-governance/sast-rule-bundle-lifecycle.store';
import {
  SastRuleBundleManifestStore,
  type PersistedSastRuleBundleCompatibilityReceipt,
  type PersistedVerifiedSastRuleBundle
} from '../../src/rule-governance/sast-rule-bundle-manifest.store';
import { durableSastScanPlan } from '../support/sast-scan-plan-fixtures';

describe('SastRuleBundleLifecycleService T047 gate', () => {
  it('promotes two verified bundles through the exact graph and binds latest ACTIVE receipts', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const service = lifecycleService(fixtures.manifestStore, store);

    for (const pair of fixtures.pairs) {
      await promoteToActive(service, pair);
    }

    const selected = await service.verifyScannerSet({
      scannerSet: fixtures.scannerSet,
      evaluatedAt: '2026-08-14T07:20:00.000Z'
    });

    expect(selected.ruleBundles).toHaveLength(2);
    expect(selected.ruleBundles).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          scanner: 'OPENGREP',
          lifecycle: expect.objectContaining({
            lifecycleState: 'ACTIVE',
            lifecycleSequence: 3,
            selectionReceiptId: expect.stringMatching(
              /^sast-rule-bundle-lifecycle-selection:\/\/[a-f0-9]{64}$/
            )
          })
        })
      ])
    );
    expect(store.selections).toHaveLength(2);
    expect(JSON.stringify(store)).not.toMatch(
      /"sourceContent"|"ruleContent"|"repositoryContent"|"secretValue"/u
    );
  });

  it('keeps automated evidence and human approval authority separate', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const service = lifecycleService(fixtures.manifestStore, store);
    const pair = fixtures.pairs[0];
    const evidence = await service.registerPromotionEvidence(
      evidenceInput(pair)
    );

    expect(evidence.evidence).toMatchObject({
      gatesPassed: true,
      automatedEvidenceOnly: true,
      approvalGranted: false
    });
    await expect(
      service.registerPromotionApproval({
        ...approvalInput(evidence.evidence, 'SECURITY_ENGINEERING', 'security'),
        approverRef: evidence.evidence.candidateAuthorRef
      })
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleServiceError>>({
      reason: 'INPUT_INVALID'
    });

    const approval = await service.registerPromotionApproval(
      approvalInput(evidence.evidence, 'SECURITY_ENGINEERING', 'security')
    );
    expect(approval.approval).toMatchObject({
      humanApproval: true,
      automatedApproval: false,
      candidateAuthorRef: evidence.evidence.candidateAuthorRef
    });
    expect(approval.approval.approverRef).not.toBe(
      evidence.evidence.candidateAuthorRef
    );
  });

  it('rejects evidence when the baseline does not support the measured profile', async () => {
    const pair = bundlePair('OPENGREP', ['JAVA_DEEP_V1']);
    const store = new InMemoryLifecycleStore();
    const service = lifecycleService(
      new InMemoryManifestStore([pair.candidate, pair.baseline]),
      store
    );

    await expect(
      service.registerPromotionEvidence(evidenceInput(pair))
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleServiceError>>({
      reason: 'EVIDENCE_UNVERIFIED'
    });
    expect(store.evidence).toHaveLength(0);
  });

  it('fails closed on illegal edges without appending partial state', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const authority = new AcceptingLifecycleAuthority();
    const authorize = jest.spyOn(authority, 'authorize');
    const service = lifecycleService(fixtures.manifestStore, store, authority);
    const pair = fixtures.pairs[0];
    const evidence = (
      await service.registerPromotionEvidence(evidenceInput(pair))
    ).evidence;
    const security = (
      await service.registerPromotionApproval(
        approvalInput(evidence, 'SECURITY_ENGINEERING', 'security')
      )
    ).approval;

    await expect(
      service.transition(
        transitionRequest(pair, evidence, [security], 'SUSPENDED', '07:10')
      )
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleServiceError>>({
      reason: 'TRANSITION_INVALID'
    });
    expect(store.transitions).toHaveLength(0);
    expect(authorize).not.toHaveBeenCalled();
  });

  it('keeps CANARY fail-closed when the deferred T048 authority is unavailable', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const service = lifecycleService(
      fixtures.manifestStore,
      store,
      new UnavailableSastRuleBundleLifecycleAuthority()
    );
    const pair = fixtures.pairs[0];
    const prepared = await promoteToCanary(service, pair);

    await expect(
      service.transition(
        transitionRequest(
          pair,
          prepared.evidence,
          [prepared.security, prepared.platform],
          'ACTIVE',
          '07:12'
        )
      )
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleServiceError>>({
      reason: 'AUTHORITY_UNAVAILABLE'
    });
    expect(store.transitions).toHaveLength(2);
    expect(store.transitions.at(-1)?.toState).toBe('CANARY');
  });

  it('rejects incomplete ACTIVE approvals before calling external authority', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const authority = new AcceptingLifecycleAuthority();
    const authorize = jest.spyOn(authority, 'authorize');
    const service = lifecycleService(fixtures.manifestStore, store, authority);
    const pair = fixtures.pairs[0];
    const prepared = await promoteToCanary(service, pair);

    await expect(
      service.transition(
        transitionRequest(
          pair,
          prepared.evidence,
          [prepared.security],
          'ACTIVE',
          '07:12'
        )
      )
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleServiceError>>({
      reason: 'APPROVAL_INVALID'
    });
    expect(authorize).not.toHaveBeenCalled();
    expect(store.transitions).toHaveLength(2);
  });

  it('rejects a backward transition timestamp before calling external authority', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const authority = new AcceptingLifecycleAuthority();
    const authorize = jest.spyOn(authority, 'authorize');
    const service = lifecycleService(fixtures.manifestStore, store, authority);
    const pair = fixtures.pairs[0];
    const prepared = await promoteToCanary(service, pair);

    await expect(
      service.transition(
        transitionRequest(
          pair,
          prepared.evidence,
          [prepared.security, prepared.platform],
          'ACTIVE',
          '07:10'
        )
      )
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleServiceError>>({
      reason: 'TRANSITION_INVALID'
    });
    expect(authorize).not.toHaveBeenCalled();
    expect(store.transitions).toHaveLength(2);
  });

  it('rejects a cross-evidence external authority receipt', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const service = lifecycleService(
      fixtures.manifestStore,
      store,
      new DriftedLifecycleAuthority()
    );
    const pair = fixtures.pairs[0];
    const prepared = await promoteToCanary(service, pair);

    await expect(
      service.transition(
        transitionRequest(
          pair,
          prepared.evidence,
          [prepared.security, prepared.platform],
          'ACTIVE',
          '07:12'
        )
      )
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleServiceError>>({
      reason: 'AUTHORITY_UNAVAILABLE'
    });
    expect(store.transitions).toHaveLength(2);
  });

  it('denies planning after an authoritative suspension transition', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const service = lifecycleService(fixtures.manifestStore, store);
    const pair = fixtures.pairs[0];
    const prepared = await promoteToActive(service, pair);
    await promoteToActive(service, fixtures.pairs[1]);
    await service.transition(
      transitionRequest(
        pair,
        prepared.evidence,
        [prepared.security],
        'SUSPENDED',
        '07:13'
      )
    );

    await expect(
      service.verifyScannerSet({
        scannerSet: fixtures.scannerSet,
        evaluatedAt: '2026-08-14T07:20:00.000Z'
      })
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleGateError>>({
      reason: 'LIFECYCLE_STATE_NOT_SELECTABLE'
    });
    expect(store.selections).toHaveLength(0);
  });

  it('persists no partial scanner-set selection when a later bundle is unverified', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const service = lifecycleService(fixtures.manifestStore, store);
    await promoteToActive(service, fixtures.pairs[0]);

    await expect(
      service.verifyScannerSet({
        scannerSet: fixtures.scannerSet,
        evaluatedAt: '2026-08-14T07:20:00.000Z'
      })
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleGateError>>({
      reason: 'PROMOTION_EVIDENCE_UNVERIFIED'
    });
    expect(store.selections).toHaveLength(0);
  });

  it('rejects a selection timestamp older than the latest transition', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const service = lifecycleService(fixtures.manifestStore, store);
    await promoteToActive(service, fixtures.pairs[0]);
    await promoteToActive(service, fixtures.pairs[1]);

    await expect(
      service.verifyScannerSet({
        scannerSet: fixtures.scannerSet,
        evaluatedAt: '2026-08-14T07:11:59.999Z'
      })
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleGateError>>({
      reason: 'LIFECYCLE_STATE_STALE'
    });
    expect(store.selections).toHaveLength(0);
  });

  it('rejects a selection timestamp later than the trusted lifecycle clock', async () => {
    const fixtures = lifecycleFixtures();
    const store = new InMemoryLifecycleStore();
    const service = lifecycleService(fixtures.manifestStore, store);
    await promoteToActive(service, fixtures.pairs[0]);
    await promoteToActive(service, fixtures.pairs[1]);

    await expect(
      service.verifyScannerSet({
        scannerSet: fixtures.scannerSet,
        evaluatedAt: '2026-08-14T08:00:00.001Z'
      })
    ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleGateError>>({
      reason: 'LIFECYCLE_STATE_STALE'
    });
    expect(store.selections).toHaveLength(0);
  });

  it.each(['throwing', 'invalid'] as const)(
    'fails closed with a bounded reason for a %s lifecycle clock',
    async (mode) => {
      const fixtures = lifecycleFixtures();
      const store = new InMemoryLifecycleStore();
      const clock: SastRuleBundleLifecycleClock = {
        now: () => {
          if (mode === 'throwing') throw new Error('clock unavailable');
          return new Date(Number.NaN);
        }
      };
      const service = lifecycleService(
        fixtures.manifestStore,
        store,
        new AcceptingLifecycleAuthority(),
        clock
      );

      await expect(
        service.registerPromotionEvidence(evidenceInput(fixtures.pairs[0]))
      ).rejects.toMatchObject<Partial<SastRuleBundleLifecycleServiceError>>({
        reason: 'STORE_UNAVAILABLE'
      });
      expect(store.evidence).toHaveLength(0);
    }
  );
});

type BundlePair = {
  candidate: PersistedVerifiedSastRuleBundle;
  baseline: PersistedVerifiedSastRuleBundle;
};

class InMemoryLifecycleStore extends SastRuleBundleLifecycleStore {
  readonly evidence: SastRuleBundlePromotionEvidence[] = [];
  readonly approvals: SastRuleBundlePromotionApproval[] = [];
  readonly transitions: SastRuleBundleLifecycleTransition[] = [];
  readonly selections: SastRuleBundleLifecycleSelectionReceipt[] = [];

  async registerPromotionEvidence(
    evidence: Readonly<SastRuleBundlePromotionEvidence>
  ): Promise<PersistedSastRuleBundlePromotionEvidence> {
    const existing = this.evidence.find(
      (item) => item.evidenceId === evidence.evidenceId
    );
    if (existing) {
      if (existing.evidenceDigest !== evidence.evidenceDigest) throw replayError();
      return { evidence: structuredClone(existing), replayed: true };
    }
    this.evidence.push(structuredClone(evidence));
    return { evidence: structuredClone(evidence), replayed: false };
  }

  async findPromotionEvidence(
    evidenceId: string
  ): Promise<PersistedSastRuleBundlePromotionEvidence | null> {
    const evidence = this.evidence.find((item) => item.evidenceId === evidenceId);
    return evidence
      ? { evidence: structuredClone(evidence), replayed: true }
      : null;
  }

  async registerPromotionApproval(
    approval: Readonly<SastRuleBundlePromotionApproval>
  ): Promise<PersistedSastRuleBundlePromotionApproval> {
    const existing = this.approvals.find(
      (item) => item.approvalId === approval.approvalId
    );
    if (existing) {
      if (existing.approvalDigest !== approval.approvalDigest) {
        throw replayError();
      }
      return { approval: structuredClone(existing), replayed: true };
    }
    if (
      this.approvals.some(
        (item) =>
          item.evidenceId === approval.evidenceId &&
          (item.role === approval.role ||
            item.approverRef === approval.approverRef)
      )
    ) {
      throw replayError();
    }
    this.approvals.push(structuredClone(approval));
    return { approval: structuredClone(approval), replayed: false };
  }

  async findPromotionApprovals(
    approvalIds: readonly string[]
  ): Promise<SastRuleBundlePromotionApproval[]> {
    return this.approvals
      .filter((approval) => approvalIds.includes(approval.approvalId))
      .map((approval) => structuredClone(approval));
  }

  async appendLifecycleTransition(
    transition: Readonly<SastRuleBundleLifecycleTransition>
  ): Promise<PersistedSastRuleBundleLifecycleTransition> {
    const existing = this.transitions.find(
      (item) => item.transitionId === transition.transitionId
    );
    if (existing) {
      if (existing.transitionDigest !== transition.transitionDigest) {
        throw replayError();
      }
      return { transition: structuredClone(existing), replayed: true };
    }
    const latest = this.transitions
      .filter((item) => item.manifestId === transition.manifestId)
      .sort((left, right) => right.sequence - left.sequence)[0];
    if (
      (latest &&
        (transition.sequence !== latest.sequence + 1 ||
          transition.previousTransitionId !== latest.transitionId ||
          transition.previousTransitionDigest !== latest.transitionDigest)) ||
      (!latest && transition.sequence !== 1)
    ) {
      throw new SastRuleBundleLifecyclePersistenceError('STALE_TRANSITION');
    }
    this.transitions.push(structuredClone(transition));
    return { transition: structuredClone(transition), replayed: false };
  }

  async findLatestLifecycleSnapshot(
    manifestId: string
  ): Promise<SastRuleBundleLifecycleLedgerSnapshot | null> {
    const transition = this.transitions
      .filter((item) => item.manifestId === manifestId)
      .sort((left, right) => right.sequence - left.sequence)[0];
    if (!transition) return null;
    const evidence = this.evidence.find(
      (item) => item.evidenceId === transition.promotionEvidenceId
    );
    const approvals = transition.approvals.map((binding) =>
      this.approvals.find((item) => item.approvalId === binding.approvalId)
    );
    if (!evidence || approvals.some((approval) => !approval)) {
      throw new SastRuleBundleLifecyclePersistenceError('LEDGER_CORRUPT');
    }
    return {
      transition: structuredClone(transition),
      evidence: structuredClone(evidence),
      approvals: structuredClone(approvals as SastRuleBundlePromotionApproval[])
    };
  }

  async recordLifecycleSelections(
    receipts: readonly Readonly<SastRuleBundleLifecycleSelectionReceipt>[]
  ): Promise<PersistedSastRuleBundleLifecycleSelection[]> {
    if (
      receipts.length === 0 ||
      new Set(receipts.map((receipt) => receipt.manifestId)).size !==
        receipts.length
    ) {
      throw new SastRuleBundleLifecyclePersistenceError('INPUT_INVALID');
    }
    const pending = receipts.map((receipt) => {
      const latest = this.transitions
        .filter((item) => item.manifestId === receipt.manifestId)
        .sort((left, right) => right.sequence - left.sequence)[0];
      if (
        !latest ||
        latest.transitionId !== receipt.transitionId ||
        latest.transitionDigest !== receipt.transitionDigest ||
        latest.sequence !== receipt.lifecycleSequence ||
        latest.toState !== receipt.lifecycleState
      ) {
        throw new SastRuleBundleLifecyclePersistenceError('STALE_TRANSITION');
      }
      const existing = this.selections.find(
        (item) => item.receiptId === receipt.receiptId
      );
      if (existing && existing.receiptDigest !== receipt.receiptDigest) {
        throw replayError();
      }
      return { receipt, existing };
    });
    for (const { receipt, existing } of pending) {
      if (!existing) this.selections.push(structuredClone(receipt));
    }
    return pending.map(({ receipt, existing }) => ({
      receipt: structuredClone(existing ?? receipt),
      replayed: existing !== undefined
    }));
  }
}

class InMemoryManifestStore extends SastRuleBundleManifestStore {
  constructor(readonly verified: PersistedVerifiedSastRuleBundle[]) {
    super();
  }

  async registerVerified(): Promise<never> {
    throw new Error('not used');
  }

  async findVerified(
    manifestId: string
  ): Promise<PersistedVerifiedSastRuleBundle | null> {
    const found = this.verified.find(
      (item) => item.manifest.manifestId === manifestId
    );
    return found ? structuredClone(found) : null;
  }

  async recordCompatibilityReceipt(): Promise<PersistedSastRuleBundleCompatibilityReceipt> {
    throw new Error('not used');
  }
}

class AcceptingLifecycleAuthority extends SastRuleBundleLifecycleAuthority {
  async authorize(
    input: Readonly<SastRuleBundleLifecycleAuthorityInput>
  ): Promise<SastRuleBundleLifecycleAuthorityReceipt> {
    const receiptDigest = digest(
      `${input.authority}:${input.manifestId}:${input.fromState}:${input.toState}:${input.requestedAt}`
    );
    return {
      authority: input.authority,
      manifestId: input.manifestId,
      manifestDigest: input.manifestDigest,
      bundleId: input.bundleId,
      bundleDigest: input.bundleDigest,
      fromState: input.fromState,
      toState: input.toState,
      promotionEvidenceId: input.promotionEvidenceId,
      promotionEvidenceDigest: input.promotionEvidenceDigest,
      requestedAt: input.requestedAt,
      receiptRef: `sast-authority://${input.authority.toLowerCase()}/${receiptDigest}`,
      receiptDigest,
      verifiedAt: input.requestedAt
    };
  }
}

class DriftedLifecycleAuthority extends AcceptingLifecycleAuthority {
  async authorize(
    input: Readonly<SastRuleBundleLifecycleAuthorityInput>
  ): Promise<SastRuleBundleLifecycleAuthorityReceipt> {
    return {
      ...(await super.authorize(input)),
      promotionEvidenceDigest: digest('drifted-authority-evidence')
    };
  }
}

function lifecycleService(
  manifestStore: SastRuleBundleManifestStore,
  store: SastRuleBundleLifecycleStore,
  authority: SastRuleBundleLifecycleAuthority =
    new AcceptingLifecycleAuthority(),
  clock: SastRuleBundleLifecycleClock = {
    now: () => new Date('2026-08-14T08:00:00.000Z')
  }
): SastRuleBundleLifecycleService {
  return new SastRuleBundleLifecycleService(
    store,
    manifestStore,
    authority,
    clock
  );
}

function lifecycleFixtures(): {
  pairs: BundlePair[];
  manifestStore: InMemoryManifestStore;
  scannerSet: VerifiedScannerSetDescriptor;
} {
  const pairs = [bundlePair('OPENGREP'), bundlePair('TRIVY')];
  const manifestStore = new InMemoryManifestStore(
    pairs.flatMap((pair) => [pair.candidate, pair.baseline])
  );
  return {
    pairs,
    manifestStore,
    scannerSet: scannerSetForPairs(pairs)
  };
}

function bundlePair(
  scanner: 'OPENGREP' | 'TRIVY',
  baselineProfileIds: readonly ('JAVA_FAST_V1' | 'JAVA_DEEP_V1')[] = [
    'JAVA_FAST_V1'
  ]
): BundlePair {
  const slug = scanner.toLowerCase();
  const baselineBundleDigest = digest(`${slug}-baseline-bundle`);
  const baselineManifest = manifest(
    scanner,
    '1.0.0',
    baselineBundleDigest,
    digest(`${slug}-older-bundle`),
    baselineProfileIds
  );
  const candidateManifest = manifest(
    scanner,
    '2.0.0',
    digest(`${slug}-candidate-bundle`),
    baselineBundleDigest
  );
  return {
    candidate: verified(candidateManifest),
    baseline: verified(baselineManifest)
  };
}

function manifest(
  scanner: 'OPENGREP' | 'TRIVY',
  bundleVersion: string,
  bundleDigest: `sha256:${string}`,
  rollbackTargetDigest: `sha256:${string}`,
  profileIds: readonly ('JAVA_FAST_V1' | 'JAVA_DEEP_V1')[] = [
    'JAVA_FAST_V1'
  ]
): SastRuleBundleManifest {
  const slug = scanner.toLowerCase();
  const value = buildSastRuleBundleManifest(
    {
      bundleId: `sast-rule-bundle://${slug}/default`,
      bundleVersion,
      lifecycleState: 'ACTIVE',
      scanner,
      builtAt: '2026-08-14T06:00:00.000Z',
      sourceRevision:
        scanner === 'OPENGREP' ? 'a'.repeat(40) : 'b'.repeat(40),
      bundleDigest,
      members: [
        {
          memberId: `rules/${slug}/${bundleVersion}.yml`,
          digest: digest(`${slug}-${bundleVersion}-member`)
        }
      ],
      rules: [
        {
          ruleId: `${slug}.fixture`,
          ruleRevision: bundleVersion,
          ruleSemanticId: `aegis.${slug}.fixture`,
          metadataDigest: digest(`${slug}-${bundleVersion}-metadata`)
        }
      ],
      compatibility: {
        scannerVersions: ['1.22.0'],
        scannerImageDigests: [digest(`${slug}-image`)],
        wrapperDigests: [digest(`${slug}-wrapper`)],
        schemaBundleDigests: [digest('schema')],
        normalizerBundleDigests: [digest('normalizer')],
        profileIds: [...profileIds]
      },
      qualityEvidence: {
        goldenCorpusResultRef: reference(`${slug}-golden`),
        regressionCorpusResultRef: reference(`${slug}-regression`),
        maliciousCorpusResultRef: reference(`${slug}-malicious`),
        performanceCorpusResultRef: reference(`${slug}-performance`)
      },
      signerIdentity: 'spiffe://aegis/security/rule-signer',
      signatureRef: reference(`${slug}-${bundleVersion}-signature`),
      provenanceRef: reference(`${slug}-${bundleVersion}-provenance`),
      compatibilityRef: reference(`${slug}-compatibility`),
      rolloutPolicyRef: reference(`${slug}-rollout`),
      killSwitchNamespace: `sast-kill-switch://rule-bundles/${slug}`,
      killSwitchRef: reference(`${slug}-kill-switch`),
      rollbackTargetDigest
    },
    digest
  );
  if (!value) throw new Error('manifest fixture invalid');
  return value;
}

function verified(
  manifestValue: SastRuleBundleManifest
): PersistedVerifiedSastRuleBundle {
  const attestation = buildSastRuleBundleSupplyChainAttestation({
    manifest: manifestValue,
    verifiedAt: '2026-08-14T06:05:00.000Z',
    digestCanonical: digest
  });
  if (!attestation) throw new Error('attestation fixture invalid');
  return {
    manifest: manifestValue,
    attestation,
    replayed: false
  };
}

function scannerSetForPairs(
  pairs: readonly BundlePair[]
): VerifiedScannerSetDescriptor {
  const base = durableSastScanPlan().scannerSet;
  const ruleBundles = pairs.map(({ candidate }) => ({
    bundleId: candidate.manifest.bundleId,
    version: candidate.manifest.bundleVersion,
    state: candidate.manifest.lifecycleState,
    digest: candidate.manifest.bundleDigest,
    manifestId: candidate.manifest.manifestId,
    manifestDigest: candidate.manifest.manifestDigest,
    verificationId: candidate.attestation.verificationId,
    verificationDigest: candidate.attestation.attestationDigest,
    signatureRef: candidate.manifest.signatureRef,
    provenanceRef: candidate.manifest.provenanceRef,
    compatibilityRef: candidate.manifest.compatibilityRef,
    rolloutPolicyRef: candidate.manifest.rolloutPolicyRef,
    killSwitchRef: candidate.manifest.killSwitchRef,
    rollbackTargetDigest: candidate.manifest.rollbackTargetDigest,
    compatibilityReceiptId:
      `sast-rule-bundle-compatibility://${candidate.manifest.manifestDigest.slice('sha256:'.length)}`,
    compatibilityReceiptDigest: digest(
      `${candidate.manifest.bundleId}-compatibility-receipt`
    ),
    scanner: candidate.manifest.scanner,
    source: candidate.manifest.source,
    immutable: candidate.manifest.immutable,
    customerExecutableConfigAllowed:
      candidate.manifest.customerExecutableConfigAllowed,
    rules: candidate.manifest.rules.map((rule) => ({ ...rule }))
  }));
  return {
    ...structuredClone(base),
    ruleBundles
  };
}

function evidenceInput(pair: BundlePair) {
  const candidate = pair.candidate;
  const baseline = pair.baseline;
  return {
    manifestId: candidate.manifest.manifestId,
    manifestDigest: candidate.manifest.manifestDigest,
    verificationId: candidate.attestation.verificationId,
    verificationDigest: candidate.attestation.attestationDigest,
    bundleId: candidate.manifest.bundleId,
    bundleDigest: candidate.manifest.bundleDigest,
    profileId: 'JAVA_FAST_V1' as const,
    candidateAuthorRef: `sast-actor://rule-authors/${candidate.manifest.scanner.toLowerCase()}`,
    baselineManifestId: baseline.manifest.manifestId,
    baselineManifestDigest: baseline.manifest.manifestDigest,
    baselineBundleDigest: baseline.manifest.bundleDigest,
    rollbackTargetDigest: candidate.manifest.rollbackTargetDigest,
    environmentRef: reference('qualification-environment'),
    corpusReferences: {
      goldenCorpusRef: reference('golden'),
      priorMustDetectCorpusRef: reference('prior-must-detect'),
      maliciousCorpusRef: reference('malicious'),
      parserCorpusRef: reference('parser'),
      fingerprintCorpusRef: reference('fingerprint'),
      coverageCorpusRef: reference('coverage'),
      performanceCorpusRef: reference('performance')
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
    measuredAt: '2026-08-14T07:00:00.000Z'
  };
}

function approvalInput(
  evidence: SastRuleBundlePromotionEvidence,
  role: 'SECURITY_ENGINEERING' | 'SCAN_PLATFORM',
  slug: string
) {
  return {
    evidenceId: evidence.evidenceId,
    evidenceDigest: evidence.evidenceDigest,
    manifestId: evidence.manifestId,
    manifestDigest: evidence.manifestDigest,
    bundleDigest: evidence.bundleDigest,
    candidateAuthorRef: evidence.candidateAuthorRef,
    role,
    approverRef: `sast-approver://rule-governance/${slug}`,
    approvalRef: reference(`approval-${slug}`),
    approvedAt:
      role === 'SECURITY_ENGINEERING'
        ? '2026-08-14T07:05:00.000Z'
        : '2026-08-14T07:06:00.000Z'
  };
}

function transitionRequest(
  pair: BundlePair,
  evidence: SastRuleBundlePromotionEvidence,
  approvals: SastRuleBundlePromotionApproval[],
  toState: SastRuleBundleLifecycleTransition['toState'],
  minute: string
) {
  return {
    manifestId: pair.candidate.manifest.manifestId,
    promotionEvidenceId: evidence.evidenceId,
    approvalIds: approvals.map((approval) => approval.approvalId),
    toState,
    actorRef: 'sast-actor://rule-governance/controller',
    reasonRef: reference(`transition-${toState.toLowerCase()}-reason`),
    auditRef: reference(`transition-${toState.toLowerCase()}-audit`),
    transitionedAt: `2026-08-14T${minute}:00.000Z`
  };
}

async function promoteToCanary(
  service: SastRuleBundleLifecycleService,
  pair: BundlePair
): Promise<{
  evidence: SastRuleBundlePromotionEvidence;
  security: SastRuleBundlePromotionApproval;
  platform: SastRuleBundlePromotionApproval;
}> {
  const evidence = (
    await service.registerPromotionEvidence(evidenceInput(pair))
  ).evidence;
  const security = (
    await service.registerPromotionApproval(
      approvalInput(evidence, 'SECURITY_ENGINEERING', 'security')
    )
  ).approval;
  const platform = (
    await service.registerPromotionApproval(
      approvalInput(evidence, 'SCAN_PLATFORM', 'platform')
    )
  ).approval;
  await service.transition(
    transitionRequest(pair, evidence, [security], 'VALIDATED', '07:10')
  );
  await service.transition(
    transitionRequest(pair, evidence, [security], 'CANARY', '07:11')
  );
  return { evidence, security, platform };
}

async function promoteToActive(
  service: SastRuleBundleLifecycleService,
  pair: BundlePair
) {
  const prepared = await promoteToCanary(service, pair);
  await service.transition(
    transitionRequest(
      pair,
      prepared.evidence,
      [prepared.security, prepared.platform],
      'ACTIVE',
      '07:12'
    )
  );
  return prepared;
}

function reference(seed: string): string {
  return `sast-reference://rule-governance/${seed}/${digest(seed)}`;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function replayError(): SastRuleBundleLifecyclePersistenceError {
  return new SastRuleBundleLifecyclePersistenceError('REPLAY_CONFLICT');
}
