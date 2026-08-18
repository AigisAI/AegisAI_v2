import { createHash } from 'node:crypto';

import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_RULE_BUNDLE_CANARY_REPOSITORY_SIZE_BUCKETS,
  SAST_RULE_BUNDLE_CANARY_STEPS,
  SAST_SCAN_PROFILES,
  buildSastRuleBundleCanaryEligibilityDecision,
  buildSastRuleBundleCanaryRollout,
  buildSastRuleBundleCanaryScanObservation,
  type PromotionVerifiedRuleBundleDescriptor,
  type PromotionVerifiedScannerSetDescriptor,
  type SastRuleBundleCanaryEligibilityClass,
  type SastRuleBundleCanaryEligibilityDecision,
  type SastRuleBundleCanaryEligibilityDecisionInput,
  type SastRuleBundleCanaryObservationReceipt,
  type SastRuleBundleCanaryRepositorySizeBucket,
  type SastRuleBundleCanaryRollout,
  type SastRuleBundleCanaryRolloutInput,
  type SastRuleBundleCanaryScanObservation,
  type SastRuleBundleCanaryScanObservationInput,
  type SastRuleBundleCanaryScanObservationMeasurements,
  type SastRuleBundleCanaryStep,
  type SastRuleBundleCanaryStepDecision,
  type VerifiedSastRuleBundleCanaryAssignmentDescriptor
} from '@aegisai/shared';

import { digestSastRuleBundleCanonical } from '../../src/rule-governance/sast-rule-bundle-canonical';
import { SastRuleBundleCanaryClock } from '../../src/rule-governance/sast-rule-bundle-canary.clock';
import {
  SastRuleBundleCanaryGateError
} from '../../src/rule-governance/sast-rule-bundle-canary.gate';
import {
  EnvironmentSastRuleBundleCanaryCohortKeyProvider,
  SastRuleBundleCanaryCohortKeyError,
  SastRuleBundleCanaryCohortKeyProvider,
  type SastRuleBundleCanaryCohortKey
} from '../../src/rule-governance/sast-rule-bundle-canary-key.provider';
import {
  SastRuleBundleCanaryObservationSource,
  SastRuleBundleCanaryObservationSourceError,
  type SastRuleBundleCanaryObservationSourceRequest
} from '../../src/rule-governance/sast-rule-bundle-canary-observation.source';
import {
  SastRuleBundleCanaryService,
  SastRuleBundleCanaryServiceError
} from '../../src/rule-governance/sast-rule-bundle-canary.service';
import {
  SastRuleBundleCanaryPersistenceError,
  SastRuleBundleCanaryStore,
  type PendingSastRuleBundleCanaryAssignment,
  type PersistedSastRuleBundleCanaryAssignment,
  type PersistedSastRuleBundleCanaryEligibilityDecision,
  type PersistedSastRuleBundleCanaryObservation,
  type PersistedSastRuleBundleCanaryRollout,
  type PersistedSastRuleBundleCanaryStepDecision,
  type SastRuleBundleCanaryRolloutSnapshot
} from '../../src/rule-governance/sast-rule-bundle-canary.store';
import {
  SastRuleBundleLifecycleStore,
  type PersistedSastRuleBundleLifecycleSelection,
  type PersistedSastRuleBundleLifecycleTransition,
  type PersistedSastRuleBundlePromotionApproval,
  type PersistedSastRuleBundlePromotionEvidence,
  type SastRuleBundleLifecycleLedgerSnapshot
} from '../../src/rule-governance/sast-rule-bundle-lifecycle.store';
import {
  SastRuleBundleManifestStore,
  type PersistedVerifiedSastRuleBundle
} from '../../src/rule-governance/sast-rule-bundle-manifest.store';
import {
  durableSastScanPlan,
  verifiedRuleBundleLifecycle
} from '../support/sast-scan-plan-fixtures';

const CREATED_AT = '2026-08-19T00:00:00.000Z';
const PROFILE = SAST_SCAN_PROFILES.JAVA_FAST_V1;
const PROFILE_DIGEST = SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1;

describe('SastRuleBundleCanaryService T048 gate', () => {
  it('accepts only canonical environment keys whose digest-bound reference matches the key', async () => {
    const names = [
      'SAST_CANARY_COHORT_HMAC_KEY_BASE64',
      'SAST_CANARY_COHORT_HMAC_KEY_REF',
      'SAST_CANARY_COHORT_HMAC_KEY_VERSION'
    ] as const;
    const previous = new Map(names.map((name) => [name, process.env[name]]));
    const provider = new EnvironmentSastRuleBundleCanaryCohortKeyProvider();
    try {
      for (const name of names) delete process.env[name];
      await expect(provider.load()).rejects.toMatchObject({
        reason: 'UNAVAILABLE'
      });

      const keyMaterial = Buffer.alloc(32, 0x5a);
      process.env.SAST_CANARY_COHORT_HMAC_KEY_BASE64 =
        keyMaterial.toString('base64');
      process.env.SAST_CANARY_COHORT_HMAC_KEY_VERSION = 'cohort-key-v1';
      process.env.SAST_CANARY_COHORT_HMAC_KEY_REF =
        `sast-canary-key://cohort/${digest('wrong-key')}`;
      await expect(provider.load()).rejects.toMatchObject({ reason: 'INVALID' });

      const keyDigest = `sha256:${createHash('sha256')
        .update(keyMaterial)
        .digest('hex')}`;
      process.env.SAST_CANARY_COHORT_HMAC_KEY_REF =
        `sast-canary-key://cohort/${keyDigest}`;
      const loaded = await provider.load();
      expect(loaded).toMatchObject({
        keyRef: process.env.SAST_CANARY_COHORT_HMAC_KEY_REF,
        keyVersion: 'cohort-key-v1'
      });
      expect(loaded.keyMaterial.equals(keyMaterial)).toBe(true);
      loaded.keyMaterial.fill(0);
    } finally {
      for (const name of names) {
        const value = previous.get(name);
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  it('bypasses canary dependencies for ACTIVE bundles and keeps membership stable across assignment times', async () => {
    const activeSet = scannerSetWithCanaries([]);
    const canarySet = scannerSetWithCanaries(['OPENGREP']);
    const rolloutInput = rolloutInputFor(canarySet.ruleBundles[0]);
    const rollout = requiredRollout(rolloutInput);
    const store = new InMemoryCanaryStore();
    const keyProvider = new FixtureKeyProvider(rollout);
    const clock = new MutableCanaryClock('2026-08-20T00:00:00.000Z');
    const service = canaryService(store, [rollout], keyProvider, clock);

    const active = await service.verifyScannerSet(gateInput(activeSet, CREATED_AT));
    expect(active.ruleBundles.every((bundle) => bundle.canaryAssignment === null)).toBe(true);
    expect(keyProvider.loadCount).toBe(0);
    expect(store.rolloutCandidateLookups).toBe(0);

    await service.registerRollout(rolloutInput);
    await service.registerEligibilityDecision(
      eligibilityInput(rollout, 'INTERNAL_CORPUS', false, CREATED_AT)
    );
    const first = await service.verifyScannerSet(
      gateInput(canarySet, '2026-08-19T01:00:00.000Z')
    );
    const second = await service.verifyScannerSet(
      gateInput(canarySet, '2026-08-19T02:00:00.000Z')
    );
    const firstAssignment = requiredAssignment(first, 'OPENGREP');
    const secondAssignment = requiredAssignment(second, 'OPENGREP');

    expect(firstAssignment).toMatchObject({
      rolloutId: rollout.rolloutId,
      step: 'INTERNAL_CORPUS',
      candidateAssigned: true
    });
    expect(secondAssignment.membershipId).toBe(firstAssignment.membershipId);
    expect(secondAssignment.membershipDigest).toBe(firstAssignment.membershipDigest);
    expect(secondAssignment.assignmentReceiptId).not.toBe(
      firstAssignment.assignmentReceiptId
    );
    expect(store.assignmentBatchSizes).toEqual([1, 1]);
    expect(keyProvider.returnedBuffers).toHaveLength(3);
    expect(
      keyProvider.returnedBuffers.every((buffer) =>
        buffer.every((value) => value === 0)
      )
    ).toBe(true);
  });

  it('persists all candidate assignments as one scanner-set batch and fails without partial writes', async () => {
    const scannerSet = scannerSetWithCanaries(['OPENGREP', 'TRIVY']);
    const rollouts = scannerSet.ruleBundles.map((bundle) =>
      requiredRollout(rolloutInputFor(bundle))
    );
    const store = new InMemoryCanaryStore();
    const keyProvider = new FixtureKeyProvider(rollouts[0]);
    const service = canaryService(
      store,
      rollouts,
      keyProvider,
      new MutableCanaryClock('2026-08-20T00:00:00.000Z')
    );
    for (const rollout of rollouts) {
      await store.registerRollout(rollout);
      await store.registerEligibilityDecision(
        requiredEligibility(
          eligibilityInput(rollout, 'INTERNAL_CORPUS', false, CREATED_AT)
        )
      );
    }

    const qualified = await service.verifyScannerSet(
      gateInput(scannerSet, '2026-08-19T01:00:00.000Z')
    );
    expect(qualified.ruleBundles.every((bundle) => bundle.canaryAssignment)).toBe(
      true
    );
    expect(store.assignmentBatchSizes).toEqual([2]);
    expect(store.assignments).toHaveLength(2);

    store.failAssignmentBatch = true;
    await expect(
      service.verifyScannerSet(
        gateInput(scannerSet, '2026-08-19T02:00:00.000Z')
      )
    ).rejects.toMatchObject<Partial<SastRuleBundleCanaryGateError>>({
      reason: 'CANARY_STORE_UNAVAILABLE'
    });
    expect(store.assignments).toHaveLength(2);
  });

  it('maps missing rollout, eligibility, excluded cohort, key, and store failures to bounded planning reasons', async () => {
    const scannerSet = scannerSetWithCanaries(['OPENGREP']);
    const rollout = requiredRollout(rolloutInputFor(scannerSet.ruleBundles[0]));
    const clock = new MutableCanaryClock('2026-08-20T00:00:00.000Z');

    await expect(
      canaryService(
        new InMemoryCanaryStore(),
        [rollout],
        new FixtureKeyProvider(rollout),
        clock
      ).verifyScannerSet(gateInput(scannerSet, '2026-08-19T01:00:00.000Z'))
    ).rejects.toMatchObject({ reason: 'CANARY_ROLLOUT_UNAVAILABLE' });

    const missingEligibilityStore = new InMemoryCanaryStore();
    await missingEligibilityStore.registerRollout(rollout);
    await expect(
      canaryService(
        missingEligibilityStore,
        [rollout],
        new FixtureKeyProvider(rollout),
        clock
      ).verifyScannerSet(gateInput(scannerSet, '2026-08-19T01:00:00.000Z'))
    ).rejects.toMatchObject({ reason: 'CANARY_ELIGIBILITY_UNAVAILABLE' });

    for (const input of [
      eligibilityInput(rollout, 'INTERNAL_CORPUS', true, CREATED_AT),
      eligibilityInput(rollout, 'ELIGIBLE_PRODUCTION', false, CREATED_AT)
    ]) {
      const store = new InMemoryCanaryStore();
      await store.registerRollout(rollout);
      await store.registerEligibilityDecision(requiredEligibility(input));
      await expect(
        canaryService(
          store,
          [rollout],
          new FixtureKeyProvider(rollout),
          clock
        ).verifyScannerSet(gateInput(scannerSet, '2026-08-19T01:00:00.000Z'))
      ).rejects.toMatchObject({ reason: 'CANARY_ASSIGNMENT_INELIGIBLE' });
      expect(store.assignments).toHaveLength(0);
    }

    const futureEligibilityStore = new InMemoryCanaryStore();
    await futureEligibilityStore.registerRollout(rollout);
    await futureEligibilityStore.registerEligibilityDecision(
      requiredEligibility(
        eligibilityInput(
          rollout,
          'INTERNAL_CORPUS',
          false,
          '2026-08-19T02:00:00.000Z'
        )
      )
    );
    await expect(
      canaryService(
        futureEligibilityStore,
        [rollout],
        new FixtureKeyProvider(rollout),
        clock
      ).verifyScannerSet(gateInput(scannerSet, '2026-08-19T01:00:00.000Z'))
    ).rejects.toMatchObject({ reason: 'CANARY_ASSIGNMENT_STALE' });

    const readyStore = new InMemoryCanaryStore();
    await readyStore.registerRollout(rollout);
    await readyStore.registerEligibilityDecision(
      requiredEligibility(
        eligibilityInput(rollout, 'INTERNAL_CORPUS', false, CREATED_AT)
      )
    );
    const unavailableKey = new (class extends SastRuleBundleCanaryCohortKeyProvider {
      async load(): Promise<never> {
        throw new SastRuleBundleCanaryCohortKeyError('UNAVAILABLE');
      }
    })();
    await expect(
      canaryService(readyStore, [rollout], unavailableKey, clock).verifyScannerSet(
        gateInput(scannerSet, '2026-08-19T01:00:00.000Z')
      )
    ).rejects.toMatchObject({ reason: 'CANARY_KEY_UNAVAILABLE' });

    const shortKeyMaterial = Buffer.alloc(31, 0x5a);
    const invalidKey = new (class extends SastRuleBundleCanaryCohortKeyProvider {
      async load(): Promise<SastRuleBundleCanaryCohortKey> {
        return {
          keyRef: rollout.cohortKeyRef,
          keyVersion: rollout.cohortKeyVersion,
          keyMaterial: shortKeyMaterial
        };
      }
    })();
    await expect(
      canaryService(readyStore, [rollout], invalidKey, clock).verifyScannerSet(
        gateInput(scannerSet, '2026-08-19T01:00:00.000Z')
      )
    ).rejects.toMatchObject({ reason: 'CANARY_KEY_UNAVAILABLE' });
    expect(shortKeyMaterial.every((value) => value === 0)).toBe(true);

    const driftedKeyMaterial = Buffer.alloc(32, 0x6b);
    const driftedKey = new (class extends SastRuleBundleCanaryCohortKeyProvider {
      async load(): Promise<SastRuleBundleCanaryCohortKey> {
        return {
          keyRef: rollout.cohortKeyRef,
          keyVersion: rollout.cohortKeyVersion,
          keyMaterial: driftedKeyMaterial
        };
      }
    })();
    await expect(
      canaryService(readyStore, [rollout], driftedKey, clock).verifyScannerSet(
        gateInput(scannerSet, '2026-08-19T01:00:00.000Z')
      )
    ).rejects.toMatchObject({ reason: 'CANARY_KEY_UNAVAILABLE' });
    expect(driftedKeyMaterial.every((value) => value === 0)).toBe(true);

    readyStore.failRolloutLookup = true;
    await expect(
      canaryService(
        readyStore,
        [rollout],
        new FixtureKeyProvider(rollout),
        clock
      ).verifyScannerSet(gateInput(scannerSet, '2026-08-19T01:00:00.000Z'))
    ).rejects.toMatchObject({ reason: 'CANARY_STORE_UNAVAILABLE' });
  });

  it('accepts content-free incomplete telemetry but rejects unavailable or scope-drifted sources', async () => {
    const scannerSet = scannerSetWithCanaries(['OPENGREP']);
    const rollout = requiredRollout(rolloutInputFor(scannerSet.ruleBundles[0]));
    const store = new InMemoryCanaryStore();
    const clock = new MutableCanaryClock('2026-08-20T00:00:00.000Z');
    await store.registerRollout(rollout);
    await store.registerEligibilityDecision(
      requiredEligibility(
        eligibilityInput(rollout, 'INTERNAL_CORPUS', false, CREATED_AT)
      )
    );
    const gateService = canaryService(
      store,
      [rollout],
      new FixtureKeyProvider(rollout),
      clock
    );
    const qualified = await gateService.verifyScannerSet(
      gateInput(scannerSet, '2026-08-19T01:00:00.000Z')
    );
    const assignment = requiredAssignment(qualified, 'OPENGREP');
    const request = observationRequest(rollout, 'candidate-source');
    const sourceInput = observationInput({
      rollout,
      assignment,
      request,
      step: 'INTERNAL_CORPUS',
      cohortRole: 'CANDIDATE',
      repositorySizeBucket: 'MEDIUM',
      completedAt: '2026-08-19T02:00:00.000Z',
      telemetryComplete: false
    });
    const acceptingSource = new FixtureObservationSource(async () => sourceInput);
    const service = canaryService(
      store,
      [rollout],
      new FixtureKeyProvider(rollout),
      clock,
      acceptingSource
    );

    const persisted = await service.recordScanObservation(request);
    expect(persisted.observation.telemetryComplete).toBe(false);
    expect(persisted.observation.sourceOrFindingContentStored).toBe(false);
    for (const callerControlledClassification of [
      { cohortRole: 'BASELINE' },
      { repositorySizeBucket: 'LARGE' }
    ]) {
      await expect(
        service.recordScanObservation({
          ...request,
          ...callerControlledClassification
        } as never)
      ).rejects.toMatchObject({ reason: 'INPUT_INVALID' });
    }

    const drifted = canaryService(
      store,
      [rollout],
      new FixtureKeyProvider(rollout),
      clock,
      new FixtureObservationSource(async () => ({
        ...sourceInput,
        tenantId: 'tenant-cross-scope'
      }))
    );
    await expect(drifted.recordScanObservation(request)).rejects.toMatchObject({
      reason: 'OBSERVATION_INVALID'
    });

    const driftedSourceDigest = digest('drifted-observation-source');
    const driftedSource = canaryService(
      store,
      [rollout],
      new FixtureKeyProvider(rollout),
      clock,
      new FixtureObservationSource(async () => ({
        ...sourceInput,
        observationSourceRef: `sast-canary-source://drift/${driftedSourceDigest}`,
        observationSourceDigest: driftedSourceDigest
      }))
    );
    await expect(
      driftedSource.recordScanObservation(request)
    ).rejects.toMatchObject({ reason: 'OBSERVATION_INVALID' });

    const unavailable = canaryService(
      store,
      [rollout],
      new FixtureKeyProvider(rollout),
      clock,
      new FixtureObservationSource(async () => {
        throw new SastRuleBundleCanaryObservationSourceError('UNAVAILABLE');
      })
    );
    await expect(unavailable.recordScanObservation(request)).rejects.toMatchObject({
      reason: 'SOURCE_UNAVAILABLE'
    });
    expect(store.observations).toHaveLength(1);
  });

  it('keeps insufficient duration/sample evidence pending without advancing the rollout', async () => {
    const fixture = evaluationFixture();
    seedStepObservations({
      store: fixture.store,
      rollout: fixture.rollout,
      step: 'INTERNAL_CORPUS',
      completedAt: '2026-08-20T00:00:00.000Z',
      countPerArm: 3,
      buckets: SAST_RULE_BUNDLE_CANARY_REPOSITORY_SIZE_BUCKETS,
      telemetryComplete: true
    });

    for (const callerControlledCutoff of [
      { observationIds: [] },
      { windowEndedAt: '2026-08-19T23:59:59.999Z' }
    ]) {
      await expect(
        fixture.service.evaluateStep({
          rolloutId: fixture.rollout.rolloutId,
          evaluatorRef: 'actor://sast-canary/evaluator',
          auditRef: reference('caller-selected-observations'),
          ...callerControlledCutoff
        } as never)
      ).rejects.toMatchObject({ reason: 'INPUT_INVALID' });
    }

    const result = await fixture.service.evaluateStep({
      rolloutId: fixture.rollout.rolloutId,
      evaluatorRef: 'actor://sast-canary/evaluator',
      auditRef: reference('pending-step-audit')
    });

    expect(result.decision.outcome).toBe('PENDING');
    expect(result.decision.reasonCodes).toEqual(
      expect.arrayContaining([
        'CANDIDATE_SAMPLE_INSUFFICIENT',
        'BASELINE_SAMPLE_INSUFFICIENT'
      ])
    );
    expect(result.receipt).toBeNull();
    expect(fixture.store.snapshots.get(fixture.rollout.rolloutId)?.passedDecisions).toHaveLength(0);
  });

  it.each([
    ['missing telemetry', false, true, SAST_RULE_BUNDLE_CANARY_REPOSITORY_SIZE_BUCKETS, 'TELEMETRY_MISSING'],
    ['incomplete coverage', true, false, SAST_RULE_BUNDLE_CANARY_REPOSITORY_SIZE_BUCKETS, 'COVERAGE_INCOMPLETE'],
    ['missing size bucket', true, true, ['SMALL'] as const, 'PROFILE_SIZE_COMPARISON_INCOMPLETE']
  ] as const)(
    'pauses terminally for %s and requires a new rollout',
    async (_label, telemetryComplete, coverageComplete, buckets, expectedReason) => {
      const fixture = evaluationFixture();
      const eligibility = requiredEligibility(
        eligibilityInput(
          fixture.rollout,
          'INTERNAL_CORPUS',
          false,
          CREATED_AT
        )
      );
      await fixture.store.registerEligibilityDecision(eligibility);
      seedStepObservations({
        store: fixture.store,
        rollout: fixture.rollout,
        step: 'INTERNAL_CORPUS',
        completedAt: '2026-08-20T00:00:00.000Z',
        countPerArm: 3,
        buckets,
        telemetryComplete,
        coverageComplete
      });
      const request = {
        rolloutId: fixture.rollout.rolloutId,
        evaluatorRef: 'actor://sast-canary/evaluator',
        auditRef: reference(`paused-${expectedReason}`)
      } as const;

      const result = await fixture.service.evaluateStep(request);
      expect(result.decision.outcome).toBe('PAUSED');
      expect(result.decision.reasonCodes).toContain(expectedReason);
      await expect(fixture.service.evaluateStep(request)).rejects.toMatchObject({
        reason: 'ROLLOUT_PAUSED'
      });
      await expect(
        fixture.service.verifyScannerSet(
          gateInput(fixture.scannerSet, '2026-08-20T00:00:00.000Z')
        )
      ).rejects.toMatchObject({ reason: 'CANARY_ASSIGNMENT_STALE' });
      await expect(
        fixture.service.registerEligibilityDecision(
          eligibilityInput(
            fixture.rollout,
            'INTERNAL_CORPUS',
            false,
            '2026-08-20T00:00:00.000Z'
          )
        )
      ).rejects.toMatchObject({ reason: 'ROLLOUT_PAUSED' });
    }
  );

  it('passes all six ordered steps, issues exact authority, and seals the completed rollout', async () => {
    const scannerSet = scannerSetWithCanaries(['OPENGREP']);
    const rollout = requiredRollout(rolloutInputFor(scannerSet.ruleBundles[0]));
    const store = new InMemoryCanaryStore();
    const clock = new MutableCanaryClock(CREATED_AT);
    const source = new FixtureObservationSource(async () => {
      throw new Error('the completed-rollout guard must run before the source');
    });
    const service = canaryService(
      store,
      [rollout],
      new FixtureKeyProvider(rollout),
      clock,
      source
    );
    await store.registerRollout(rollout);
    await store.registerEligibilityDecision(
      requiredEligibility(
        eligibilityInput(rollout, 'INTERNAL_CORPUS', false, CREATED_AT)
      )
    );

    let finalResult: PersistedSastRuleBundleCanaryStepDecision | null = null;
    for (const step of SAST_RULE_BUNDLE_CANARY_STEPS) {
      const qualified = await service.verifyScannerSet(
        gateInput(scannerSet, clock.toISOString())
      );
      const assignment = requiredAssignment(qualified, 'OPENGREP');
      expect(assignment.step).toBe(step);
      const expanded = step === 'PERCENT_25' || step === 'PERCENT_100';
      clock.advanceHours(expanded ? 48 : 24);
      seedStepObservations({
        store,
        rollout,
        step,
        completedAt: clock.toISOString(),
        countPerArm: expanded ? 1_000 : 200,
        buckets: SAST_RULE_BUNDLE_CANARY_REPOSITORY_SIZE_BUCKETS,
        telemetryComplete: true,
        assignment
      });
      finalResult = await service.evaluateStep({
        rolloutId: rollout.rolloutId,
        evaluatorRef: 'actor://sast-canary/evaluator',
        auditRef: reference(`passed-${step}`)
      });
      expect(finalResult.decision).toMatchObject({ step, outcome: 'PASSED' });
    }

    expect(finalResult?.receipt).toMatchObject({
      everyStepPassed: true,
      thresholdsWaived: false,
      passedSteps: SAST_RULE_BUNDLE_CANARY_STEPS.map((step) =>
        expect.objectContaining({ step })
      )
    });
    const authority = await service.authorizeLifecycleTransition({
      authority: 'CANARY_OBSERVATION',
      manifestId: rollout.candidateManifestId,
      manifestDigest: rollout.candidateManifestDigest,
      bundleId: rollout.candidateBundleId,
      bundleDigest: rollout.candidateBundleDigest,
      fromState: 'CANARY',
      toState: 'ACTIVE',
      promotionEvidenceId: rollout.promotionEvidenceId,
      promotionEvidenceDigest: rollout.promotionEvidenceDigest,
      requestedAt: new Date(clock.valueOf() + 1).toISOString()
    });
    expect(authority).toMatchObject({
      authority: 'CANARY_OBSERVATION',
      receiptRef: finalResult?.receipt?.receiptRef,
      receiptDigest: finalResult?.receipt?.receiptDigest
    });

    await expect(
      service.verifyScannerSet(gateInput(scannerSet, clock.toISOString()))
    ).rejects.toMatchObject({ reason: 'CANARY_ASSIGNMENT_STALE' });
    await expect(
      service.registerEligibilityDecision(
        eligibilityInput(
          rollout,
          'INTERNAL_CORPUS',
          false,
          clock.toISOString()
        )
      )
    ).rejects.toMatchObject({ reason: 'ROLLOUT_COMPLETE' });
    await expect(
      service.recordScanObservation(observationRequest(rollout, 'complete'))
    ).rejects.toMatchObject({ reason: 'ROLLOUT_COMPLETE' });
    await expect(
      service.evaluateStep({
        rolloutId: rollout.rolloutId,
        evaluatorRef: 'actor://sast-canary/evaluator',
        auditRef: reference('complete-evaluation')
      })
    ).rejects.toMatchObject<Partial<SastRuleBundleCanaryServiceError>>({
      reason: 'ROLLOUT_COMPLETE'
    });
    expect(source.loadCount).toBe(0);
  }, 30_000);
});

class InMemoryCanaryStore extends SastRuleBundleCanaryStore {
  readonly snapshots = new Map<string, SastRuleBundleCanaryRolloutSnapshot>();
  readonly eligibility = new Map<string, SastRuleBundleCanaryEligibilityDecision>();
  readonly assignments: PersistedSastRuleBundleCanaryAssignment[] = [];
  readonly observations: SastRuleBundleCanaryScanObservation[] = [];
  readonly assignmentBatchSizes: number[] = [];
  rolloutCandidateLookups = 0;
  failAssignmentBatch = false;
  failRolloutLookup = false;

  async registerRollout(
    rollout: Readonly<SastRuleBundleCanaryRollout>
  ): Promise<PersistedSastRuleBundleCanaryRollout> {
    const existing = this.snapshots.get(rollout.rolloutId);
    if (existing) {
      if (existing.rollout.rolloutDigest !== rollout.rolloutDigest) {
        throw new SastRuleBundleCanaryPersistenceError('REPLAY_CONFLICT');
      }
      return { rollout: structuredClone(existing.rollout), replayed: true };
    }
    this.snapshots.set(rollout.rolloutId, {
      rollout: structuredClone(rollout),
      latestDecision: null,
      passedDecisions: [],
      observationReceipt: null
    });
    return { rollout: structuredClone(rollout), replayed: false };
  }

  async findRolloutForCandidate(
    manifestId: string,
    profileId: string
  ): Promise<SastRuleBundleCanaryRolloutSnapshot | null> {
    this.rolloutCandidateLookups += 1;
    if (this.failRolloutLookup) throw new Error('store unavailable');
    const snapshot = [...this.snapshots.values()].find(
      (item) =>
        item.rollout.candidateManifestId === manifestId &&
        item.rollout.profileId === profileId
    );
    return snapshot ? structuredClone(snapshot) : null;
  }

  async findRollout(
    rolloutId: string
  ): Promise<SastRuleBundleCanaryRolloutSnapshot | null> {
    const snapshot = this.snapshots.get(rolloutId);
    return snapshot ? structuredClone(snapshot) : null;
  }

  async registerEligibilityDecision(
    decision: Readonly<SastRuleBundleCanaryEligibilityDecision>
  ): Promise<PersistedSastRuleBundleCanaryEligibilityDecision> {
    const key = eligibilityKey(decision);
    const existing = this.eligibility.get(key);
    if (existing) {
      if (
        existing.eligibilityDecisionDigest !==
        decision.eligibilityDecisionDigest
      ) {
        throw new SastRuleBundleCanaryPersistenceError('REPLAY_CONFLICT');
      }
      return { decision: structuredClone(existing), replayed: true };
    }
    this.eligibility.set(key, structuredClone(decision));
    return { decision: structuredClone(decision), replayed: false };
  }

  async findEligibilityDecision(input: {
    rolloutId: string;
    tenantId: string;
    repositoryBindingId: string;
    profileId: string;
  }): Promise<SastRuleBundleCanaryEligibilityDecision | null> {
    const decision = this.eligibility.get(eligibilityKey(input));
    return decision ? structuredClone(decision) : null;
  }

  async recordAssignments(
    assignments: readonly Readonly<PendingSastRuleBundleCanaryAssignment>[]
  ): Promise<PersistedSastRuleBundleCanaryAssignment[]> {
    this.assignmentBatchSizes.push(assignments.length);
    if (this.failAssignmentBatch) {
      throw new SastRuleBundleCanaryPersistenceError('LEDGER_CORRUPT');
    }
    const result: PersistedSastRuleBundleCanaryAssignment[] = [];
    for (const pending of assignments) {
      const existing = this.assignments.find(
        (item) =>
          item.assignment.assignmentReceiptId ===
          pending.assignment.assignmentReceiptId
      );
      if (existing) {
        result.push({ ...structuredClone(existing), replayed: true });
        continue;
      }
      const created = {
        membership: structuredClone(pending.membership),
        assignment: structuredClone(pending.assignment),
        replayed: false
      };
      this.assignments.push(created);
      result.push(structuredClone(created));
    }
    return result;
  }

  async registerObservation(
    observation: Readonly<SastRuleBundleCanaryScanObservation>
  ): Promise<PersistedSastRuleBundleCanaryObservation> {
    const existing = this.observations.find(
      (item) => item.observationId === observation.observationId
    );
    if (existing) {
      if (existing.observationDigest !== observation.observationDigest) {
        throw new SastRuleBundleCanaryPersistenceError('REPLAY_CONFLICT');
      }
      return { observation: structuredClone(existing), replayed: true };
    }
    this.observations.push(structuredClone(observation));
    return { observation: structuredClone(observation), replayed: false };
  }

  async findObservations(input: {
    rolloutId: string;
    step: SastRuleBundleCanaryStep;
    windowStartedAt: string;
    windowEndedAt: string;
  }): Promise<SastRuleBundleCanaryScanObservation[]> {
    return this.observations
      .filter(
        (item) =>
          item.rolloutId === input.rolloutId &&
          item.step === input.step &&
          item.completedAt >= input.windowStartedAt &&
          item.completedAt <= input.windowEndedAt
      )
      .sort((left, right) => left.observationId.localeCompare(right.observationId))
      .map((item) => structuredClone(item));
  }

  async appendStepDecision(input: {
    decision: Readonly<SastRuleBundleCanaryStepDecision>;
    finalReceipt: Readonly<SastRuleBundleCanaryObservationReceipt> | null;
  }): Promise<PersistedSastRuleBundleCanaryStepDecision> {
    const snapshot = this.snapshots.get(input.decision.rolloutId);
    if (!snapshot) {
      throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_NOT_FOUND');
    }
    if (snapshot.latestDecision?.outcome === 'PAUSED') {
      throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_PAUSED');
    }
    snapshot.latestDecision = structuredClone(input.decision);
    if (input.decision.outcome === 'PASSED') {
      snapshot.passedDecisions.push(structuredClone(input.decision));
    }
    snapshot.observationReceipt = input.finalReceipt
      ? structuredClone(input.finalReceipt)
      : null;
    return {
      decision: structuredClone(input.decision),
      receipt: input.finalReceipt ? structuredClone(input.finalReceipt) : null,
      replayed: false
    };
  }

  async findObservationReceiptForAuthority(input: {
    manifestId: string;
    manifestDigest: string;
    bundleId: string;
    bundleDigest: string;
    promotionEvidenceId: string;
    promotionEvidenceDigest: string;
  }): Promise<SastRuleBundleCanaryObservationReceipt | null> {
    const receipt = [...this.snapshots.values()]
      .map((snapshot) => snapshot.observationReceipt)
      .find(
        (item) =>
          item?.candidateManifestId === input.manifestId &&
          item.candidateManifestDigest === input.manifestDigest &&
          item.candidateBundleId === input.bundleId &&
          item.candidateBundleDigest === input.bundleDigest &&
          item.promotionEvidenceId === input.promotionEvidenceId &&
          item.promotionEvidenceDigest === input.promotionEvidenceDigest
      );
    return receipt ? structuredClone(receipt) : null;
  }
}

class FixtureKeyProvider extends SastRuleBundleCanaryCohortKeyProvider {
  readonly returnedBuffers: Buffer[] = [];
  loadCount = 0;

  constructor(private readonly rollout: Readonly<SastRuleBundleCanaryRollout>) {
    super();
  }

  async load(): Promise<SastRuleBundleCanaryCohortKey> {
    this.loadCount += 1;
    const keyMaterial = Buffer.alloc(32, 0x5a);
    this.returnedBuffers.push(keyMaterial);
    return {
      keyRef: this.rollout.cohortKeyRef,
      keyVersion: this.rollout.cohortKeyVersion,
      keyMaterial
    };
  }
}

class FixtureObservationSource extends SastRuleBundleCanaryObservationSource {
  loadCount = 0;

  constructor(
    private readonly loader: (
      request: Readonly<SastRuleBundleCanaryObservationSourceRequest>
    ) => Promise<SastRuleBundleCanaryScanObservationInput>
  ) {
    super();
  }

  async load(
    request: Readonly<SastRuleBundleCanaryObservationSourceRequest>
  ): Promise<SastRuleBundleCanaryScanObservationInput> {
    this.loadCount += 1;
    return this.loader(request);
  }
}

class MutableCanaryClock extends SastRuleBundleCanaryClock {
  private milliseconds: number;

  constructor(value: string) {
    super();
    this.milliseconds = Date.parse(value);
  }

  now(): Date {
    return new Date(this.milliseconds);
  }

  advanceHours(hours: number): void {
    this.milliseconds += hours * 60 * 60 * 1_000;
  }

  toISOString(): string {
    return new Date(this.milliseconds).toISOString();
  }

  valueOf(): number {
    return this.milliseconds;
  }
}

class FixtureManifestStore extends SastRuleBundleManifestStore {
  constructor(private readonly rollouts: readonly SastRuleBundleCanaryRollout[]) {
    super();
  }

  async registerVerified(): Promise<never> {
    throw new Error('not used by canary fixture');
  }

  async findVerified(
    manifestId: string
  ): Promise<PersistedVerifiedSastRuleBundle | null> {
    for (const rollout of this.rollouts) {
      if (manifestId === rollout.candidateManifestId) {
        return verifiedManifest({
          manifestId,
          manifestDigest: rollout.candidateManifestDigest,
          bundleId: rollout.candidateBundleId,
          bundleDigest: rollout.candidateBundleDigest,
          rollbackTargetDigest: rollout.baselineBundleDigest
        });
      }
      if (manifestId === rollout.baselineManifestId) {
        return verifiedManifest({
          manifestId,
          manifestDigest: rollout.baselineManifestDigest,
          bundleId: `sast-rule-bundle://baseline/${rollout.candidateBundleId}`,
          bundleDigest: rollout.baselineBundleDigest,
          rollbackTargetDigest: digest('older-baseline')
        });
      }
    }
    return null;
  }

  async recordCompatibilityReceipt(): Promise<never> {
    throw new Error('not used by canary fixture');
  }
}

class FixtureLifecycleStore extends SastRuleBundleLifecycleStore {
  constructor(private readonly rollouts: readonly SastRuleBundleCanaryRollout[]) {
    super();
  }

  async registerPromotionEvidence(): Promise<PersistedSastRuleBundlePromotionEvidence> {
    throw new Error('not used by canary fixture');
  }

  async findPromotionEvidence(): Promise<PersistedSastRuleBundlePromotionEvidence | null> {
    return null;
  }

  async registerPromotionApproval(): Promise<PersistedSastRuleBundlePromotionApproval> {
    throw new Error('not used by canary fixture');
  }

  async findPromotionApprovals(): Promise<[]> {
    return [];
  }

  async appendLifecycleTransition(): Promise<PersistedSastRuleBundleLifecycleTransition> {
    throw new Error('not used by canary fixture');
  }

  async findLatestLifecycleSnapshot(
    manifestId: string
  ): Promise<SastRuleBundleLifecycleLedgerSnapshot | null> {
    const rollout = this.rollouts.find(
      (item) => item.candidateManifestId === manifestId
    );
    const baselineRollout = this.rollouts.find(
      (item) => item.baselineManifestId === manifestId
    );
    if (!rollout && !baselineRollout) return null;
    if (baselineRollout) {
      return {
        transition: {
          transitionId: `baseline-active-transition-${manifestId}`,
          transitionDigest: digest(`baseline-active-transition-${manifestId}`),
          manifestId: baselineRollout.baselineManifestId,
          manifestDigest: baselineRollout.baselineManifestDigest,
          bundleId: baselineRollout.candidateBundleId,
          bundleDigest: baselineRollout.baselineBundleDigest,
          toState: 'ACTIVE',
          transitionedAt: '2026-08-18T23:00:00.000Z'
        } as SastRuleBundleLifecycleLedgerSnapshot['transition'],
        evidence: {} as SastRuleBundleLifecycleLedgerSnapshot['evidence'],
        approvals: []
      };
    }
    if (!rollout) return null;
    return {
      transition: {
        transitionId: rollout.canaryTransitionId,
        transitionDigest: rollout.canaryTransitionDigest,
        manifestId: rollout.candidateManifestId,
        manifestDigest: rollout.candidateManifestDigest,
        bundleId: rollout.candidateBundleId,
        bundleDigest: rollout.candidateBundleDigest,
        toState: 'CANARY',
        transitionedAt: '2026-08-18T23:59:00.000Z'
      } as SastRuleBundleLifecycleLedgerSnapshot['transition'],
      evidence: {
        evidenceId: rollout.promotionEvidenceId,
        evidenceDigest: rollout.promotionEvidenceDigest,
        baselineManifestId: rollout.baselineManifestId,
        baselineManifestDigest: rollout.baselineManifestDigest,
        baselineBundleDigest: rollout.baselineBundleDigest,
        profileId: rollout.profileId
      } as SastRuleBundleLifecycleLedgerSnapshot['evidence'],
      approvals: []
    };
  }

  async recordLifecycleSelections(): Promise<PersistedSastRuleBundleLifecycleSelection[]> {
    throw new Error('not used by canary fixture');
  }
}

function canaryService(
  store: SastRuleBundleCanaryStore,
  rollouts: readonly SastRuleBundleCanaryRollout[],
  keyProvider: SastRuleBundleCanaryCohortKeyProvider,
  clock: SastRuleBundleCanaryClock,
  observationSource: SastRuleBundleCanaryObservationSource =
    new FixtureObservationSource(async () => {
      throw new SastRuleBundleCanaryObservationSourceError('UNAVAILABLE');
    })
): SastRuleBundleCanaryService {
  return new SastRuleBundleCanaryService(
    store,
    new FixtureManifestStore(rollouts),
    new FixtureLifecycleStore(rollouts),
    keyProvider,
    observationSource,
    clock
  );
}

function scannerSetWithCanaries(
  canaryScanners: readonly ('OPENGREP' | 'TRIVY')[]
): PromotionVerifiedScannerSetDescriptor {
  const scannerSet = durableSastScanPlan().scannerSet;
  return {
    ...structuredClone(scannerSet),
    ruleBundles: scannerSet.ruleBundles.map((bundle) => {
      const { canaryAssignment, ...promotionVerified } = structuredClone(bundle);
      void canaryAssignment;
      return {
        ...promotionVerified,
        lifecycle: verifiedRuleBundleLifecycle(
          `canary-${bundle.scanner.toLowerCase()}`,
          canaryScanners.includes(bundle.scanner) ? 'CANARY' : 'ACTIVE'
        )
      };
    })
  };
}

function rolloutInputFor(
  candidate: Readonly<PromotionVerifiedRuleBundleDescriptor>
): SastRuleBundleCanaryRolloutInput {
  const baselineManifestDigest = digest(`${candidate.scanner}-baseline-manifest`);
  const policyDigest = digest('eligibility-policy-v1');
  const sourceDigest = digest('observation-source-v1');
  const keyDigest = `sha256:${createHash('sha256')
    .update(Buffer.alloc(32, 0x5a))
    .digest('hex')}` as const;
  return {
    candidateManifestId: candidate.manifestId,
    candidateManifestDigest: candidate.manifestDigest,
    candidateBundleId: candidate.bundleId,
    candidateBundleDigest: candidate.digest,
    baselineManifestId: `sast-rule-bundle-manifest://${baselineManifestDigest.slice('sha256:'.length)}`,
    baselineManifestDigest,
    baselineBundleDigest: candidate.rollbackTargetDigest,
    profileId: PROFILE.id,
    profileDigest: PROFILE_DIGEST,
    promotionEvidenceId: candidate.lifecycle.promotionEvidenceId,
    promotionEvidenceDigest: candidate.lifecycle.promotionEvidenceDigest,
    canaryTransitionId: candidate.lifecycle.lifecycleTransitionId,
    canaryTransitionDigest: candidate.lifecycle.lifecycleTransitionDigest,
    cohortKeyRef: `sast-canary-key://cohort/${keyDigest}`,
    cohortKeyVersion: 'cohort-key-v1',
    eligibilityPolicyRef: `sast-canary-policy://eligibility/${policyDigest}`,
    eligibilityPolicyDigest: policyDigest,
    observationSourceRef: `sast-canary-source://telemetry/${sourceDigest}`,
    observationSourceDigest: sourceDigest,
    createdAt: CREATED_AT
  };
}

function requiredRollout(
  input: Readonly<SastRuleBundleCanaryRolloutInput>
): SastRuleBundleCanaryRollout {
  const rollout = buildSastRuleBundleCanaryRollout(
    input,
    digestSastRuleBundleCanonical
  );
  if (!rollout) throw new Error('fixture rollout invalid');
  return rollout;
}

function eligibilityInput(
  rollout: Readonly<SastRuleBundleCanaryRollout>,
  eligibilityClass: SastRuleBundleCanaryEligibilityClass,
  excluded: boolean,
  evaluatedAt: string
): SastRuleBundleCanaryEligibilityDecisionInput {
  return {
    rolloutId: rollout.rolloutId,
    rolloutDigest: rollout.rolloutDigest,
    tenantId: 'tenant-canary',
    repositoryBindingId: 'repository-canary',
    profileId: rollout.profileId,
    profileDigest: rollout.profileDigest,
    eligibilityClass,
    excluded,
    exclusionRef: excluded ? reference('contractual-exclusion') : null,
    eligibilityPolicyRef: rollout.eligibilityPolicyRef,
    eligibilityPolicyDigest: rollout.eligibilityPolicyDigest,
    actorRef: 'actor://sast-canary/eligibility-controller',
    auditRef: reference(`eligibility-${eligibilityClass}-${excluded}`),
    evaluatedAt
  };
}

function requiredEligibility(
  input: Readonly<SastRuleBundleCanaryEligibilityDecisionInput>
): SastRuleBundleCanaryEligibilityDecision {
  const decision = buildSastRuleBundleCanaryEligibilityDecision(
    input,
    digestSastRuleBundleCanonical
  );
  if (!decision) throw new Error('fixture eligibility invalid');
  return decision;
}

function gateInput(
  scannerSet: Readonly<PromotionVerifiedScannerSetDescriptor>,
  evaluatedAt: string
) {
  return {
    tenantId: 'tenant-canary',
    repositoryBindingId: 'repository-canary',
    scannerSet,
    profile: PROFILE,
    profileDigest: PROFILE_DIGEST,
    evaluatedAt
  };
}

function requiredAssignment(
  scannerSet: Readonly<{
    ruleBundles: readonly Readonly<{
      scanner: 'OPENGREP' | 'TRIVY';
      canaryAssignment: VerifiedSastRuleBundleCanaryAssignmentDescriptor | null;
    }>[];
  }>,
  scanner: 'OPENGREP' | 'TRIVY'
): VerifiedSastRuleBundleCanaryAssignmentDescriptor {
  const assignment = scannerSet.ruleBundles.find(
    (bundle) => bundle.scanner === scanner
  )?.canaryAssignment;
  if (!assignment) throw new Error('fixture assignment missing');
  return assignment;
}

function evaluationFixture() {
  const scannerSet = scannerSetWithCanaries(['OPENGREP']);
  const rollout = requiredRollout(rolloutInputFor(scannerSet.ruleBundles[0]));
  const store = new InMemoryCanaryStore();
  void store.registerRollout(rollout);
  const clock = new MutableCanaryClock('2026-08-20T00:00:00.000Z');
  return {
    scannerSet,
    rollout,
    store,
    clock,
    service: canaryService(
      store,
      [rollout],
      new FixtureKeyProvider(rollout),
      clock
    )
  };
}

function seedStepObservations(input: {
  store: InMemoryCanaryStore;
  rollout: Readonly<SastRuleBundleCanaryRollout>;
  step: SastRuleBundleCanaryStep;
  completedAt: string;
  countPerArm: number;
  buckets: readonly SastRuleBundleCanaryRepositorySizeBucket[];
  telemetryComplete: boolean;
  coverageComplete?: boolean;
  assignment?: Readonly<VerifiedSastRuleBundleCanaryAssignmentDescriptor>;
}): void {
  const observations: SastRuleBundleCanaryScanObservation[] = [];
  for (const cohortRole of ['CANDIDATE', 'BASELINE'] as const) {
    for (let index = 0; index < input.countPerArm; index += 1) {
      const bucket = input.buckets[index % input.buckets.length];
      if (!bucket) throw new Error('fixture bucket missing');
      const request = observationRequest(
        input.rollout,
        `${input.step}-${cohortRole.toLowerCase()}-${index}`,
        cohortRole
      );
      const observation = buildSastRuleBundleCanaryScanObservation(
        observationInput({
          rollout: input.rollout,
          assignment:
            cohortRole === 'CANDIDATE'
              ? input.assignment ?? syntheticAssignment(input.step, index)
              : null,
          request,
          step: input.step,
          cohortRole,
          repositorySizeBucket: bucket,
          completedAt: input.completedAt,
          coverageComplete:
            (input.coverageComplete ?? true) ||
            index > 0 ||
            cohortRole === 'BASELINE',
          telemetryComplete:
            input.telemetryComplete || index > 0 || cohortRole === 'BASELINE'
        }),
        digestSastRuleBundleCanonical
      );
      if (!observation) throw new Error('fixture observation invalid');
      observations.push(observation);
    }
  }
  input.store.observations.push(...observations);
}

function observationRequest(
  rollout: Readonly<SastRuleBundleCanaryRollout>,
  slug: string,
  cohortRole: 'CANDIDATE' | 'BASELINE' = 'CANDIDATE'
): SastRuleBundleCanaryObservationSourceRequest {
  return {
    rolloutId: rollout.rolloutId,
    tenantId:
      cohortRole === 'CANDIDATE' ? 'tenant-canary' : 'tenant-baseline',
    repositoryBindingId:
      cohortRole === 'CANDIDATE'
        ? 'repository-canary'
        : 'repository-baseline',
    scanRequestId: `scan-${slug}`,
    attemptId: `attempt-${slug}`
  };
}

function observationInput(input: {
  rollout: Readonly<SastRuleBundleCanaryRollout>;
  assignment:
    | Readonly<VerifiedSastRuleBundleCanaryAssignmentDescriptor>
    | null;
  request: Readonly<SastRuleBundleCanaryObservationSourceRequest>;
  step: SastRuleBundleCanaryStep;
  cohortRole: 'CANDIDATE' | 'BASELINE';
  repositorySizeBucket: SastRuleBundleCanaryRepositorySizeBucket;
  completedAt: string;
  coverageComplete?: boolean;
  telemetryComplete: boolean;
}): SastRuleBundleCanaryScanObservationInput {
  const candidate = input.cohortRole === 'CANDIDATE';
  const coverageDigest = digest(`coverage-${input.request.scanRequestId}`);
  const publicationDigest = digest(`publication-${input.request.scanRequestId}`);
  const telemetryDigest = digest(`telemetry-${input.request.scanRequestId}`);
  const measurements = passingMeasurements();
  if (input.coverageComplete === false) {
    measurements.incompleteCoverageCount = 1;
  }
  return {
    rolloutId: input.rollout.rolloutId,
    rolloutDigest: input.rollout.rolloutDigest,
    step: input.step,
    cohortRole: input.cohortRole,
    tenantId: input.request.tenantId,
    repositoryBindingId: input.request.repositoryBindingId,
    scanRequestId: input.request.scanRequestId,
    attemptId: input.request.attemptId,
    assignmentReceiptId: candidate
      ? input.assignment?.assignmentReceiptId ?? null
      : null,
    assignmentReceiptDigest: candidate
      ? input.assignment?.assignmentReceiptDigest ?? null
      : null,
    selectedManifestId: candidate
      ? input.rollout.candidateManifestId
      : input.rollout.baselineManifestId,
    selectedManifestDigest: candidate
      ? input.rollout.candidateManifestDigest
      : input.rollout.baselineManifestDigest,
    selectedBundleDigest: candidate
      ? input.rollout.candidateBundleDigest
      : input.rollout.baselineBundleDigest,
    profileId: input.rollout.profileId,
    profileDigest: input.rollout.profileDigest,
    lane: 'FAST',
    repositorySizeBucket: input.repositorySizeBucket,
    coverageDecisionId: `coverage-decision-${input.request.scanRequestId}`,
    coverageDecisionDigest: coverageDigest,
    publicationDecisionId: `publication-decision-${input.request.scanRequestId}`,
    publicationDecisionDigest: publicationDigest,
    observationSourceRef: input.rollout.observationSourceRef,
    observationSourceDigest: input.rollout.observationSourceDigest,
    telemetrySourceRef: `sast-canary-telemetry://source/${telemetryDigest}`,
    telemetrySourceDigest: telemetryDigest,
    startedAt: new Date(Date.parse(input.completedAt) - 60_000).toISOString(),
    completedAt: input.completedAt,
    coverageComplete: input.coverageComplete ?? true,
    telemetryComplete: input.telemetryComplete,
    measurements
  };
}

function passingMeasurements(): SastRuleBundleCanaryScanObservationMeasurements {
  return {
    findingCount: 1,
    criticalHighFindingCount: 1,
    falsePositiveCount: 0,
    feedbackEligibleFindingCount: 1,
    waiverCount: 0,
    suppressionCount: 0,
    scannerFailureCount: 0,
    scannerTimeoutCount: 0,
    eligibleScannerAttemptCount: 1,
    artifactRejectionCount: 0,
    latencyMilliseconds: 1_000,
    cpuMilliseconds: 1_000,
    peakMemoryBytes: 1_000_000,
    diskBytes: 1_000_000,
    incompleteCoverageCount: 0,
    publicationDenialCount: 0,
    egressDenialCount: 0,
    cleanupLagMilliseconds: 100,
    quarantineCount: 0,
    killSwitchSignalCount: 0,
    crossTenantEvents: 0,
    secretLeakEvents: 0,
    sandboxEscapeEvents: 0,
    stalePublicationEvents: 0,
    unauthorizedEgressEvents: 0,
    missingDestructionEvidenceEvents: 0,
    evidencePolicyViolationEvents: 0,
    unsignedArtifactExecutionEvents: 0
  };
}

function syntheticAssignment(
  step: SastRuleBundleCanaryStep,
  index: number
): VerifiedSastRuleBundleCanaryAssignmentDescriptor {
  const membershipDigest = digest(`membership-${step}-${index}`);
  const assignmentDigest = digest(`assignment-${step}-${index}`);
  return {
    rolloutId: 'synthetic-rollout',
    rolloutDigest: digest('synthetic-rollout'),
    membershipId: `sast-rule-bundle-canary-membership://${membershipDigest.slice('sha256:'.length)}`,
    membershipDigest,
    bucketBasisPoints: 0,
    step,
    stepHeadDecisionId: null,
    stepHeadDecisionDigest: null,
    assignmentReceiptId: `sast-rule-bundle-canary-assignment://${assignmentDigest.slice('sha256:'.length)}`,
    assignmentReceiptDigest: assignmentDigest,
    candidateAssigned: true
  };
}

function eligibilityKey(input: {
  rolloutId: string;
  tenantId: string;
  repositoryBindingId: string;
  profileId: string;
}): string {
  return [
    input.rolloutId,
    input.tenantId,
    input.repositoryBindingId,
    input.profileId
  ].join('\u0000');
}

function verifiedManifest(input: {
  manifestId: string;
  manifestDigest: string;
  bundleId: string;
  bundleDigest: string;
  rollbackTargetDigest: string;
}): PersistedVerifiedSastRuleBundle {
  return {
    manifest: input as PersistedVerifiedSastRuleBundle['manifest'],
    attestation: {} as PersistedVerifiedSastRuleBundle['attestation'],
    replayed: true
  };
}

function reference(seed: string): string {
  return `sast-canary-audit://evidence/${digest(seed)}`;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
