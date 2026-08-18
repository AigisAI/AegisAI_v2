import { createHash, createHmac } from 'node:crypto';

import {
  SAST_RULE_BUNDLE_CANARY_REPOSITORY_SIZE_BUCKETS,
  SAST_RULE_BUNDLE_CANARY_STEPS,
  buildSastCanaryMembershipHmacPreimage,
  buildSastRuleBundleCanaryAssignmentReceipt,
  buildSastRuleBundleCanaryEligibilityDecision,
  buildSastRuleBundleCanaryMembership,
  buildSastRuleBundleCanaryObservationReceipt,
  buildSastRuleBundleCanaryRollout,
  buildSastRuleBundleCanaryScanObservation,
  buildSastRuleBundleCanaryStepDecision,
  isCanaryQualifiedScannerSetDescriptorValid,
  isPromotionVerifiedScannerSetDescriptorValid,
  isSastRuleBundleCanaryAssignmentReceiptShapeValid,
  isSastRuleBundleCanaryEligibilityDecisionShapeValid,
  isSastRuleBundleCanaryMembershipShapeValid,
  isSastRuleBundleCanaryObservationReceiptShapeValid,
  isSastRuleBundleCanaryRolloutShapeValid,
  isSastRuleBundleCanaryScanObservationShapeValid,
  isSastScanProfileValid,
  nextSastRuleBundleCanaryStep,
  toVerifiedSastRuleBundleCanaryAssignmentDescriptor,
  type CanaryQualifiedRuleBundleDescriptor,
  type CanaryQualifiedScannerSetDescriptor,
  type PromotionVerifiedRuleBundleDescriptor,
  type PromotionVerifiedScannerSetDescriptor,
  type SastRuleBundleCanaryAssignmentReceipt,
  type SastRuleBundleCanaryEligibilityDecisionInput,
  type SastRuleBundleCanaryMembership,
  type SastRuleBundleCanaryObservationReceipt,
  type SastRuleBundleCanaryRollout,
  type SastRuleBundleCanaryRolloutInput,
  type SastRuleBundleCanaryScanObservation,
  type SastRuleBundleCanaryStep,
  type SastRuleBundleCanaryStepAggregateMeasurements,
  type SastRuleBundleCanaryStepDecision
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import { digestSastRuleBundleCanonical } from './sast-rule-bundle-canonical';
import { SastRuleBundleCanaryClock } from './sast-rule-bundle-canary.clock';
import {
  SastRuleBundleCanaryGate,
  SastRuleBundleCanaryGateError,
  type SastRuleBundleCanaryGateInput
} from './sast-rule-bundle-canary.gate';
import {
  SastRuleBundleCanaryCohortKeyError,
  SastRuleBundleCanaryCohortKeyProvider
} from './sast-rule-bundle-canary-key.provider';
import {
  SastRuleBundleCanaryObservationSource,
  SastRuleBundleCanaryObservationSourceError,
  type SastRuleBundleCanaryObservationSourceRequest
} from './sast-rule-bundle-canary-observation.source';
import {
  SastRuleBundleCanaryPersistenceError,
  SastRuleBundleCanaryStore,
  type PersistedSastRuleBundleCanaryAssignment,
  type PersistedSastRuleBundleCanaryEligibilityDecision,
  type PersistedSastRuleBundleCanaryObservation,
  type PersistedSastRuleBundleCanaryRollout,
  type PersistedSastRuleBundleCanaryStepDecision,
  type SastRuleBundleCanaryRolloutSnapshot
} from './sast-rule-bundle-canary.store';
import type {
  SastRuleBundleLifecycleAuthorityInput,
  SastRuleBundleLifecycleAuthorityReceipt
} from './sast-rule-bundle-lifecycle.authority';
import {
  SastRuleBundleLifecyclePersistenceError,
  SastRuleBundleLifecycleStore,
  type SastRuleBundleLifecycleLedgerSnapshot
} from './sast-rule-bundle-lifecycle.store';
import {
  SastRuleBundleManifestPersistenceError,
  SastRuleBundleManifestStore
} from './sast-rule-bundle-manifest.store';

export interface SastRuleBundleCanaryStepEvaluationRequest {
  rolloutId: string;
  evaluatorRef: string;
  auditRef: string;
}

export class SastRuleBundleCanaryServiceError extends Error {
  constructor(
    readonly reason:
      | 'INPUT_INVALID'
      | 'MANIFEST_UNVERIFIED'
      | 'ROLLOUT_INVALID'
      | 'ELIGIBILITY_INVALID'
      | 'OBSERVATION_INVALID'
      | 'STEP_INVALID'
      | 'ROLLOUT_PAUSED'
      | 'ROLLOUT_COMPLETE'
      | 'KEY_UNAVAILABLE'
      | 'SOURCE_UNAVAILABLE'
      | 'STORE_UNAVAILABLE'
  ) {
    super('The SAST rule-bundle canary operation failed closed.');
    this.name = 'SastRuleBundleCanaryServiceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

@Injectable()
export class SastRuleBundleCanaryService extends SastRuleBundleCanaryGate {
  constructor(
    private readonly store: SastRuleBundleCanaryStore,
    private readonly manifestStore: SastRuleBundleManifestStore,
    private readonly lifecycleStore: SastRuleBundleLifecycleStore,
    private readonly keyProvider: SastRuleBundleCanaryCohortKeyProvider,
    private readonly observationSource: SastRuleBundleCanaryObservationSource,
    private readonly clock: SastRuleBundleCanaryClock
  ) {
    super();
  }

  async registerRollout(
    input: Readonly<SastRuleBundleCanaryRolloutInput>
  ): Promise<PersistedSastRuleBundleCanaryRollout> {
    const rollout = buildSastRuleBundleCanaryRollout(
      input,
      digestSastRuleBundleCanonical
    );
    if (!rollout || !this.isAtOrBeforeTrustedNow(rollout.createdAt)) {
      throw new SastRuleBundleCanaryServiceError('INPUT_INVALID');
    }
    let keyMaterial: Buffer | null = null;
    try {
      const key = await this.keyProvider.load();
      keyMaterial = Buffer.isBuffer(key?.keyMaterial) ? key.keyMaterial : null;
      if (!isUsableCohortKey(key)) {
        throw new SastRuleBundleCanaryCohortKeyError('INVALID');
      }
      const [candidate, baseline, lifecycle, baselineLifecycle] = await Promise.all([
        this.manifestStore.findVerified(rollout.candidateManifestId),
        this.manifestStore.findVerified(rollout.baselineManifestId),
        this.lifecycleStore.findLatestLifecycleSnapshot(
          rollout.candidateManifestId
        ),
        this.lifecycleStore.findLatestLifecycleSnapshot(
          rollout.baselineManifestId
        )
      ]);
      if (!candidate || !baseline || !lifecycle || !baselineLifecycle) {
        throw new SastRuleBundleCanaryServiceError('MANIFEST_UNVERIFIED');
      }
      if (
        !rolloutMatchesVerifiedState(
          rollout,
          candidate,
          baseline,
          lifecycle,
          baselineLifecycle
        ) ||
        key.keyRef !== rollout.cohortKeyRef ||
        key.keyVersion !== rollout.cohortKeyVersion ||
        Date.parse(rollout.createdAt) <
          Date.parse(lifecycle.transition.transitionedAt)
      ) {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_INVALID');
      }
      return await this.store.registerRollout(rollout);
    } catch (error) {
      if (error instanceof SastRuleBundleCanaryServiceError) throw error;
      if (error instanceof SastRuleBundleCanaryCohortKeyError) {
        throw new SastRuleBundleCanaryServiceError('KEY_UNAVAILABLE');
      }
      if (
        error instanceof SastRuleBundleManifestPersistenceError ||
        error instanceof SastRuleBundleLifecyclePersistenceError
      ) {
        throw new SastRuleBundleCanaryServiceError('MANIFEST_UNVERIFIED');
      }
      if (error instanceof SastRuleBundleCanaryPersistenceError) {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_INVALID');
      }
      throw new SastRuleBundleCanaryServiceError('STORE_UNAVAILABLE');
    } finally {
      keyMaterial?.fill(0);
    }
  }

  async registerEligibilityDecision(
    input: Readonly<SastRuleBundleCanaryEligibilityDecisionInput>
  ): Promise<PersistedSastRuleBundleCanaryEligibilityDecision> {
    const decision = buildSastRuleBundleCanaryEligibilityDecision(
      input,
      digestSastRuleBundleCanonical
    );
    if (!decision || !this.isAtOrBeforeTrustedNow(decision.evaluatedAt)) {
      throw new SastRuleBundleCanaryServiceError('INPUT_INVALID');
    }
    try {
      const snapshot = await this.store.findRollout(decision.rolloutId);
      if (!snapshot || !eligibilityMatchesRollout(decision, snapshot.rollout)) {
        throw new SastRuleBundleCanaryServiceError('ELIGIBILITY_INVALID');
      }
      if (!(await this.isRolloutLifecycleCurrent(snapshot.rollout))) {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_INVALID');
      }
      if (snapshot.latestDecision?.outcome === 'PAUSED') {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_PAUSED');
      }
      if (snapshot.observationReceipt) {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_COMPLETE');
      }
      return await this.store.registerEligibilityDecision(decision);
    } catch (error) {
      if (error instanceof SastRuleBundleCanaryServiceError) throw error;
      if (error instanceof SastRuleBundleCanaryPersistenceError) {
        throw new SastRuleBundleCanaryServiceError('ELIGIBILITY_INVALID');
      }
      throw new SastRuleBundleCanaryServiceError('STORE_UNAVAILABLE');
    }
  }

  async verifyScannerSet(
    input: Readonly<SastRuleBundleCanaryGateInput>
  ): Promise<CanaryQualifiedScannerSetDescriptor> {
    if (
      !isPromotionVerifiedScannerSetDescriptorValid(input.scannerSet) ||
      !isSastScanProfileValid(input.profile) ||
      !isDigest(input.profileDigest) ||
      !isOpaqueIdentifier(input.tenantId) ||
      !isOpaqueIdentifier(input.repositoryBindingId) ||
      !isExactIsoInstant(input.evaluatedAt)
    ) {
      throw new SastRuleBundleCanaryGateError('CANARY_ASSIGNMENT_STALE');
    }
    if (!this.isAtOrBeforeTrustedNowForGate(input.evaluatedAt)) {
      throw new SastRuleBundleCanaryGateError('CANARY_ASSIGNMENT_STALE');
    }

    if (
      input.scannerSet.ruleBundles.every(
        (bundle) => bundle.lifecycle.lifecycleState === 'ACTIVE'
      )
    ) {
      const qualified = cloneQualifiedScannerSet(
        input.scannerSet,
        input.scannerSet.ruleBundles.map((bundle) =>
          cloneQualifiedBundle(bundle, null)
        )
      );
      if (!isCanaryQualifiedScannerSetDescriptorValid(qualified)) {
        throw new SastRuleBundleCanaryGateError('CANARY_STORE_UNAVAILABLE');
      }
      return qualified;
    }

    let keyMaterial: Buffer | null = null;
    try {
      const key = await this.keyProvider.load();
      keyMaterial = Buffer.isBuffer(key?.keyMaterial) ? key.keyMaterial : null;
      if (!isUsableCohortKey(key)) {
        throw new SastRuleBundleCanaryCohortKeyError('INVALID');
      }
      const pending: Array<{
        bundle: PromotionVerifiedRuleBundleDescriptor;
        snapshot: SastRuleBundleCanaryRolloutSnapshot;
        membership: SastRuleBundleCanaryMembership;
        assignment: SastRuleBundleCanaryAssignmentReceipt;
      }> = [];
      const activeBundles: CanaryQualifiedRuleBundleDescriptor[] = [];

      for (const bundle of input.scannerSet.ruleBundles) {
        if (bundle.lifecycle.lifecycleState === 'ACTIVE') {
          activeBundles.push(cloneQualifiedBundle(bundle, null));
          continue;
        }
        const snapshot = await this.store.findRolloutForCandidate(
          bundle.manifestId,
          input.profile.id
        );
        if (!snapshot || !rolloutMatchesGate(snapshot.rollout, bundle, input)) {
          throw new SastRuleBundleCanaryGateError(
            'CANARY_ROLLOUT_UNAVAILABLE'
          );
        }
        if (!(await this.isRolloutLifecycleCurrent(snapshot.rollout))) {
          throw new SastRuleBundleCanaryGateError(
            'CANARY_ROLLOUT_UNAVAILABLE'
          );
        }
        if (snapshot.latestDecision?.outcome === 'PAUSED') {
          throw new SastRuleBundleCanaryGateError(
            'CANARY_ASSIGNMENT_STALE'
          );
        }
        if (snapshot.observationReceipt) {
          throw new SastRuleBundleCanaryGateError(
            'CANARY_ASSIGNMENT_STALE'
          );
        }
        if (
          snapshot.rollout.cohortKeyRef !== key.keyRef ||
          snapshot.rollout.cohortKeyVersion !== key.keyVersion
        ) {
          throw new SastRuleBundleCanaryGateError('CANARY_KEY_UNAVAILABLE');
        }
        const eligibility = await this.store.findEligibilityDecision({
          rolloutId: snapshot.rollout.rolloutId,
          tenantId: input.tenantId,
          repositoryBindingId: input.repositoryBindingId,
          profileId: input.profile.id
        });
        if (
          !eligibility ||
          !isSastRuleBundleCanaryEligibilityDecisionShapeValid(
            eligibility,
            digestSastRuleBundleCanonical
          ) ||
          !eligibilityMatchesRollout(eligibility, snapshot.rollout)
        ) {
          throw new SastRuleBundleCanaryGateError(
            'CANARY_ELIGIBILITY_UNAVAILABLE'
          );
        }
        if (Date.parse(input.evaluatedAt) < Date.parse(eligibility.evaluatedAt)) {
          throw new SastRuleBundleCanaryGateError(
            'CANARY_ASSIGNMENT_STALE'
          );
        }
        const preimage = buildSastCanaryMembershipHmacPreimage({
          tenantId: input.tenantId,
          repositoryBindingId: input.repositoryBindingId,
          profileId: input.profile.id,
          rolloutId: snapshot.rollout.rolloutId
        });
        if (!preimage) {
          throw new SastRuleBundleCanaryGateError(
            'CANARY_ASSIGNMENT_STALE'
          );
        }
        const assignmentHmacDigest = `sha256:${createHmac('sha256', key.keyMaterial)
          .update(preimage, 'utf8')
          .digest('hex')}` as const;
        const membership = buildSastRuleBundleCanaryMembership(
          {
            rolloutId: snapshot.rollout.rolloutId,
            rolloutDigest: snapshot.rollout.rolloutDigest,
            tenantId: input.tenantId,
            repositoryBindingId: input.repositoryBindingId,
            profileId: input.profile.id,
            profileDigest: input.profileDigest,
            eligibilityDecisionId: eligibility.eligibilityDecisionId,
            eligibilityDecisionDigest:
              eligibility.eligibilityDecisionDigest,
            eligibilityClass: eligibility.eligibilityClass,
            excluded: eligibility.excluded,
            exclusionRef: eligibility.exclusionRef,
            eligibilityPolicyRef: eligibility.eligibilityPolicyRef,
            eligibilityPolicyDigest: eligibility.eligibilityPolicyDigest,
            cohortKeyRef: snapshot.rollout.cohortKeyRef,
            cohortKeyVersion: snapshot.rollout.cohortKeyVersion,
            assignmentHmacDigest,
            evaluatedAt: eligibility.evaluatedAt
          },
          digestSastRuleBundleCanonical
        );
        if (!membership) {
          throw new SastRuleBundleCanaryGateError(
            'CANARY_ASSIGNMENT_STALE'
          );
        }
        const current = currentCanaryStep(snapshot);
        const assignment = buildSastRuleBundleCanaryAssignmentReceipt(
          {
            rolloutId: snapshot.rollout.rolloutId,
            rolloutDigest: snapshot.rollout.rolloutDigest,
            membershipId: membership.membershipId,
            membershipDigest: membership.membershipDigest,
            tenantId: membership.tenantId,
            repositoryBindingId: membership.repositoryBindingId,
            profileId: membership.profileId,
            profileDigest: membership.profileDigest,
            eligibilityClass: membership.eligibilityClass,
            excluded: membership.excluded,
            bucketBasisPoints: membership.bucketBasisPoints,
            step: current.step,
            stepHeadDecisionId: current.head?.decisionId ?? null,
            stepHeadDecisionDigest: current.head?.decisionDigest ?? null,
            candidateManifestId: snapshot.rollout.candidateManifestId,
            candidateManifestDigest:
              snapshot.rollout.candidateManifestDigest,
            candidateBundleDigest: snapshot.rollout.candidateBundleDigest,
            baselineManifestId: snapshot.rollout.baselineManifestId,
            baselineManifestDigest: snapshot.rollout.baselineManifestDigest,
            baselineBundleDigest: snapshot.rollout.baselineBundleDigest,
            evaluatedAt: input.evaluatedAt
          },
          digestSastRuleBundleCanonical
        );
        if (!assignment || assignment.selection !== 'CANDIDATE') {
          throw new SastRuleBundleCanaryGateError(
            'CANARY_ASSIGNMENT_INELIGIBLE'
          );
        }
        pending.push({ bundle, snapshot, membership, assignment });
      }

      const persisted = await this.store.recordAssignments(
        pending.map(({ membership, assignment }) => ({
          membership,
          assignment
        }))
      );
      if (persisted.length !== pending.length) {
        throw new SastRuleBundleCanaryGateError('CANARY_STORE_UNAVAILABLE');
      }
      const persistedByReceipt = new Map(
        persisted.map((item) => [item.assignment.assignmentReceiptId, item])
      );
      for (const item of pending) {
        const stored = persistedByReceipt.get(
          item.assignment.assignmentReceiptId
        );
        if (!stored || !persistedAssignmentMatches(stored, item.assignment)) {
          throw new SastRuleBundleCanaryGateError('CANARY_STORE_UNAVAILABLE');
        }
        const descriptor = toVerifiedSastRuleBundleCanaryAssignmentDescriptor(
          stored.membership,
          stored.assignment
        );
        if (!descriptor) {
          throw new SastRuleBundleCanaryGateError('CANARY_STORE_UNAVAILABLE');
        }
        activeBundles.push(cloneQualifiedBundle(item.bundle, descriptor));
      }
      const qualified = cloneQualifiedScannerSet(
        input.scannerSet,
        input.scannerSet.ruleBundles.map((bundle) => {
          const active = activeBundles.find(
            (qualifiedBundle) => qualifiedBundle.scanner === bundle.scanner
          );
          if (!active) {
            throw new SastRuleBundleCanaryGateError(
              'CANARY_STORE_UNAVAILABLE'
            );
          }
          return active;
        })
      );
      if (!isCanaryQualifiedScannerSetDescriptorValid(qualified)) {
        throw new SastRuleBundleCanaryGateError('CANARY_STORE_UNAVAILABLE');
      }
      return qualified;
    } catch (error) {
      if (error instanceof SastRuleBundleCanaryGateError) throw error;
      if (error instanceof SastRuleBundleCanaryCohortKeyError) {
        throw new SastRuleBundleCanaryGateError('CANARY_KEY_UNAVAILABLE');
      }
      if (error instanceof SastRuleBundleCanaryPersistenceError) {
        throw new SastRuleBundleCanaryGateError(
          error.reason === 'ROLLOUT_PAUSED' || error.reason === 'STEP_STALE'
            ? 'CANARY_ASSIGNMENT_STALE'
            : 'CANARY_STORE_UNAVAILABLE'
        );
      }
      throw new SastRuleBundleCanaryGateError('CANARY_STORE_UNAVAILABLE');
    } finally {
      keyMaterial?.fill(0);
    }
  }

  async recordScanObservation(
    request: Readonly<SastRuleBundleCanaryObservationSourceRequest>
  ): Promise<PersistedSastRuleBundleCanaryObservation> {
    if (!isObservationSourceRequestValid(request)) {
      throw new SastRuleBundleCanaryServiceError('INPUT_INVALID');
    }
    try {
      const snapshot = await this.store.findRollout(request.rolloutId);
      if (!snapshot || snapshot.latestDecision?.outcome === 'PAUSED') {
        throw new SastRuleBundleCanaryServiceError(
          snapshot ? 'ROLLOUT_PAUSED' : 'ROLLOUT_INVALID'
        );
      }
      if (!(await this.isRolloutLifecycleCurrent(snapshot.rollout))) {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_INVALID');
      }
      if (snapshot.observationReceipt) {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_COMPLETE');
      }
      const source = await this.observationSource.load(request);
      if (!observationSourceMatchesRequest(source, request, snapshot.rollout)) {
        throw new SastRuleBundleCanaryServiceError('OBSERVATION_INVALID');
      }
      const observation = buildSastRuleBundleCanaryScanObservation(
        source,
        digestSastRuleBundleCanonical
      );
      if (
        !observation ||
        !this.isAtOrBeforeTrustedNow(observation.completedAt)
      ) {
        throw new SastRuleBundleCanaryServiceError('OBSERVATION_INVALID');
      }
      return await this.store.registerObservation(observation);
    } catch (error) {
      if (error instanceof SastRuleBundleCanaryServiceError) throw error;
      if (error instanceof SastRuleBundleCanaryObservationSourceError) {
        throw new SastRuleBundleCanaryServiceError('SOURCE_UNAVAILABLE');
      }
      if (error instanceof SastRuleBundleCanaryPersistenceError) {
        throw new SastRuleBundleCanaryServiceError('OBSERVATION_INVALID');
      }
      throw new SastRuleBundleCanaryServiceError('STORE_UNAVAILABLE');
    }
  }

  async evaluateStep(
    request: Readonly<SastRuleBundleCanaryStepEvaluationRequest>
  ): Promise<PersistedSastRuleBundleCanaryStepDecision> {
    if (!isStepEvaluationRequestValid(request)) {
      throw new SastRuleBundleCanaryServiceError('INPUT_INVALID');
    }
    const evaluatedAt = this.readTrustedNow();
    const windowEndedAt = evaluatedAt;
    try {
      const snapshot = await this.store.findRollout(request.rolloutId);
      if (!snapshot) {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_INVALID');
      }
      if (!(await this.isRolloutLifecycleCurrent(snapshot.rollout))) {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_INVALID');
      }
      if (snapshot.latestDecision?.outcome === 'PAUSED') {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_PAUSED');
      }
      if (snapshot.observationReceipt) {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_COMPLETE');
      }
      const current = currentCanaryStep(snapshot);
      const observations = await this.store.findObservations({
        rolloutId: snapshot.rollout.rolloutId,
        step: current.step,
        windowStartedAt: current.windowStartedAt,
        windowEndedAt
      });
      if (
        observations.length === 0 ||
        !observationsMatchEvaluation(
          observations,
          snapshot.rollout,
          current.step,
          current.windowStartedAt,
          windowEndedAt
        )
      ) {
        throw new SastRuleBundleCanaryServiceError('OBSERVATION_INVALID');
      }
      const bindings = observations
        .map((observation) => ({
          observationId: observation.observationId,
          observationDigest: observation.observationDigest
        }))
        .sort((left, right) =>
          left.observationId.localeCompare(right.observationId)
        );
      const decision = buildSastRuleBundleCanaryStepDecision(
        {
          rolloutId: snapshot.rollout.rolloutId,
          rolloutDigest: snapshot.rollout.rolloutDigest,
          candidateManifestId: snapshot.rollout.candidateManifestId,
          candidateManifestDigest:
            snapshot.rollout.candidateManifestDigest,
          candidateBundleDigest: snapshot.rollout.candidateBundleDigest,
          baselineManifestId: snapshot.rollout.baselineManifestId,
          baselineManifestDigest: snapshot.rollout.baselineManifestDigest,
          baselineBundleDigest: snapshot.rollout.baselineBundleDigest,
          profileId: snapshot.rollout.profileId,
          profileDigest: snapshot.rollout.profileDigest,
          sequence: (snapshot.latestDecision?.sequence ?? 0) + 1,
          step: current.step,
          previousDecisionId:
            snapshot.latestDecision?.decisionId ?? null,
          previousDecisionDigest:
            snapshot.latestDecision?.decisionDigest ?? null,
          windowStartedAt: current.windowStartedAt,
          windowEndedAt,
          observations: bindings,
          measurements: aggregateObservations(observations),
          telemetryComplete: observations.every(
            (observation) => observation.telemetryComplete
          ),
          allProfileSizeBucketsCompared:
            allProfileSizeBucketsCompared(observations),
          evaluatorRef: request.evaluatorRef,
          auditRef: request.auditRef,
          evaluatedAt
        },
        digestSastRuleBundleCanonical
      );
      if (!decision) {
        throw new SastRuleBundleCanaryServiceError('STEP_INVALID');
      }
      const finalReceipt = buildFinalReceiptIfEligible(
        snapshot,
        decision,
        evaluatedAt
      );
      return await this.store.appendStepDecision({
        decision,
        finalReceipt
      });
    } catch (error) {
      if (error instanceof SastRuleBundleCanaryServiceError) throw error;
      if (error instanceof SastRuleBundleCanaryPersistenceError) {
        throw new SastRuleBundleCanaryServiceError(
          error.reason === 'ROLLOUT_PAUSED'
            ? 'ROLLOUT_PAUSED'
            : error.reason === 'STEP_STALE'
              ? 'STEP_INVALID'
              : 'STORE_UNAVAILABLE'
        );
      }
      throw new SastRuleBundleCanaryServiceError('STORE_UNAVAILABLE');
    }
  }

  async authorizeLifecycleTransition(
    input: Readonly<SastRuleBundleLifecycleAuthorityInput>
  ): Promise<SastRuleBundleLifecycleAuthorityReceipt> {
    if (
      input.authority !== 'CANARY_OBSERVATION' ||
      input.fromState !== 'CANARY' ||
      input.toState !== 'ACTIVE' ||
      !isExactIsoInstant(input.requestedAt)
    ) {
      throw new SastRuleBundleCanaryServiceError('INPUT_INVALID');
    }
    try {
      const receipt = await this.store.findObservationReceiptForAuthority({
        manifestId: input.manifestId,
        manifestDigest: input.manifestDigest,
        bundleId: input.bundleId,
        bundleDigest: input.bundleDigest,
        promotionEvidenceId: input.promotionEvidenceId,
        promotionEvidenceDigest: input.promotionEvidenceDigest
      });
      if (
        !receipt ||
        !isSastRuleBundleCanaryObservationReceiptShapeValid(
          receipt,
          digestSastRuleBundleCanonical
        ) ||
        !authorityReceiptMatchesInput(receipt, input) ||
        Date.parse(receipt.issuedAt) > Date.parse(input.requestedAt)
      ) {
        throw new SastRuleBundleCanaryServiceError('STEP_INVALID');
      }
      const snapshot = await this.store.findRollout(receipt.rolloutId);
      if (
        !snapshot ||
        !(await this.isRolloutLifecycleCurrent(snapshot.rollout))
      ) {
        throw new SastRuleBundleCanaryServiceError('ROLLOUT_INVALID');
      }
      return {
        authority: 'CANARY_OBSERVATION',
        manifestId: input.manifestId,
        manifestDigest: input.manifestDigest,
        bundleId: input.bundleId,
        bundleDigest: input.bundleDigest,
        fromState: 'CANARY',
        toState: 'ACTIVE',
        promotionEvidenceId: input.promotionEvidenceId,
        promotionEvidenceDigest: input.promotionEvidenceDigest,
        requestedAt: input.requestedAt,
        receiptRef: receipt.receiptRef,
        receiptDigest: receipt.receiptDigest,
        verifiedAt: receipt.issuedAt
      };
    } catch (error) {
      if (error instanceof SastRuleBundleCanaryServiceError) throw error;
      throw new SastRuleBundleCanaryServiceError('STORE_UNAVAILABLE');
    }
  }

  private isAtOrBeforeTrustedNow(value: string): boolean {
    return (
      isExactIsoInstant(value) &&
      Date.parse(value) <= Date.parse(this.readTrustedNow())
    );
  }

  private async isRolloutLifecycleCurrent(
    rollout: Readonly<SastRuleBundleCanaryRollout>
  ): Promise<boolean> {
    const [candidate, baseline] = await Promise.all([
      this.lifecycleStore.findLatestLifecycleSnapshot(
        rollout.candidateManifestId
      ),
      this.lifecycleStore.findLatestLifecycleSnapshot(
        rollout.baselineManifestId
      )
    ]);
    return rolloutLifecycleMatches(rollout, candidate, baseline);
  }

  private isAtOrBeforeTrustedNowForGate(value: string): boolean {
    try {
      return this.isAtOrBeforeTrustedNow(value);
    } catch {
      return false;
    }
  }

  private readTrustedNow(): string {
    try {
      const value = this.clock.now();
      const milliseconds = Date.prototype.getTime.call(value);
      if (!Number.isFinite(milliseconds)) {
        throw new SastRuleBundleCanaryServiceError('STORE_UNAVAILABLE');
      }
      return new Date(milliseconds).toISOString();
    } catch (error) {
      if (error instanceof SastRuleBundleCanaryServiceError) throw error;
      throw new SastRuleBundleCanaryServiceError('STORE_UNAVAILABLE');
    }
  }
}

function rolloutMatchesVerifiedState(
  rollout: Readonly<SastRuleBundleCanaryRollout>,
  candidate: Readonly<Awaited<ReturnType<SastRuleBundleManifestStore['findVerified']>> & {}>,
  baseline: Readonly<Awaited<ReturnType<SastRuleBundleManifestStore['findVerified']>> & {}>,
  lifecycle: Readonly<
    Awaited<ReturnType<SastRuleBundleLifecycleStore['findLatestLifecycleSnapshot']>> & {}
  >,
  baselineLifecycle: Readonly<
    Awaited<ReturnType<SastRuleBundleLifecycleStore['findLatestLifecycleSnapshot']>> & {}
  >
): boolean {
  return (
    rollout.candidateManifestId === candidate.manifest.manifestId &&
    rollout.candidateManifestDigest === candidate.manifest.manifestDigest &&
    rollout.candidateBundleId === candidate.manifest.bundleId &&
    rollout.candidateBundleDigest === candidate.manifest.bundleDigest &&
    rollout.baselineManifestId === baseline.manifest.manifestId &&
    rollout.baselineManifestDigest === baseline.manifest.manifestDigest &&
    rollout.baselineBundleDigest === baseline.manifest.bundleDigest &&
    rollout.baselineBundleDigest === candidate.manifest.rollbackTargetDigest &&
    baselineLifecycle.transition.manifestId === rollout.baselineManifestId &&
    baselineLifecycle.transition.manifestDigest ===
      rollout.baselineManifestDigest &&
    baselineLifecycle.transition.bundleId === rollout.candidateBundleId &&
    baselineLifecycle.transition.bundleDigest === rollout.baselineBundleDigest &&
    baselineLifecycle.transition.toState === 'ACTIVE' &&
    Date.parse(rollout.createdAt) >=
      Date.parse(baselineLifecycle.transition.transitionedAt) &&
    lifecycle.transition.toState === 'CANARY' &&
    rollout.canaryTransitionId === lifecycle.transition.transitionId &&
    rollout.canaryTransitionDigest === lifecycle.transition.transitionDigest &&
    rollout.promotionEvidenceId === lifecycle.evidence.evidenceId &&
    rollout.promotionEvidenceDigest === lifecycle.evidence.evidenceDigest &&
    rollout.baselineManifestId === lifecycle.evidence.baselineManifestId &&
    rollout.baselineManifestDigest ===
      lifecycle.evidence.baselineManifestDigest &&
    rollout.baselineBundleDigest === lifecycle.evidence.baselineBundleDigest &&
    rollout.profileId === lifecycle.evidence.profileId
  );
}

function rolloutMatchesGate(
  rollout: Readonly<SastRuleBundleCanaryRollout>,
  bundle: Readonly<PromotionVerifiedRuleBundleDescriptor>,
  input: Readonly<SastRuleBundleCanaryGateInput>
): boolean {
  return (
    isSastRuleBundleCanaryRolloutShapeValid(
      rollout,
      digestSastRuleBundleCanonical
    ) &&
    rollout.candidateManifestId === bundle.manifestId &&
    rollout.candidateManifestDigest === bundle.manifestDigest &&
    rollout.candidateBundleId === bundle.bundleId &&
    rollout.candidateBundleDigest === bundle.digest &&
    rollout.profileId === input.profile.id &&
    rollout.profileDigest === input.profileDigest &&
    rollout.canaryTransitionId === bundle.lifecycle.lifecycleTransitionId &&
    rollout.canaryTransitionDigest ===
      bundle.lifecycle.lifecycleTransitionDigest &&
    rollout.promotionEvidenceId === bundle.lifecycle.promotionEvidenceId &&
    rollout.promotionEvidenceDigest ===
      bundle.lifecycle.promotionEvidenceDigest &&
    Date.parse(input.evaluatedAt) >= Date.parse(rollout.createdAt)
  );
}

function rolloutLifecycleMatches(
  rollout: Readonly<SastRuleBundleCanaryRollout>,
  candidate: Readonly<SastRuleBundleLifecycleLedgerSnapshot> | null,
  baseline: Readonly<SastRuleBundleLifecycleLedgerSnapshot> | null
): boolean {
  return (
    candidate !== null &&
    baseline !== null &&
    candidate.transition.manifestId === rollout.candidateManifestId &&
    candidate.transition.manifestDigest === rollout.candidateManifestDigest &&
    candidate.transition.bundleId === rollout.candidateBundleId &&
    candidate.transition.bundleDigest === rollout.candidateBundleDigest &&
    candidate.transition.transitionId === rollout.canaryTransitionId &&
    candidate.transition.transitionDigest === rollout.canaryTransitionDigest &&
    candidate.transition.toState === 'CANARY' &&
    baseline.transition.manifestId === rollout.baselineManifestId &&
    baseline.transition.manifestDigest === rollout.baselineManifestDigest &&
    baseline.transition.bundleId === rollout.candidateBundleId &&
    baseline.transition.bundleDigest === rollout.baselineBundleDigest &&
    baseline.transition.toState === 'ACTIVE' &&
    Date.parse(baseline.transition.transitionedAt) <=
      Date.parse(rollout.createdAt)
  );
}

function eligibilityMatchesRollout(
  decision: Readonly<{
    rolloutId: string;
    rolloutDigest: string;
    profileId: string;
    profileDigest: string;
    eligibilityPolicyRef: string;
    eligibilityPolicyDigest: string;
    evaluatedAt: string;
  }>,
  rollout: Readonly<SastRuleBundleCanaryRollout>
): boolean {
  return (
    decision.rolloutId === rollout.rolloutId &&
    decision.rolloutDigest === rollout.rolloutDigest &&
    decision.profileId === rollout.profileId &&
    decision.profileDigest === rollout.profileDigest &&
    decision.eligibilityPolicyRef === rollout.eligibilityPolicyRef &&
    decision.eligibilityPolicyDigest === rollout.eligibilityPolicyDigest &&
    Date.parse(decision.evaluatedAt) >= Date.parse(rollout.createdAt)
  );
}

function currentCanaryStep(snapshot: Readonly<SastRuleBundleCanaryRolloutSnapshot>): {
  step: SastRuleBundleCanaryStep;
  head: SastRuleBundleCanaryStepDecision | null;
  windowStartedAt: string;
} {
  const latest = snapshot.latestDecision;
  if (!latest) {
    return {
      step: 'INTERNAL_CORPUS',
      head: null,
      windowStartedAt: snapshot.rollout.createdAt
    };
  }
  if (latest.outcome === 'PENDING') {
    return {
      step: latest.step,
      head: latest,
      windowStartedAt: latest.windowStartedAt
    };
  }
  const next = nextSastRuleBundleCanaryStep(latest.step);
  return {
    step: next ?? latest.step,
    head: latest,
    windowStartedAt: next ? latest.evaluatedAt : latest.windowStartedAt
  };
}

function persistedAssignmentMatches(
  persisted: Readonly<PersistedSastRuleBundleCanaryAssignment>,
  expected: Readonly<SastRuleBundleCanaryAssignmentReceipt>
): boolean {
  return (
    isSastRuleBundleCanaryMembershipShapeValid(
      persisted.membership,
      digestSastRuleBundleCanonical
    ) &&
    isSastRuleBundleCanaryAssignmentReceiptShapeValid(
      persisted.assignment,
      digestSastRuleBundleCanonical
    ) &&
    persisted.assignment.assignmentReceiptId ===
      expected.assignmentReceiptId &&
    persisted.assignment.assignmentReceiptDigest ===
      expected.assignmentReceiptDigest &&
    persisted.assignment.selection === 'CANDIDATE'
  );
}

function cloneQualifiedBundle(
  bundle: Readonly<PromotionVerifiedRuleBundleDescriptor>,
  canaryAssignment: CanaryQualifiedRuleBundleDescriptor['canaryAssignment']
): CanaryQualifiedRuleBundleDescriptor {
  return {
    ...bundle,
    rules: bundle.rules.map((rule) => ({ ...rule })),
    lifecycle: { ...bundle.lifecycle },
    canaryAssignment: canaryAssignment ? { ...canaryAssignment } : null
  };
}

function cloneQualifiedScannerSet(
  scannerSet: Readonly<PromotionVerifiedScannerSetDescriptor>,
  ruleBundles: CanaryQualifiedRuleBundleDescriptor[]
): CanaryQualifiedScannerSetDescriptor {
  return {
    ...scannerSet,
    scanners: structuredClone(scannerSet.scanners),
    ruleBundles,
    vulnerabilityDatabase: { ...scannerSet.vulnerabilityDatabase },
    schemaBundle: { ...scannerSet.schemaBundle },
    normalizerBundle: { ...scannerSet.normalizerBundle }
  };
}

function isObservationSourceRequestValid(
  value: unknown
): value is SastRuleBundleCanaryObservationSourceRequest {
  if (!hasExactKeys(value, OBSERVATION_SOURCE_REQUEST_KEYS)) return false;
  const request = value as unknown as SastRuleBundleCanaryObservationSourceRequest;
  return (
    isOpaqueIdentifier(request.rolloutId) &&
    isOpaqueIdentifier(request.tenantId) &&
    isOpaqueIdentifier(request.repositoryBindingId) &&
    isOpaqueIdentifier(request.scanRequestId) &&
    isOpaqueIdentifier(request.attemptId)
  );
}

function observationSourceMatchesRequest(
  source: Readonly<Parameters<typeof buildSastRuleBundleCanaryScanObservation>[0]>,
  request: Readonly<SastRuleBundleCanaryObservationSourceRequest>,
  rollout: Readonly<SastRuleBundleCanaryRollout>
): boolean {
  const candidate = source.cohortRole === 'CANDIDATE';
  return (
    source.rolloutId === request.rolloutId &&
    source.rolloutDigest === rollout.rolloutDigest &&
    source.tenantId === request.tenantId &&
    source.repositoryBindingId === request.repositoryBindingId &&
    source.scanRequestId === request.scanRequestId &&
    source.attemptId === request.attemptId &&
    source.profileId === rollout.profileId &&
    source.profileDigest === rollout.profileDigest &&
    source.observationSourceRef === rollout.observationSourceRef &&
    source.observationSourceDigest === rollout.observationSourceDigest &&
    source.selectedManifestId ===
      (candidate ? rollout.candidateManifestId : rollout.baselineManifestId) &&
    source.selectedManifestDigest ===
      (candidate
        ? rollout.candidateManifestDigest
        : rollout.baselineManifestDigest) &&
    source.selectedBundleDigest ===
      (candidate
        ? rollout.candidateBundleDigest
        : rollout.baselineBundleDigest)
  );
}

function isStepEvaluationRequestValid(
  value: unknown
): value is SastRuleBundleCanaryStepEvaluationRequest {
  if (!hasExactKeys(value, STEP_EVALUATION_REQUEST_KEYS)) return false;
  const request = value as unknown as SastRuleBundleCanaryStepEvaluationRequest;
  return (
    isOpaqueIdentifier(request.rolloutId) &&
    isActorReference(request.evaluatorRef) &&
    isDigestBoundReference(request.auditRef)
  );
}

function observationsMatchEvaluation(
  observations: readonly Readonly<SastRuleBundleCanaryScanObservation>[],
  rollout: Readonly<SastRuleBundleCanaryRollout>,
  step: SastRuleBundleCanaryStep,
  windowStartedAt: string,
  windowEndedAt: string
): boolean {
  const scanKeys = new Set<string>();
  for (const observation of observations) {
    if (
      !isSastRuleBundleCanaryScanObservationShapeValid(
        observation,
        digestSastRuleBundleCanonical
      ) ||
      observation.rolloutId !== rollout.rolloutId ||
      observation.rolloutDigest !== rollout.rolloutDigest ||
      observation.step !== step ||
      observation.profileId !== rollout.profileId ||
      observation.profileDigest !== rollout.profileDigest ||
      Date.parse(observation.completedAt) < Date.parse(windowStartedAt) ||
      Date.parse(observation.completedAt) > Date.parse(windowEndedAt)
    ) {
      return false;
    }
    const scanKey = `${observation.tenantId}:${observation.scanRequestId}:${observation.attemptId}`;
    if (scanKeys.has(scanKey)) return false;
    scanKeys.add(scanKey);
  }
  return true;
}

function allProfileSizeBucketsCompared(
  observations: readonly Readonly<SastRuleBundleCanaryScanObservation>[]
): boolean {
  return SAST_RULE_BUNDLE_CANARY_REPOSITORY_SIZE_BUCKETS.every(
    (size) =>
      observations.some(
        (observation) =>
          observation.repositorySizeBucket === size &&
          observation.cohortRole === 'CANDIDATE'
      ) &&
      observations.some(
        (observation) =>
          observation.repositorySizeBucket === size &&
          observation.cohortRole === 'BASELINE'
      )
  );
}

function aggregateObservations(
  observations: readonly Readonly<SastRuleBundleCanaryScanObservation>[]
): SastRuleBundleCanaryStepAggregateMeasurements {
  const candidate = observations.filter(
    (observation) => observation.cohortRole === 'CANDIDATE'
  );
  const baseline = observations.filter(
    (observation) => observation.cohortRole === 'BASELINE'
  );
  const sum = (
    values: readonly Readonly<SastRuleBundleCanaryScanObservation>[],
    field: keyof SastRuleBundleCanaryScanObservation['measurements']
  ) => values.reduce((total, value) => total + value.measurements[field], 0);
  const percentile = (
    values: readonly Readonly<SastRuleBundleCanaryScanObservation>[],
    field: keyof SastRuleBundleCanaryScanObservation['measurements'],
    percent: number
  ) => nearestRank(values.map((value) => value.measurements[field]), percent);
  const securityFields = [
    'crossTenantEvents',
    'secretLeakEvents',
    'sandboxEscapeEvents',
    'stalePublicationEvents',
    'unauthorizedEgressEvents',
    'missingDestructionEvidenceEvents',
    'evidencePolicyViolationEvents',
    'unsignedArtifactExecutionEvents'
  ] as const;
  const both = [...candidate, ...baseline];
  return {
    candidateCompletedScans: candidate.length,
    baselineCompletedScans: baseline.length,
    candidateFindingCount: sum(candidate, 'findingCount'),
    baselineFindingCount: sum(baseline, 'findingCount'),
    candidateCriticalHighFindingCount: sum(
      candidate,
      'criticalHighFindingCount'
    ),
    baselineCriticalHighFindingCount: sum(
      baseline,
      'criticalHighFindingCount'
    ),
    candidateFalsePositiveCount: sum(candidate, 'falsePositiveCount'),
    candidateFeedbackEligibleFindingCount: sum(
      candidate,
      'feedbackEligibleFindingCount'
    ),
    baselineFalsePositiveCount: sum(baseline, 'falsePositiveCount'),
    baselineFeedbackEligibleFindingCount: sum(
      baseline,
      'feedbackEligibleFindingCount'
    ),
    candidateWaiverCount: sum(candidate, 'waiverCount'),
    baselineWaiverCount: sum(baseline, 'waiverCount'),
    candidateSuppressionCount: sum(candidate, 'suppressionCount'),
    baselineSuppressionCount: sum(baseline, 'suppressionCount'),
    candidateScannerFailureCount: sum(candidate, 'scannerFailureCount'),
    candidateEligibleScannerAttemptCount: sum(
      candidate,
      'eligibleScannerAttemptCount'
    ),
    baselineScannerFailureCount: sum(baseline, 'scannerFailureCount'),
    baselineEligibleScannerAttemptCount: sum(
      baseline,
      'eligibleScannerAttemptCount'
    ),
    candidateScannerTimeoutCount: sum(candidate, 'scannerTimeoutCount'),
    baselineScannerTimeoutCount: sum(baseline, 'scannerTimeoutCount'),
    candidateP50LatencyMilliseconds: percentile(
      candidate,
      'latencyMilliseconds',
      50
    ),
    candidateP95LatencyMilliseconds: percentile(
      candidate,
      'latencyMilliseconds',
      95
    ),
    baselineP50LatencyMilliseconds: percentile(
      baseline,
      'latencyMilliseconds',
      50
    ),
    baselineP95LatencyMilliseconds: percentile(
      baseline,
      'latencyMilliseconds',
      95
    ),
    candidateP95CpuMilliseconds: percentile(candidate, 'cpuMilliseconds', 95),
    baselineP95CpuMilliseconds: percentile(baseline, 'cpuMilliseconds', 95),
    candidateP95PeakMemoryBytes: percentile(candidate, 'peakMemoryBytes', 95),
    baselineP95PeakMemoryBytes: percentile(baseline, 'peakMemoryBytes', 95),
    candidateP95DiskBytes: percentile(candidate, 'diskBytes', 95),
    baselineP95DiskBytes: percentile(baseline, 'diskBytes', 95),
    candidateArtifactRejectionCount: sum(candidate, 'artifactRejectionCount'),
    baselineArtifactRejectionCount: sum(baseline, 'artifactRejectionCount'),
    candidateIncompleteCoverageCount: sum(
      candidate,
      'incompleteCoverageCount'
    ),
    baselineIncompleteCoverageCount: sum(
      baseline,
      'incompleteCoverageCount'
    ),
    candidatePublicationDenialCount: sum(
      candidate,
      'publicationDenialCount'
    ),
    baselinePublicationDenialCount: sum(
      baseline,
      'publicationDenialCount'
    ),
    candidateEgressDenialCount: sum(candidate, 'egressDenialCount'),
    baselineEgressDenialCount: sum(baseline, 'egressDenialCount'),
    candidateP95CleanupLagMilliseconds: percentile(
      candidate,
      'cleanupLagMilliseconds',
      95
    ),
    baselineP95CleanupLagMilliseconds: percentile(
      baseline,
      'cleanupLagMilliseconds',
      95
    ),
    candidateQuarantineCount: sum(candidate, 'quarantineCount'),
    baselineQuarantineCount: sum(baseline, 'quarantineCount'),
    candidateKillSwitchSignalCount: sum(candidate, 'killSwitchSignalCount'),
    baselineKillSwitchSignalCount: sum(baseline, 'killSwitchSignalCount'),
    ...Object.fromEntries(
      securityFields.map((field) => [field, sum(both, field)])
    )
  } as SastRuleBundleCanaryStepAggregateMeasurements;
}

function nearestRank(values: readonly number[], percent: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.max(0, Math.ceil((percent / 100) * sorted.length) - 1);
  return sorted[index] ?? 0;
}

function buildFinalReceiptIfEligible(
  snapshot: Readonly<SastRuleBundleCanaryRolloutSnapshot>,
  decision: Readonly<SastRuleBundleCanaryStepDecision>,
  issuedAt: string
): SastRuleBundleCanaryObservationReceipt | null {
  if (decision.step !== 'PERCENT_100' || decision.outcome !== 'PASSED') {
    return null;
  }
  const allPassed = [...snapshot.passedDecisions, decision].sort(
    (left, right) =>
      SAST_RULE_BUNDLE_CANARY_STEPS.indexOf(left.step) -
      SAST_RULE_BUNDLE_CANARY_STEPS.indexOf(right.step)
  );
  if (
    allPassed.length !== SAST_RULE_BUNDLE_CANARY_STEPS.length ||
    !allPassed.every(
      (item, index) =>
        item.outcome === 'PASSED' &&
        item.step === SAST_RULE_BUNDLE_CANARY_STEPS[index]
    )
  ) {
    throw new SastRuleBundleCanaryServiceError('STEP_INVALID');
  }
  const receipt = buildSastRuleBundleCanaryObservationReceipt(
    {
      rolloutId: snapshot.rollout.rolloutId,
      rolloutDigest: snapshot.rollout.rolloutDigest,
      candidateManifestId: snapshot.rollout.candidateManifestId,
      candidateManifestDigest: snapshot.rollout.candidateManifestDigest,
      candidateBundleId: snapshot.rollout.candidateBundleId,
      candidateBundleDigest: snapshot.rollout.candidateBundleDigest,
      baselineManifestId: snapshot.rollout.baselineManifestId,
      baselineManifestDigest: snapshot.rollout.baselineManifestDigest,
      baselineBundleDigest: snapshot.rollout.baselineBundleDigest,
      profileId: snapshot.rollout.profileId,
      profileDigest: snapshot.rollout.profileDigest,
      promotionEvidenceId: snapshot.rollout.promotionEvidenceId,
      promotionEvidenceDigest: snapshot.rollout.promotionEvidenceDigest,
      passedSteps: allPassed.map((item) => ({
        step: item.step,
        decisionId: item.decisionId,
        decisionDigest: item.decisionDigest
      })),
      observedFrom: allPassed[0]?.windowStartedAt ?? snapshot.rollout.createdAt,
      observedThrough: decision.windowEndedAt,
      issuedAt
    },
    digestSastRuleBundleCanonical
  );
  if (!receipt) {
    throw new SastRuleBundleCanaryServiceError('STEP_INVALID');
  }
  return receipt;
}

function authorityReceiptMatchesInput(
  receipt: Readonly<SastRuleBundleCanaryObservationReceipt>,
  input: Readonly<SastRuleBundleLifecycleAuthorityInput>
): boolean {
  return (
    receipt.candidateManifestId === input.manifestId &&
    receipt.candidateManifestDigest === input.manifestDigest &&
    receipt.candidateBundleId === input.bundleId &&
    receipt.candidateBundleDigest === input.bundleDigest &&
    receipt.promotionEvidenceId === input.promotionEvidenceId &&
    receipt.promotionEvidenceDigest === input.promotionEvidenceDigest
  );
}

function isExactIsoInstant(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function isDigest(value: unknown): value is `sha256:${string}` {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/u.test(value);
}

function isOpaqueIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 512 &&
    value === value.trim() &&
    value.normalize('NFC') === value &&
    !containsControlCharacter(value)
  );
}

function isUsableCohortKey(value: unknown): value is {
  keyRef: string;
  keyVersion: string;
  keyMaterial: Buffer;
} {
  if (!value || typeof value !== 'object') return false;
  const key = value as Record<string, unknown>;
  const keyMaterial = key.keyMaterial;
  return (
    isDigestBoundReference(key.keyRef) &&
    isOpaqueIdentifier(key.keyVersion) &&
    Buffer.isBuffer(keyMaterial) &&
    keyMaterial.length >= 32 &&
    key.keyRef.endsWith(
      `sha256:${createHash('sha256').update(keyMaterial).digest('hex')}`
    )
  );
}

function isActorReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= 2_048 &&
    /^actor:\/\/[a-zA-Z0-9._~:/@+-]+$/u.test(value)
  );
}

function isDigestBoundReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= 2_048 &&
    !containsControlCharacter(value) &&
    /^[a-z][a-z0-9+.-]*:\/\/\S*sha256:[0-9a-f]{64}$/u.test(value) &&
    !/^https?:/u.test(value)
  );
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 31 || code === 127;
  });
}

function hasExactKeys<T extends readonly string[]>(
  value: unknown,
  keys: T
): value is Record<T[number], unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

const OBSERVATION_SOURCE_REQUEST_KEYS = [
  'rolloutId',
  'tenantId',
  'repositoryBindingId',
  'scanRequestId',
  'attemptId'
] as const;

const STEP_EVALUATION_REQUEST_KEYS = [
  'rolloutId',
  'evaluatorRef',
  'auditRef'
] as const;
