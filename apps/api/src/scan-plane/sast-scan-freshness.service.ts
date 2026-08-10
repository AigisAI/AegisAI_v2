import { createHash } from 'node:crypto';

import {
  SAST_LATEST_TARGET_OBSERVATION_VERSION,
  buildSastScanFreshnessDecision,
  buildSastScanRetryDecision,
  canonicalizeSastLatestTargetObservation,
  isSastFindingLifecycleCoverageDecisionShapeValid,
  isSastLatestTargetObservationShapeValid,
  isSastScanFreshnessDecisionShapeValid,
  isSastScanRetryDecisionShapeValid,
  isSastScannerWrapperExecutionRequestValid,
  type SastFindingLifecycleCoverageDecision,
  type SastLatestTargetAuthority as SastLatestTargetAuthorityStatus,
  type SastLatestTargetObservation,
  type SastScanFreshnessDecision,
  type SastScanRetryEvaluation,
  type SastScannerWrapperExecutionRequest
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import type {
  SastFindingLifecycleCoverageVerification
} from './sast-finding-lifecycle-coverage.gate';
import { SastFindingLifecycleCoverageGate } from './sast-finding-lifecycle-coverage.gate';
import { SastLatestTargetAuthority } from './sast-latest-target-authority';
import {
  SastRetryAdmissionGate,
  type SastRetryAdmissionVerification
} from './sast-retry-admission.gate';
import { SastRetryRuntimeAuthority } from './sast-retry-runtime-authority';
import {
  SastScanFreshnessStore,
  type SastScanFreshnessContext
} from './sast-scan-freshness.store';

export type SastScanFreshnessOutcome =
  | {
      outcome: 'EVALUATED';
      decision: SastScanFreshnessDecision;
      replayed: boolean;
    }
  | {
      outcome: 'REJECTED';
      reasonCode:
        | 'FRESHNESS_INPUT_INVALID'
        | 'FRESHNESS_CONTEXT_UNAVAILABLE'
        | 'FRESHNESS_PERSISTENCE_FAILED';
      publicationAttempted: false;
      lifecycleMutationAttempted: false;
      aiPayloadCreated: false;
    };

type FreshnessClock = () => string;

@Injectable()
export class SastScanFreshnessService
  extends SastFindingLifecycleCoverageGate
  implements SastRetryAdmissionGate {
  constructor(
    private readonly store: SastScanFreshnessStore,
    private readonly latestTarget: SastLatestTargetAuthority,
    private readonly retryRuntime: SastRetryRuntimeAuthority
  ) {
    super();
  }

  async evaluate(
    coverageDecisionId: string,
    clock: FreshnessClock = () => new Date().toISOString()
  ): Promise<SastScanFreshnessOutcome> {
    if (!/^sast-coverage:\/\/[a-f0-9]{64}$/u.test(coverageDecisionId)) {
      return this.reject('FRESHNESS_INPUT_INVALID');
    }
    try {
      const context = await this.store.loadContext(coverageDecisionId);
      if (!context) return this.reject('FRESHNESS_CONTEXT_UNAVAILABLE');
      if (
        context.existingDecision &&
        isSastScanFreshnessDecisionShapeValid(
          context.existingDecision,
          digest
        )
      ) {
        return {
          outcome: 'EVALUATED',
          decision: context.existingDecision,
          replayed: true
        };
      }

      const decidedAt = clock();
      if (
        !isCanonicalTimestamp(decidedAt) ||
        !context.coverageCompletedAt ||
        Date.parse(decidedAt) < Date.parse(context.coverageCompletedAt)
      ) {
        return this.reject('FRESHNESS_INPUT_INVALID');
      }
      const observed = await this.readTargetObservation(
        context,
        decidedAt
      );
      const decision = buildSastScanFreshnessDecision({
        freshnessDecisionId: deterministicId(
          'sast-freshness',
          `${context.scope.coverageDecisionId}\0${context.scope.coverageDecisionDigest}`
        ),
        coverageComplete: context.coverageComplete,
        scope: context.scope,
        observation: observed.observation,
        observationAuthority: observed.authority,
        observationMonotonic: observed.monotonic,
        comparison: context.comparison,
        decidedAt,
        digestCanonical: digest
      });
      if (!isSastScanFreshnessDecisionShapeValid(decision, digest)) {
        return this.reject('FRESHNESS_INPUT_INVALID');
      }
      const persisted = await this.store.persistFreshness({
        context,
        observation: observed.observation,
        decision
      });
      if (
        persisted.freshnessDecisionId !==
          decision.freshnessDecisionId ||
        persisted.decisionDigest !== decision.decisionDigest
      ) {
        return this.reject('FRESHNESS_PERSISTENCE_FAILED');
      }
      return {
        outcome: 'EVALUATED',
        decision,
        replayed: persisted.replayed
      };
    } catch {
      return this.reject('FRESHNESS_PERSISTENCE_FAILED');
    }
  }

  async verify(
    decision: Readonly<SastFindingLifecycleCoverageDecision>
  ): Promise<SastFindingLifecycleCoverageVerification> {
    if (
      !isSastFindingLifecycleCoverageDecisionShapeValid(
        decision,
        digest
      )
    ) {
      return 'REJECTED';
    }
    try {
      const context = await this.store.loadContext(
        decision.sourceCoverageDecisionRef
      );
      if (
        !context ||
        !(await this.targetStillCurrent(
          context,
          decision.commitSha,
          decision.decidedAt
        ))
      ) {
        return 'REJECTED';
      }
      return (await this.store.verifyLifecycleSource(decision)) ===
        'MATCHED'
        ? 'VERIFIED'
        : 'REJECTED';
    } catch {
      return 'REJECTED';
    }
  }

  async authorize(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    decidedAt: string
  ): Promise<SastRetryAdmissionVerification> {
    if (
      request.attemptNumber !== 2 ||
      !isCanonicalTimestamp(decidedAt) ||
      !isSastScannerWrapperExecutionRequestValid(request)
    ) {
      return 'REJECTED';
    }
    try {
      const context = await this.store.loadRetryContext(request);
      if (!context) return 'REJECTED';
      if (context.existingDecision) {
        return isSastScanRetryDecisionShapeValid(
          context.existingDecision,
          digest
        ) &&
          context.existingDecision.retryAllowed &&
          context.existingDecision.decidedAt === decidedAt
          ? 'AUTHORIZED'
          : 'REJECTED';
      }
      const authority = await this.retryRuntime
        .verify(context.evaluation.scope)
        .catch(() => ({
          currentScannerSetDigest: null,
          scannerSetAvailable: false,
          killSwitchStatus: 'UNAVAILABLE' as const,
          killSwitchSnapshotDigest: null
        }));
      const evaluation: SastScanRetryEvaluation = {
        ...context.evaluation,
        ...authority
      };
      const decision = buildSastScanRetryDecision({
        retryDecisionId: deterministicId(
          'sast-retry',
          `${evaluation.scope.scanRequestId}\0${evaluation.scope.requestedAttemptId}`
        ),
        evaluation,
        decidedAt,
        digestCanonical: digest
      });
      if (!isSastScanRetryDecisionShapeValid(decision, digest)) {
        return 'REJECTED';
      }
      const persisted = await this.store.persistRetryDecision({
        context,
        decision
      });
      return persisted.retryDecisionId === decision.retryDecisionId &&
        persisted.decisionDigest === decision.decisionDigest &&
        persisted.retryAllowed &&
        decision.retryAllowed
        ? 'AUTHORIZED'
        : 'REJECTED';
    } catch {
      return 'REJECTED';
    }
  }

  private async readTargetObservation(
    context: Readonly<SastScanFreshnessContext>,
    decidedAt: string
  ): Promise<{
    authority: SastLatestTargetAuthorityStatus;
    observation: SastLatestTargetObservation | null;
    monotonic: boolean;
  }> {
    let result: Awaited<ReturnType<SastLatestTargetAuthority['observe']>>;
    try {
      result = await this.latestTarget.observe(context.scope);
    } catch {
      return {
        authority: 'UNAVAILABLE',
        observation: null,
        monotonic: false
      };
    }
    if (result.status === 'UNAVAILABLE') {
      return {
        authority: 'UNAVAILABLE',
        observation: null,
        monotonic: false
      };
    }
    const core = {
      version: SAST_LATEST_TARGET_OBSERVATION_VERSION,
      observationId: deterministicId(
        'sast-target-observation',
        [
          context.scope.tenantId,
          context.scope.repositoryBindingId,
          context.scope.provider,
          context.scope.targetRef,
          result.headCommitSha,
          String(result.sequence),
          result.observerRef,
          result.observedAt
        ].join('\0')
      ),
      tenantId: context.scope.tenantId,
      repositoryBindingId: context.scope.repositoryBindingId,
      provider: context.scope.provider,
      targetRef: context.scope.targetRef,
      headCommitSha: result.headCommitSha,
      sequence: result.sequence,
      observerRef: result.observerRef,
      observedAt: result.observedAt
    };
    const observation: SastLatestTargetObservation = {
      ...core,
      observationDigest: digest(
        canonicalizeSastLatestTargetObservation(core)
      )
    };
    if (
      !isSastLatestTargetObservationShapeValid(observation, digest) ||
      !context.coverageCompletedAt ||
      Date.parse(observation.observedAt) <
        Date.parse(context.coverageCompletedAt) ||
      Date.parse(observation.observedAt) > Date.parse(decidedAt) + 5_000
    ) {
      return {
        authority: 'INVALID',
        observation: null,
        monotonic: false
      };
    }
    const previous = context.latestObservation;
    const monotonic = !previous ||
      (observation.sequence > previous.sequence &&
        Date.parse(observation.observedAt) >=
          Date.parse(previous.observedAt));
    if (!monotonic) {
      return {
        authority: 'INVALID',
        observation: null,
        monotonic: false
      };
    }
    return {
      authority: 'VERIFIED',
      observation,
      monotonic
    };
  }

  private async targetStillCurrent(
    context: Readonly<SastScanFreshnessContext>,
    commitSha: string,
    freshnessDecidedAt: string
  ): Promise<boolean> {
    try {
      const result = await this.latestTarget.observe(context.scope);
      if (
        result.status !== 'VERIFIED' ||
        !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(
          result.headCommitSha
        ) ||
        result.headCommitSha !== commitSha ||
        !Number.isSafeInteger(result.sequence) ||
        result.sequence <= 0 ||
        typeof result.observerRef !== 'string' ||
        result.observerRef.length === 0 ||
        result.observerRef.length > 2048 ||
        !isCanonicalTimestamp(result.observedAt) ||
        Date.parse(result.observedAt) < Date.parse(freshnessDecidedAt) ||
        Date.parse(result.observedAt) > Date.now() + 5_000
      ) {
        return false;
      }
      const previous = context.latestObservation;
      return !previous ||
        (result.sequence > previous.sequence &&
          Date.parse(result.observedAt) >=
            Date.parse(previous.observedAt));
    } catch {
      return false;
    }
  }

  private reject(
    reasonCode: Extract<
      SastScanFreshnessOutcome,
      { outcome: 'REJECTED' }
    >['reasonCode']
  ): SastScanFreshnessOutcome {
    return {
      outcome: 'REJECTED',
      reasonCode,
      publicationAttempted: false,
      lifecycleMutationAttempted: false,
      aiPayloadCreated: false
    };
  }
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function deterministicId(prefix: string, preimage: string): string {
  return `${prefix}://${createHash('sha256')
    .update(preimage)
    .digest('hex')}`;
}

function isCanonicalTimestamp(value: string): boolean {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString() === value;
}
