import { createHash } from 'node:crypto';

import {
  SAST_KILL_SWITCH_GATES,
  SAST_SCANNER_KINDS,
  buildSastKillSwitchDecision,
  buildSastKillSwitchContextFromPlanParts,
  buildSastKillSwitchVerification,
  isSastKillSwitchEvaluationContextValid,
  isSastKillSwitchEvaluationReceiptValid,
  isSastScanPlanValid,
  type SastKillSwitchControlDecisionInput,
  type SastKillSwitchEvaluationContext,
  type SastKillSwitchEvaluationResult,
  type SastScanPlan,
  type SastScannerKind
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import {
  SastKillSwitchGate,
  SastKillSwitchGateError,
  type SastKillSwitchContextEvaluationInput,
  type SastKillSwitchPersistedScanEvaluationInput,
  type SastKillSwitchPlanEvaluationInput
} from './sast-kill-switch.gate';
import { SastKillSwitchClock } from './sast-kill-switch.clock';
import {
  SastKillSwitchSignatureAuthority,
  SastKillSwitchSignatureAuthorityError
} from './sast-kill-switch-signature.authority';
import {
  SastKillSwitchPersistenceError,
  SastKillSwitchStore,
  type PersistedSastKillSwitchDecision
} from './sast-kill-switch.store';
import type {
  SastRuleBundleLifecycleAuthorityInput,
  SastRuleBundleLifecycleAuthorityReceipt
} from './sast-rule-bundle-lifecycle.authority';

export const MAX_BOUNDARY_CLOCK_SKEW_MILLISECONDS = 5_000;
const MAX_LIFECYCLE_CLOCK_SKEW_MILLISECONDS = 60_000;

export class SastKillSwitchServiceError extends Error {
  constructor(
    readonly reason:
      | 'INPUT_INVALID'
      | 'SIGNATURE_UNAVAILABLE'
      | 'SIGNATURE_REJECTED'
      | 'STATE_STALE'
      | 'STORE_UNAVAILABLE'
  ) {
    super('The SAST kill-switch service failed closed.');
    this.name = 'SastKillSwitchServiceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

@Injectable()
export class SastKillSwitchService extends SastKillSwitchGate {
  constructor(
    private readonly store: SastKillSwitchStore,
    private readonly signatureAuthority: SastKillSwitchSignatureAuthority,
    private readonly clock: SastKillSwitchClock
  ) {
    super();
  }

  async registerDecision(
    input: Readonly<SastKillSwitchControlDecisionInput>
  ): Promise<PersistedSastKillSwitchDecision> {
    const decision = buildSastKillSwitchDecision(input, digest);
    if (!decision) {
      throw new SastKillSwitchServiceError('INPUT_INVALID');
    }
    const verifiedAt = this.readTrustedNow();
    if (Date.parse(decision.effectiveAt) > Date.parse(verifiedAt)) {
      throw new SastKillSwitchServiceError('INPUT_INVALID');
    }
    try {
      const facts = await this.signatureAuthority.verify(decision);
      if (
        facts.signatureRef !== decision.signatureRef ||
        facts.provenanceRef !== decision.provenanceRef ||
        facts.signatureVerified !== true ||
        facts.provenanceVerified !== true ||
        facts.trustedSigner !== true ||
        facts.signatureBytesStored !== false ||
        facts.provenancePayloadStored !== false
      ) {
        throw new SastKillSwitchServiceError('SIGNATURE_REJECTED');
      }
      const verification = buildSastKillSwitchVerification(
        {
          decisionId: decision.decisionId,
          decisionDigest: decision.decisionDigest,
          selectorKey: decision.selectorKey,
          signerIdentity: facts.signerIdentity,
          signatureRef: facts.signatureRef,
          provenanceRef: facts.provenanceRef,
          verifiedAt
        },
        digest
      );
      if (!verification) {
        throw new SastKillSwitchServiceError('SIGNATURE_REJECTED');
      }
      return await this.store.appendDecision(decision, verification);
    } catch (error) {
      if (error instanceof SastKillSwitchServiceError) throw error;
      if (error instanceof SastKillSwitchSignatureAuthorityError) {
        throw new SastKillSwitchServiceError(
          error.reason === 'UNAVAILABLE'
            ? 'SIGNATURE_UNAVAILABLE'
            : 'SIGNATURE_REJECTED'
        );
      }
      if (error instanceof SastKillSwitchPersistenceError) {
        throw new SastKillSwitchServiceError(
          error.reason === 'STALE_DECISION' ||
            error.reason === 'DEACTIVATION_WITHOUT_ACTIVE_HEAD' ||
            error.reason === 'REPLAY_CONFLICT'
            ? 'STATE_STALE'
            : error.reason === 'INPUT_INVALID'
              ? 'INPUT_INVALID'
              : 'STORE_UNAVAILABLE'
        );
      }
      throw new SastKillSwitchServiceError('STORE_UNAVAILABLE');
    }
  }

  async evaluateContext(
    input: Readonly<SastKillSwitchContextEvaluationInput>
  ): Promise<SastKillSwitchEvaluationResult> {
    if (
      !SAST_KILL_SWITCH_GATES.includes(input?.gate) ||
      !isCanonicalTimestamp(input?.evaluatedAt) ||
      !isSastKillSwitchEvaluationContextValid(input?.context, digest)
    ) {
      throw new SastKillSwitchGateError('CONTEXT_INVALID');
    }
    this.assertTrustedBoundaryTime(
      input.evaluatedAt,
      MAX_BOUNDARY_CLOCK_SKEW_MILLISECONDS
    );
    try {
      const result = await this.store.evaluate(
        input.context,
        input.gate,
        input.evaluatedAt
      );
      if (
        !isSastKillSwitchEvaluationReceiptValid(
          result.receipt,
          digest
        ) ||
        result.receipt.gate !== input.gate ||
        result.receipt.contextDigest !== input.context.contextDigest ||
        result.receipt.evaluatedAt !== input.evaluatedAt
      ) {
        throw new SastKillSwitchGateError('STATE_STALE');
      }
      return result;
    } catch (error) {
      if (error instanceof SastKillSwitchGateError) throw error;
      throw mapGateError(error);
    }
  }

  async evaluatePlan(
    input: Readonly<SastKillSwitchPlanEvaluationInput>
  ): Promise<SastKillSwitchEvaluationResult> {
    const context = contextFromPlan(input?.plan, input?.scanner);
    if (!context) {
      throw new SastKillSwitchGateError('CONTEXT_INVALID');
    }
    return this.evaluateContext({
      gate: input.gate,
      context,
      evaluatedAt: input.evaluatedAt
    });
  }

  async evaluatePersistedScan(
    input: Readonly<SastKillSwitchPersistedScanEvaluationInput>
  ): Promise<SastKillSwitchEvaluationResult> {
    if (
      !input ||
      !isBounded(input.tenantId) ||
      !isBounded(input.repositoryBindingId) ||
      !isBounded(input.scanRequestId)
    ) {
      throw new SastKillSwitchGateError('CONTEXT_INVALID');
    }
    try {
      const plan = await this.store.loadPersistedPlan(input);
      if (
        !plan ||
        plan.tenantId !== input.tenantId ||
        plan.repositoryState.repositoryBindingId !==
          input.repositoryBindingId ||
        plan.scanRequestId !== input.scanRequestId
      ) {
        throw new SastKillSwitchGateError('CONTEXT_INVALID');
      }
      return await this.evaluatePlan({
        gate: input.gate,
        plan,
        evaluatedAt: input.evaluatedAt,
        ...(input.scanner ? { scanner: input.scanner } : {})
      });
    } catch (error) {
      if (error instanceof SastKillSwitchGateError) throw error;
      throw mapGateError(error);
    }
  }

  async authorizeEmergencySuspension(
    input: Readonly<SastRuleBundleLifecycleAuthorityInput>
  ): Promise<SastRuleBundleLifecycleAuthorityReceipt> {
    if (
      input.authority !== 'EMERGENCY_SUSPENSION' ||
      (input.fromState !== 'CANARY' && input.fromState !== 'ACTIVE') ||
      input.toState !== 'SUSPENDED' ||
      !isCanonicalTimestamp(input.requestedAt)
    ) {
      throw new SastKillSwitchGateError('CONTEXT_INVALID');
    }
    try {
      const trustedNow = this.readTrustedNow();
      const requestedMilliseconds = Date.parse(input.requestedAt);
      const trustedMilliseconds = Date.parse(trustedNow);
      if (
        requestedMilliseconds > trustedMilliseconds ||
        trustedMilliseconds - requestedMilliseconds >
          MAX_LIFECYCLE_CLOCK_SKEW_MILLISECONDS
      ) {
        throw new SastKillSwitchGateError('AUTHORITY_UNAVAILABLE');
      }
      const receipt = await this.store.authorizeEmergencySuspension(
        input,
        input.requestedAt
      );
      return {
        authority: 'EMERGENCY_SUSPENSION',
        manifestId: receipt.manifestId,
        manifestDigest: receipt.manifestDigest,
        bundleId: receipt.bundleId,
        bundleDigest: receipt.bundleDigest,
        fromState: receipt.fromState,
        toState: receipt.toState,
        promotionEvidenceId: receipt.promotionEvidenceId,
        promotionEvidenceDigest: receipt.promotionEvidenceDigest,
        requestedAt: receipt.requestedAt,
        receiptRef: receipt.receiptRef,
        receiptDigest: receipt.receiptDigest,
        verifiedAt: receipt.verifiedAt
      };
    } catch (error) {
      if (error instanceof SastKillSwitchGateError) throw error;
      throw mapGateError(error);
    }
  }

  private readTrustedNow(): string {
    try {
      const value = this.clock.now();
      const milliseconds = Date.prototype.getTime.call(value);
      if (!Number.isFinite(milliseconds)) {
        throw new Error('invalid clock');
      }
      return new Date(milliseconds).toISOString();
    } catch {
      throw new SastKillSwitchServiceError('STORE_UNAVAILABLE');
    }
  }

  private assertTrustedBoundaryTime(
    evaluatedAt: string,
    maximumSkewMilliseconds: number
  ): void {
    let trustedNow: string;
    try {
      trustedNow = this.readTrustedNow();
    } catch {
      throw new SastKillSwitchGateError('AUTHORITY_UNAVAILABLE');
    }
    const evaluatedMilliseconds = Date.parse(evaluatedAt);
    const trustedMilliseconds = Date.parse(trustedNow);
    if (
      evaluatedMilliseconds > trustedMilliseconds ||
      trustedMilliseconds - evaluatedMilliseconds > maximumSkewMilliseconds
    ) {
      throw new SastKillSwitchGateError('AUTHORITY_UNAVAILABLE');
    }
  }
}

export function contextFromPlan(
  plan: Readonly<SastScanPlan>,
  onlyScanner?: SastScannerKind
): SastKillSwitchEvaluationContext | null {
  if (
    !isSastScanPlanValid(plan) ||
    (onlyScanner !== undefined &&
      !SAST_SCANNER_KINDS.includes(onlyScanner))
  ) {
    return null;
  }
  return buildSastKillSwitchContextFromPlanParts(
    {
      tenantId: plan.tenantId,
      repositoryBindingId:
        plan.repositoryState.repositoryBindingId,
      scanRequestId: plan.scanRequestId,
      profile: plan.profile,
      profileDigest: plan.profileDigest,
      scannerSet: plan.scannerSet
    },
    digest,
    onlyScanner
  );
}

function mapGateError(error: unknown): SastKillSwitchGateError {
  if (error instanceof SastKillSwitchPersistenceError) {
    switch (error.reason) {
      case 'ACTIVE_DECISION_EXPIRED':
      case 'AUTHORITY_UNAVAILABLE':
        return new SastKillSwitchGateError('AUTHORITY_UNAVAILABLE');
      case 'STALE_DECISION':
      case 'REPLAY_CONFLICT':
      case 'LEDGER_CORRUPT':
        return new SastKillSwitchGateError('STATE_STALE');
      case 'INPUT_INVALID':
      case 'PLAN_NOT_FOUND':
      case 'PLAN_SCOPE_MISMATCH':
      case 'LIFECYCLE_NOT_FOUND':
      case 'LIFECYCLE_SCOPE_MISMATCH':
      case 'NO_ACTIVE_SUSPENSION_DECISION':
      case 'DEACTIVATION_WITHOUT_ACTIVE_HEAD':
        return new SastKillSwitchGateError('CONTEXT_INVALID');
    }
  }
  return new SastKillSwitchGateError('STORE_UNAVAILABLE');
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return (
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value
  );
}

function isBounded(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 512;
}
