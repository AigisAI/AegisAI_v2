import { ConflictException, Injectable } from '@nestjs/common';
import {
  evaluateSastQueueAdmission,
  type SastQueueAdmissionDecision,
  type SastQueuePolicySet,
  type SastQueueUsageSnapshot,
  type SastScanLane
} from '@aegisai/shared';

interface SastQueueReservationInput {
  scanRequestId: string;
  canonicalScanKey: `sha256:${string}`;
  lane: SastScanLane;
  tenantId: string;
  repositoryBindingId: string;
  requestedAt: string;
  policySet: SastQueuePolicySet;
  usage: SastQueueUsageSnapshot;
}

interface SastQueueReservation {
  canonicalScanKey: `sha256:${string}`;
  lane: SastScanLane;
  tenantId: string;
  repositoryBindingId: string;
  queuePolicyVersion: string;
  queuePolicyDigest: `sha256:${string}`;
  decision: SastQueueAdmissionDecision;
}

interface TenantQueueUsage {
  activeForTenant: number;
  queuedForTenant: number;
  admittedTodayForTenant: number;
}

interface RepositoryQueueUsage {
  activeForRepository: number;
  lastRepositoryAdmissionAt?: string;
}

interface LaneWindowLedger {
  snapshotVersion: number;
  queuedInLane: number;
  tenants: Map<string, TenantQueueUsage>;
  repositories: Map<string, RepositoryQueueUsage>;
}

@Injectable()
export class SastQueueAdmissionService {
  private readonly ledgers = new Map<string, LaneWindowLedger>();
  private readonly reservations = new Map<string, SastQueueReservation>();

  reserve(input: SastQueueReservationInput): SastQueueAdmissionDecision {
    const existingReservation = this.reservations.get(input.scanRequestId);
    if (existingReservation) {
      this.assertReservationIdentity(existingReservation, input);
      return this.cloneDecision(existingReservation.decision);
    }

    const evaluated = evaluateSastQueueAdmission({
      lane: input.lane,
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      requestedAt: input.requestedAt,
      policySet: input.policySet,
      usage: input.usage
    });
    if (evaluated.state !== 'ADMITTED') {
      return evaluated;
    }

    if (input.usage.snapshotVersion === Number.MAX_SAFE_INTEGER) {
      return this.invalidUsageDecision(input.policySet);
    }

    const ledgerKey = this.scopeKey(input.lane, input.usage.dailyWindowStartedAt);
    const existingLedger = this.ledgers.get(ledgerKey);
    const tenantUsage = existingLedger?.tenants.get(input.tenantId);
    const repositoryKey = this.scopeKey(input.tenantId, input.repositoryBindingId);
    const repositoryUsage = existingLedger?.repositories.get(repositoryKey);

    if (
      existingLedger &&
      (input.usage.snapshotVersion !== existingLedger.snapshotVersion ||
        input.usage.queuedInLane !== existingLedger.queuedInLane ||
        (tenantUsage !== undefined && !this.matchesTenantUsage(tenantUsage, input.usage)) ||
        (repositoryUsage !== undefined &&
          !this.matchesRepositoryUsage(repositoryUsage, input.usage)))
    ) {
      return this.staleUsageDecision(input.policySet, input.lane);
    }

    const ledger =
      existingLedger ??
      {
        snapshotVersion: input.usage.snapshotVersion,
        queuedInLane: input.usage.queuedInLane,
        tenants: new Map<string, TenantQueueUsage>(),
        repositories: new Map<string, RepositoryQueueUsage>()
      };
    const authoritativeTenantUsage = tenantUsage ?? {
      activeForTenant: input.usage.activeForTenant,
      queuedForTenant: input.usage.queuedForTenant,
      admittedTodayForTenant: input.usage.admittedTodayForTenant
    };
    const authoritativeRepositoryUsage = repositoryUsage ?? {
      activeForRepository: input.usage.activeForRepository,
      lastRepositoryAdmissionAt: input.usage.lastRepositoryAdmissionAt
    };

    authoritativeTenantUsage.queuedForTenant += 1;
    authoritativeTenantUsage.admittedTodayForTenant += 1;
    authoritativeRepositoryUsage.lastRepositoryAdmissionAt = input.requestedAt;
    ledger.queuedInLane += 1;
    ledger.snapshotVersion += 1;
    ledger.tenants.set(input.tenantId, authoritativeTenantUsage);
    ledger.repositories.set(repositoryKey, authoritativeRepositoryUsage);
    this.ledgers.set(ledgerKey, ledger);

    const decision = this.cloneDecision(evaluated);
    this.reservations.set(input.scanRequestId, {
      canonicalScanKey: input.canonicalScanKey,
      lane: input.lane,
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      queuePolicyVersion: input.policySet.policyVersion,
      queuePolicyDigest: input.policySet.digest,
      decision
    });

    return this.cloneDecision(decision);
  }

  private assertReservationIdentity(
    reservation: SastQueueReservation,
    input: SastQueueReservationInput
  ): void {
    if (
      reservation.canonicalScanKey !== input.canonicalScanKey ||
      reservation.lane !== input.lane ||
      reservation.tenantId !== input.tenantId ||
      reservation.repositoryBindingId !== input.repositoryBindingId ||
      reservation.queuePolicyVersion !== input.policySet.policyVersion ||
      reservation.queuePolicyDigest !== input.policySet.digest
    ) {
      throw new ConflictException('An admitted SAST queue reservation is immutable.');
    }
  }

  private matchesTenantUsage(
    authoritative: TenantQueueUsage,
    observed: SastQueueUsageSnapshot
  ): boolean {
    return (
      authoritative.activeForTenant === observed.activeForTenant &&
      authoritative.queuedForTenant === observed.queuedForTenant &&
      authoritative.admittedTodayForTenant === observed.admittedTodayForTenant
    );
  }

  private matchesRepositoryUsage(
    authoritative: RepositoryQueueUsage,
    observed: SastQueueUsageSnapshot
  ): boolean {
    return (
      authoritative.activeForRepository === observed.activeForRepository &&
      this.timestampsEqual(
        authoritative.lastRepositoryAdmissionAt,
        observed.lastRepositoryAdmissionAt
      )
    );
  }

  private timestampsEqual(left?: string, right?: string): boolean {
    if (left === undefined || right === undefined) {
      return left === right;
    }

    return Date.parse(left) === Date.parse(right);
  }

  private staleUsageDecision(
    policySet: SastQueuePolicySet,
    lane: SastScanLane
  ): SastQueueAdmissionDecision {
    const policy = policySet.lanes[lane];
    return {
      state: 'DEFERRED',
      queueName: policy.queueName,
      queuePolicyVersion: policySet.policyVersion,
      queuePolicyDigest: policySet.digest,
      reasonCodes: ['QUEUE_USAGE_STALE'],
      retryAfterSeconds: policy.capacityRetrySeconds
    };
  }

  private invalidUsageDecision(policySet: SastQueuePolicySet): SastQueueAdmissionDecision {
    return {
      state: 'REJECTED',
      queuePolicyVersion: policySet.policyVersion,
      queuePolicyDigest: policySet.digest,
      reasonCodes: ['QUEUE_USAGE_INVALID']
    };
  }

  private cloneDecision(decision: SastQueueAdmissionDecision): SastQueueAdmissionDecision {
    return { ...decision, reasonCodes: [...decision.reasonCodes] };
  }

  private scopeKey(...parts: string[]): string {
    return JSON.stringify(parts);
  }
}
