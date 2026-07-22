import {
  orderSastQueueCandidatesFairly,
  type SastQueueAdmissionDecision
} from '@aegisai/shared';

import {
  SastQueueAdmissionStore,
  type SastQueueDispatchAcknowledgementInput,
  type SastQueueDispatchClaim,
  type SastQueueDispatchClaimInput,
  type SastQueueReservationInput,
  type SastQueueReservationRecord,
  type SastQueueReservationWriteResult
} from '../../src/control-plane/sast-queue-admission.store';

interface TenantUsage {
  activeForTenant: number;
  queuedForTenant: number;
  admittedTodayForTenant: number;
}

interface RepositoryUsage {
  activeForRepository: number;
  lastRepositoryAdmissionAt?: string;
}

interface Ledger {
  snapshotVersion: number;
  queuedInLane: number;
  lastServedTenantId?: string;
  tenants: Map<string, TenantUsage>;
  repositories: Map<string, RepositoryUsage>;
}

interface ReservationState extends SastQueueReservationRecord {
  dispatchLeaseOwner?: string;
  dispatchLeaseExpiresAt?: string;
  publishedAt?: string;
}

export class InMemorySastQueueAdmissionStore extends SastQueueAdmissionStore {
  private readonly ledgers = new Map<string, Ledger>();
  private readonly reservations = new Map<string, ReservationState>();
  private lockTail: Promise<void> = Promise.resolve();

  async findReservation(scanRequestId: string): Promise<SastQueueReservationRecord | null> {
    const reservation = this.reservations.get(scanRequestId);
    return reservation ? this.cloneReservation(reservation) : null;
  }

  async reserveAdmitted(
    input: SastQueueReservationInput,
    decision: SastQueueAdmissionDecision
  ): Promise<SastQueueReservationWriteResult> {
    return this.exclusive(() => {
      const existing = this.reservations.get(input.scanRequestId);
      if (existing) {
        return { state: 'EXISTING', reservation: this.cloneReservation(existing) };
      }

      const dailyWindowStartedAt = this.normalizeTimestamp(input.usage.dailyWindowStartedAt);
      const ledgerKey = this.ledgerKey(input.lane, dailyWindowStartedAt);
      const existingLedger = this.ledgers.get(ledgerKey);
      const tenantUsage = existingLedger?.tenants.get(input.tenantId);
      const repositoryKey = this.repositoryKey(input.tenantId, input.repositoryBindingId);
      const repositoryUsage = existingLedger?.repositories.get(repositoryKey);

      if (
        existingLedger &&
        (input.usage.snapshotVersion !== existingLedger.snapshotVersion ||
          input.usage.queuedInLane !== existingLedger.queuedInLane ||
          (tenantUsage !== undefined && !this.matchesTenantUsage(tenantUsage, input)) ||
          (repositoryUsage !== undefined &&
            !this.matchesRepositoryUsage(repositoryUsage, input)))
      ) {
        return { state: 'STALE' };
      }

      const ledger =
        existingLedger ??
        {
          snapshotVersion: input.usage.snapshotVersion,
          queuedInLane: input.usage.queuedInLane,
          tenants: new Map<string, TenantUsage>(),
          repositories: new Map<string, RepositoryUsage>()
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
      authoritativeRepositoryUsage.lastRepositoryAdmissionAt = this.normalizeTimestamp(
        input.requestedAt
      );
      ledger.queuedInLane += 1;
      ledger.snapshotVersion += 1;
      ledger.tenants.set(input.tenantId, authoritativeTenantUsage);
      ledger.repositories.set(repositoryKey, authoritativeRepositoryUsage);
      this.ledgers.set(ledgerKey, ledger);

      const storedDecision = this.cloneDecision(decision);
      const reservation: ReservationState = {
        scanRequestId: input.scanRequestId,
        canonicalScanKey: input.canonicalScanKey,
        lane: input.lane,
        tenantId: input.tenantId,
        repositoryBindingId: input.repositoryBindingId,
        queuePolicyVersion: input.policySet.policyVersion,
        queuePolicyDigest: input.policySet.digest,
        dailyWindowStartedAt,
        enqueuedAt: this.normalizeTimestamp(input.requestedAt),
        decision: storedDecision
      };
      this.reservations.set(input.scanRequestId, reservation);

      return { state: 'RESERVED', reservation: this.cloneReservation(reservation) };
    });
  }

  async claimNextForDispatch(
    input: SastQueueDispatchClaimInput
  ): Promise<SastQueueDispatchClaim | null> {
    return this.exclusive(() => {
      const claimedAt = this.normalizeTimestamp(input.claimedAt);
      const dailyWindowStartedAt = this.normalizeTimestamp(input.dailyWindowStartedAt);
      const ledger = this.ledgers.get(this.ledgerKey(input.lane, dailyWindowStartedAt));
      if (!ledger) {
        return null;
      }

      const existingClaim = Array.from(this.reservations.values())
        .filter(
          (reservation) =>
            reservation.lane === input.lane &&
            reservation.dailyWindowStartedAt === dailyWindowStartedAt &&
            reservation.publishedAt === undefined &&
            reservation.dispatchLeaseOwner === input.workerId &&
            Date.parse(reservation.dispatchLeaseExpiresAt ?? '') > Date.parse(claimedAt)
        )
        .sort(this.compareReservations)[0];
      if (existingClaim) {
        return this.toDispatchClaim(existingClaim);
      }

      const available = Array.from(this.reservations.values()).filter(
        (reservation) =>
          reservation.lane === input.lane &&
          reservation.dailyWindowStartedAt === dailyWindowStartedAt &&
          reservation.publishedAt === undefined &&
          (reservation.dispatchLeaseExpiresAt === undefined ||
            Date.parse(reservation.dispatchLeaseExpiresAt) <= Date.parse(claimedAt))
      );
      const ordered = orderSastQueueCandidatesFairly(
        input.lane,
        available.map((reservation) => ({
          lane: reservation.lane,
          tenantId: reservation.tenantId,
          scanRequestId: reservation.scanRequestId,
          enqueuedAt: reservation.enqueuedAt
        })),
        ledger.lastServedTenantId
      );
      const next = ordered[0];
      if (!next) {
        return null;
      }

      const reservation = this.reservations.get(next.scanRequestId)!;
      reservation.dispatchLeaseOwner = input.workerId;
      reservation.dispatchLeaseExpiresAt = new Date(
        Date.parse(claimedAt) + input.leaseSeconds * 1000
      ).toISOString();
      ledger.lastServedTenantId = reservation.tenantId;

      return this.toDispatchClaim(reservation);
    });
  }

  async acknowledgeDispatch(
    input: SastQueueDispatchAcknowledgementInput
  ): Promise<boolean> {
    return this.exclusive(() => {
      const reservation = this.reservations.get(input.scanRequestId);
      if (!reservation || reservation.dispatchLeaseOwner !== input.workerId) {
        return false;
      }
      if (reservation.publishedAt !== undefined) {
        return true;
      }
      if (
        reservation.dispatchLeaseExpiresAt === undefined ||
        Date.parse(reservation.dispatchLeaseExpiresAt) < Date.parse(input.acknowledgedAt)
      ) {
        return false;
      }

      reservation.publishedAt = this.normalizeTimestamp(input.acknowledgedAt);
      return true;
    });
  }

  private async exclusive<T>(operation: () => T): Promise<T> {
    const previous = this.lockTail;
    let release!: () => void;
    this.lockTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;

    try {
      return operation();
    } finally {
      release();
    }
  }

  private matchesTenantUsage(
    authoritative: TenantUsage,
    input: SastQueueReservationInput
  ): boolean {
    return (
      authoritative.activeForTenant === input.usage.activeForTenant &&
      authoritative.queuedForTenant === input.usage.queuedForTenant &&
      authoritative.admittedTodayForTenant === input.usage.admittedTodayForTenant
    );
  }

  private matchesRepositoryUsage(
    authoritative: RepositoryUsage,
    input: SastQueueReservationInput
  ): boolean {
    return (
      authoritative.activeForRepository === input.usage.activeForRepository &&
      this.timestampsEqual(
        authoritative.lastRepositoryAdmissionAt,
        input.usage.lastRepositoryAdmissionAt
      )
    );
  }

  private timestampsEqual(left?: string, right?: string): boolean {
    if (left === undefined || right === undefined) {
      return left === right;
    }

    return Date.parse(left) === Date.parse(right);
  }

  private toDispatchClaim(reservation: ReservationState): SastQueueDispatchClaim {
    if (
      !reservation.decision.queueName ||
      !reservation.dispatchLeaseOwner ||
      !reservation.dispatchLeaseExpiresAt
    ) {
      throw new Error('Test SAST queue reservation is not dispatchable.');
    }

    return {
      scanRequestId: reservation.scanRequestId,
      canonicalScanKey: reservation.canonicalScanKey,
      lane: reservation.lane,
      tenantId: reservation.tenantId,
      repositoryBindingId: reservation.repositoryBindingId,
      queueName: reservation.decision.queueName,
      queuePolicyVersion: reservation.queuePolicyVersion,
      queuePolicyDigest: reservation.queuePolicyDigest,
      enqueuedAt: reservation.enqueuedAt,
      leaseOwner: reservation.dispatchLeaseOwner,
      leaseExpiresAt: reservation.dispatchLeaseExpiresAt
    };
  }

  private cloneReservation(reservation: ReservationState): SastQueueReservationRecord {
    return {
      scanRequestId: reservation.scanRequestId,
      canonicalScanKey: reservation.canonicalScanKey,
      lane: reservation.lane,
      tenantId: reservation.tenantId,
      repositoryBindingId: reservation.repositoryBindingId,
      queuePolicyVersion: reservation.queuePolicyVersion,
      queuePolicyDigest: reservation.queuePolicyDigest,
      dailyWindowStartedAt: reservation.dailyWindowStartedAt,
      enqueuedAt: reservation.enqueuedAt,
      decision: this.cloneDecision(reservation.decision)
    };
  }

  private cloneDecision(decision: SastQueueAdmissionDecision): SastQueueAdmissionDecision {
    return { ...decision, reasonCodes: [...decision.reasonCodes] };
  }

  private compareReservations(left: ReservationState, right: ReservationState): number {
    const timestampOrder = Date.parse(left.enqueuedAt) - Date.parse(right.enqueuedAt);
    return timestampOrder === 0
      ? left.scanRequestId.localeCompare(right.scanRequestId)
      : timestampOrder;
  }

  private normalizeTimestamp(value: string): string {
    return new Date(value).toISOString();
  }

  private ledgerKey(lane: 'FAST' | 'DEEP', dailyWindowStartedAt: string): string {
    return JSON.stringify([lane, dailyWindowStartedAt]);
  }

  private repositoryKey(tenantId: string, repositoryBindingId: string): string {
    return JSON.stringify([tenantId, repositoryBindingId]);
  }
}
