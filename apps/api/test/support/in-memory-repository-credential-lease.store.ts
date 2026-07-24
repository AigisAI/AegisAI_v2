import { ConflictException, NotFoundException } from '@nestjs/common';
import type { SastCredentialLeaseMetadata } from '@aegisai/shared';

import {
  RepositoryCredentialLeaseStore,
  type ReserveRepositoryCredentialLeaseInput
} from '../../src/token-broker/repository-credential-lease.store';

export class InMemoryRepositoryCredentialLeaseStore extends RepositoryCredentialLeaseStore {
  private readonly leases = new Map<string, SastCredentialLeaseMetadata>();
  private lockTail: Promise<void> = Promise.resolve();

  async reserve(
    input: ReserveRepositoryCredentialLeaseInput
  ): Promise<SastCredentialLeaseMetadata> {
    return this.exclusive(() => {
      if (Array.from(this.leases.values()).some((lease) => lease.attemptId === input.attemptId)) {
        throw new ConflictException('A credential was already reserved for this scan attempt.');
      }
      const lease: SastCredentialLeaseMetadata = {
        credentialId: input.credentialId,
        tenantId: input.tenantId,
        repositoryBindingId: input.repositoryBindingId,
        scanRequestId: input.scanRequestId,
        attemptId: input.attemptId,
        workloadIdentityRef: input.workloadIdentityRef,
        commitSha: input.commitSha,
        status: 'RESERVED',
        issuedAt: input.issuedAt,
        expiresAt: input.expiresAt
      };
      this.leases.set(lease.credentialId, lease);
      return this.clone(lease);
    });
  }

  async activate(
    credentialId: string,
    tenantId: string,
    attemptId: string,
    credentialFingerprint: `sha256:${string}`
  ): Promise<SastCredentialLeaseMetadata> {
    return this.exclusive(() => {
      const lease = this.requireAttempt(credentialId, tenantId, attemptId);
      if (lease.status !== 'RESERVED') {
        throw new ConflictException('Credential lease is not in the reserved state.');
      }
      lease.status = 'ISSUED';
      lease.credentialFingerprint = credentialFingerprint;
      return this.clone(lease);
    });
  }

  async markWiped(
    credentialId: string,
    tenantId: string,
    attemptId: string,
    wipedAt: string
  ): Promise<SastCredentialLeaseMetadata> {
    return this.exclusive(() => {
      const lease = this.requireAttempt(credentialId, tenantId, attemptId);
      if (lease.status === 'WIPED') {
        return this.clone(lease);
      }
      if (lease.status !== 'ISSUED') {
        throw new ConflictException('Only an issued credential lease can be marked wiped.');
      }
      lease.status = 'WIPED';
      lease.wipedAt = wipedAt;
      return this.clone(lease);
    });
  }

  async revoke(
    credentialId: string,
    tenantId: string,
    attemptId: string,
    revokedAt: string
  ): Promise<SastCredentialLeaseMetadata> {
    return this.exclusive(() => {
      const lease = this.requireAttempt(credentialId, tenantId, attemptId);
      if (lease.status !== 'WIPED') {
        lease.status = 'REVOKED';
        lease.revokedAt = revokedAt;
      }
      return this.clone(lease);
    });
  }

  async findByAttempt(
    tenantId: string,
    attemptId: string
  ): Promise<SastCredentialLeaseMetadata | null> {
    const lease = Array.from(this.leases.values()).find(
      (candidate) =>
        candidate.tenantId === tenantId && candidate.attemptId === attemptId
    );
    return lease ? this.clone(lease) : null;
  }

  private require(credentialId: string): SastCredentialLeaseMetadata {
    const lease = this.leases.get(credentialId);
    if (!lease) {
      throw new NotFoundException('Credential lease not found.');
    }
    return lease;
  }

  private requireAttempt(
    credentialId: string,
    tenantId: string,
    attemptId: string
  ): SastCredentialLeaseMetadata {
    const lease = this.require(credentialId);
    if (lease.tenantId !== tenantId || lease.attemptId !== attemptId) {
      throw new NotFoundException('Credential lease not found for attempt.');
    }
    return lease;
  }

  private clone(lease: SastCredentialLeaseMetadata): SastCredentialLeaseMetadata {
    return { ...lease };
  }

  private async exclusive<T>(operation: () => T | Promise<T>): Promise<T> {
    const predecessor = this.lockTail;
    let release!: () => void;
    this.lockTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await predecessor;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}
