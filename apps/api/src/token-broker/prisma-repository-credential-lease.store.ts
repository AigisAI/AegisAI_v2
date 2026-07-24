import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import type { SastCredentialLeaseMetadata } from '@aegisai/shared';

import { PrismaService } from '../prisma/prisma.service';
import {
  RepositoryCredentialLeaseStore,
  type ReserveRepositoryCredentialLeaseInput
} from './repository-credential-lease.store';

@Injectable()
export class PrismaRepositoryCredentialLeaseStore extends RepositoryCredentialLeaseStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async reserve(
    input: ReserveRepositoryCredentialLeaseInput
  ): Promise<SastCredentialLeaseMetadata> {
    try {
      const row = await this.prisma.$transaction(
        async (transaction) => {
          const scanRequest = await transaction.scanRequest.findFirst({
            where: {
              id: input.scanRequestId,
              tenantId: input.tenantId,
              repositoryBindingId: input.repositoryBindingId,
              commitSha: input.commitSha,
              status: 'RUNNING',
              repositoryBinding: {
                status: 'ACTIVE',
                integration: { status: 'ACTIVE' }
              }
            }
          });
          if (!scanRequest) {
            throw new ConflictException(
              'Credential lease scope does not match an active durable scan request.'
            );
          }

          return transaction.sastRepositoryCredentialLease.create({
            data: {
              id: input.credentialId,
              tenantId: input.tenantId,
              repositoryBindingId: input.repositoryBindingId,
              scanRequestId: input.scanRequestId,
              attemptId: input.attemptId,
              workloadIdentityRef: input.workloadIdentityRef,
              commitSha: input.commitSha,
              issuedAt: new Date(input.issuedAt),
              expiresAt: new Date(input.expiresAt)
            }
          });
        },
        { isolationLevel: Prisma.TransactionIsolationLevel.Serializable }
      );
      return this.toMetadata(row);
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('A credential was already reserved for this scan attempt.');
      }
      throw error;
    }
  }

  async activate(
    credentialId: string,
    tenantId: string,
    attemptId: string,
    credentialFingerprint: `sha256:${string}`
  ): Promise<SastCredentialLeaseMetadata> {
    const updated = await this.prisma.sastRepositoryCredentialLease.updateMany({
      where: {
        id: credentialId,
        tenantId,
        attemptId,
        status: 'RESERVED'
      },
      data: { status: 'ISSUED', credentialFingerprint }
    });
    if (updated.count !== 1) {
      throw new ConflictException('Credential lease is not in the reserved state.');
    }
    return this.requireAttemptLease(credentialId, tenantId, attemptId);
  }

  async markWiped(
    credentialId: string,
    tenantId: string,
    attemptId: string,
    wipedAt: string
  ): Promise<SastCredentialLeaseMetadata> {
    const updated = await this.prisma.sastRepositoryCredentialLease.updateMany({
      where: { id: credentialId, tenantId, attemptId, status: 'ISSUED' },
      data: { status: 'WIPED', wipedAt: new Date(wipedAt) }
    });
    if (updated.count === 1) {
      return this.requireAttemptLease(credentialId, tenantId, attemptId);
    }

    const existing = await this.findAttemptLease(credentialId, tenantId, attemptId);
    if (!existing) {
      throw new NotFoundException('Credential lease not found for attempt.');
    }
    if (existing.status === 'WIPED') {
      return this.toMetadata(existing);
    }
    throw new ConflictException('Only an issued credential lease can be marked wiped.');
  }

  async revoke(
    credentialId: string,
    tenantId: string,
    attemptId: string,
    revokedAt: string
  ): Promise<SastCredentialLeaseMetadata> {
    const updated = await this.prisma.sastRepositoryCredentialLease.updateMany({
      where: {
        id: credentialId,
        tenantId,
        attemptId,
        status: { in: ['RESERVED', 'ISSUED'] }
      },
      data: { status: 'REVOKED', revokedAt: new Date(revokedAt) }
    });
    if (updated.count === 1) {
      return this.requireAttemptLease(credentialId, tenantId, attemptId);
    }

    const existing = await this.findAttemptLease(credentialId, tenantId, attemptId);
    if (!existing) {
      throw new NotFoundException('Credential lease not found for attempt.');
    }
    if (existing.status === 'REVOKED' || existing.status === 'WIPED') {
      return this.toMetadata(existing);
    }
    throw new ConflictException('Credential lease cannot be revoked from its current state.');
  }

  async revokeExpired(referenceTime: string): Promise<number> {
    const timestamp = new Date(referenceTime);
    if (!Number.isFinite(timestamp.getTime())) {
      throw new Error('Credential lease expiry reference time is invalid.');
    }
    const updated = await this.prisma.sastRepositoryCredentialLease.updateMany({
      where: {
        status: { in: ['RESERVED', 'ISSUED'] },
        expiresAt: { lte: timestamp }
      },
      data: {
        status: 'REVOKED',
        revokedAt: timestamp
      }
    });
    return updated.count;
  }

  async findByAttempt(
    tenantId: string,
    attemptId: string
  ): Promise<SastCredentialLeaseMetadata | null> {
    const row = await this.prisma.sastRepositoryCredentialLease.findFirst({
      where: { tenantId, attemptId }
    });
    return row ? this.toMetadata(row) : null;
  }

  private async requireAttemptLease(
    credentialId: string,
    tenantId: string,
    attemptId: string
  ): Promise<SastCredentialLeaseMetadata> {
    const row = await this.findAttemptLease(credentialId, tenantId, attemptId);
    if (!row) {
      throw new NotFoundException('Credential lease not found for attempt.');
    }
    return this.toMetadata(row);
  }

  private findAttemptLease(
    credentialId: string,
    tenantId: string,
    attemptId: string
  ) {
    return this.prisma.sastRepositoryCredentialLease.findFirst({
      where: { id: credentialId, tenantId, attemptId }
    });
  }

  private toMetadata(row: {
    id: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    workloadIdentityRef: string;
    commitSha: string;
    credentialFingerprint: string | null;
    status: 'RESERVED' | 'ISSUED' | 'WIPED' | 'REVOKED';
    issuedAt: Date;
    expiresAt: Date;
    wipedAt: Date | null;
    revokedAt: Date | null;
  }): SastCredentialLeaseMetadata {
    return {
      credentialId: row.id,
      tenantId: row.tenantId,
      repositoryBindingId: row.repositoryBindingId,
      scanRequestId: row.scanRequestId,
      attemptId: row.attemptId,
      workloadIdentityRef: row.workloadIdentityRef,
      commitSha: row.commitSha,
      credentialFingerprint:
        (row.credentialFingerprint as `sha256:${string}` | null) ?? undefined,
      status: row.status,
      issuedAt: row.issuedAt.toISOString(),
      expiresAt: row.expiresAt.toISOString(),
      wipedAt: row.wipedAt?.toISOString(),
      revokedAt: row.revokedAt?.toISOString()
    };
  }
}
