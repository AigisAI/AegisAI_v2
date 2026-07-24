import { ConflictException } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaRepositoryCredentialLeaseStore } from '../../src/token-broker/prisma-repository-credential-lease.store';
import type { PrismaService } from '../../src/prisma/prisma.service';

describe('PrismaRepositoryCredentialLeaseStore', () => {
  const issuedAt = new Date('2026-07-24T00:00:00.000Z');
  const expiresAt = new Date('2026-07-24T00:02:00.000Z');
  const baseRow = () => ({
    id: 'credential-1',
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    workloadIdentityRef: 'spiffe://aegisai/scan/attempt-1',
    commitSha: 'a'.repeat(40),
    credentialFingerprint: null as string | null,
    status: 'RESERVED' as 'RESERVED' | 'ISSUED' | 'WIPED' | 'REVOKED',
    issuedAt,
    expiresAt,
    wipedAt: null as Date | null,
    revokedAt: null as Date | null
  });
  const reserveInput = {
    credentialId: 'credential-1',
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    workloadIdentityRef: 'spiffe://aegisai/scan/attempt-1',
    commitSha: 'a'.repeat(40),
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString()
  };

  it('reserves only against an active durable scan scope and records no secret value', async () => {
    const row = baseRow();
    const transaction = {
      scanRequest: { findFirst: jest.fn().mockResolvedValue({ id: 'scan-1' }) },
      sastRepositoryCredentialLease: {
        create: jest.fn().mockResolvedValue(row)
      }
    };
    const prisma = {
      $transaction: jest.fn(
        async (operation: (client: typeof transaction) => Promise<unknown>) =>
          operation(transaction)
      )
    };
    const store = new PrismaRepositoryCredentialLeaseStore(
      prisma as unknown as PrismaService
    );

    await expect(store.reserve(reserveInput)).resolves.toEqual({
      credentialId: 'credential-1',
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      scanRequestId: 'scan-1',
      attemptId: 'attempt-1',
      workloadIdentityRef: 'spiffe://aegisai/scan/attempt-1',
      commitSha: 'a'.repeat(40),
      status: 'RESERVED',
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      wipedAt: undefined,
      revokedAt: undefined
    });
    expect(transaction.scanRequest.findFirst).toHaveBeenCalledWith({
      where: expect.objectContaining({
        id: 'scan-1',
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        commitSha: 'a'.repeat(40),
        status: 'RUNNING',
        repositoryBinding: {
          status: 'ACTIVE',
          integration: { status: 'ACTIVE' }
        }
      })
    });
    expect(JSON.stringify(transaction.sastRepositoryCredentialLease.create.mock.calls)).not.toMatch(
      /credentialValue|accessToken|refreshToken|secretValue/
    );
  });

  it('fails closed for inactive scope and duplicate attempt reservation', async () => {
    const inactiveTransaction = {
      scanRequest: { findFirst: jest.fn().mockResolvedValue(null) },
      sastRepositoryCredentialLease: { create: jest.fn() }
    };
    const inactiveStore = new PrismaRepositoryCredentialLeaseStore({
      $transaction: jest.fn(
        async (operation: (client: typeof inactiveTransaction) => Promise<unknown>) =>
          operation(inactiveTransaction)
      )
    } as unknown as PrismaService);
    await expect(inactiveStore.reserve(reserveInput)).rejects.toBeInstanceOf(
      ConflictException
    );

    const duplicate = new Prisma.PrismaClientKnownRequestError('duplicate attempt', {
      code: 'P2002',
      clientVersion: '5.22.0',
      meta: { target: ['attemptId'] }
    });
    const duplicateTransaction = {
      scanRequest: { findFirst: jest.fn().mockResolvedValue({ id: 'scan-1' }) },
      sastRepositoryCredentialLease: {
        create: jest.fn().mockRejectedValue(duplicate)
      }
    };
    const duplicateStore = new PrismaRepositoryCredentialLeaseStore({
      $transaction: jest.fn(
        async (operation: (client: typeof duplicateTransaction) => Promise<unknown>) =>
          operation(duplicateTransaction)
      )
    } as unknown as PrismaService);
    await expect(duplicateStore.reserve(reserveInput)).rejects.toThrow(
      'already reserved'
    );
  });

  it('allows only monotonic RESERVED to ISSUED to WIPED lifecycle updates', async () => {
    const row = baseRow();
    const delegate = {
      updateMany: jest.fn().mockImplementation(
        async ({ data }: { data: Record<string, unknown> }) => {
          if (data.status === 'ISSUED') {
            row.status = 'ISSUED';
            row.credentialFingerprint = data.credentialFingerprint as string;
          }
          if (data.status === 'WIPED') {
            row.status = 'WIPED';
            row.wipedAt = data.wipedAt as Date;
          }
          if (data.status === 'REVOKED') {
            row.status = 'REVOKED';
            row.revokedAt = data.revokedAt as Date;
          }
          return { count: 1 };
        }
      ),
      findUnique: jest.fn().mockImplementation(async () => row),
      findFirst: jest.fn().mockImplementation(async () => row)
    };
    const store = new PrismaRepositoryCredentialLeaseStore({
      sastRepositoryCredentialLease: delegate
    } as unknown as PrismaService);

    await expect(
      store.activate(
        'credential-1',
        'tenant-1',
        'attempt-1',
        `sha256:${'b'.repeat(64)}`
      )
    ).resolves.toMatchObject({ status: 'ISSUED' });
    await expect(
      store.markWiped(
        'credential-1',
        'tenant-1',
        'attempt-1',
        '2026-07-24T00:01:00.000Z'
      )
    ).resolves.toMatchObject({
      status: 'WIPED',
      wipedAt: '2026-07-24T00:01:00.000Z'
    });
    expect(delegate.updateMany).toHaveBeenLastCalledWith({
      where: {
        id: 'credential-1',
        tenantId: 'tenant-1',
        attemptId: 'attempt-1',
        status: 'ISSUED'
      },
      data: {
        status: 'WIPED',
        wipedAt: new Date('2026-07-24T00:01:00.000Z')
      }
    });
  });

  it('keeps a wiped lease terminal when concurrent revocation loses the race', async () => {
    const row = {
      ...baseRow(),
      status: 'WIPED' as const,
      credentialFingerprint: `sha256:${'b'.repeat(64)}`,
      wipedAt: new Date('2026-07-24T00:01:00.000Z')
    };
    const delegate = {
      updateMany: jest.fn().mockResolvedValue({ count: 0 }),
      findFirst: jest.fn().mockResolvedValue(row)
    };
    const store = new PrismaRepositoryCredentialLeaseStore({
      sastRepositoryCredentialLease: delegate
    } as unknown as PrismaService);

    await expect(
      store.revoke(
        'credential-1',
        'tenant-1',
        'attempt-1',
        '2026-07-24T00:01:01.000Z'
      )
    ).resolves.toMatchObject({
      status: 'WIPED',
      revokedAt: undefined
    });
    expect(delegate.updateMany).toHaveBeenCalledWith({
      where: {
        id: 'credential-1',
        tenantId: 'tenant-1',
        attemptId: 'attempt-1',
        status: { in: ['RESERVED', 'ISSUED'] }
      },
      data: {
        status: 'REVOKED',
        revokedAt: new Date('2026-07-24T00:01:01.000Z')
      }
    });
  });
});
