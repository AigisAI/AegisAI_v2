import { ConflictException, NotFoundException } from '@nestjs/common';

import { SCAN_PROCESS_JOB } from '../../src/scan/scan.constants';
import { ScanService } from '../../src/scan/scan.service';

describe('ScanService', () => {
  it('creates a pending scan and enqueues the processor job', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'repo-1',
          userId: 'user-1',
          fullName: 'acme/service',
          provider: 'GITHUB'
        })
      },
      scan: {
        findFirst: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue({
          id: 'scan-1',
          status: 'PENDING'
        })
      }
    };
    const queue = {
      add: jest.fn().mockResolvedValue({ id: 'scan-1' })
    };

    const service = new ScanService(prisma as never, queue as never);

    await expect(
      service.createScan({
        userId: 'user-1',
        connectedRepoId: 'repo-1',
        branch: 'main'
      })
    ).resolves.toEqual({
      scanId: 'scan-1',
      status: 'PENDING',
      message: 'Scan queued successfully.'
    });

    expect(prisma.connectedRepo.findFirst).toHaveBeenCalledWith({
      where: {
        id: 'repo-1',
        userId: 'user-1'
      }
    });
    expect(prisma.scan.findFirst).toHaveBeenCalledWith({
      where: {
        connectedRepoId: 'repo-1',
        branch: 'main',
        status: { in: ['PENDING', 'RUNNING'] }
      }
    });
    expect(prisma.scan.create).toHaveBeenCalledWith({
      data: {
        connectedRepoId: 'repo-1',
        branch: 'main',
        language: 'java',
        status: 'PENDING'
      }
    });
    expect(queue.add).toHaveBeenCalledWith(
      SCAN_PROCESS_JOB,
      { scanId: 'scan-1' },
      { jobId: 'scan-1' }
    );
  });

  it('rejects duplicate active scans for the same repository branch', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'repo-1',
          userId: 'user-1'
        })
      },
      scan: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'scan-existing',
          status: 'RUNNING'
        })
      }
    };

    const service = new ScanService(prisma as never, { add: jest.fn() } as never);

    await expect(
      service.createScan({
        userId: 'user-1',
        connectedRepoId: 'repo-1',
        branch: 'main'
      })
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('throws when the connected repository does not belong to the user', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue(null)
      }
    };

    const service = new ScanService(prisma as never, { add: jest.fn() } as never);

    await expect(
      service.createScan({
        userId: 'user-1',
        connectedRepoId: 'missing-repo',
        branch: 'main'
      })
    ).rejects.toBeInstanceOf(NotFoundException);
  });
});
