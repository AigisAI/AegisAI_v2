import type { ConfigService } from '../../src/config/config.service';
import { CredentialLeaseExpiryTask } from '../../src/token-broker/credential-lease-expiry.task';
import type { RepositoryCredentialLeaseStore } from '../../src/token-broker/repository-credential-lease.store';

describe('CredentialLeaseExpiryTask', () => {
  it('atomically revokes expired nonterminal leases at the supplied reference time', async () => {
    const leases = {
      revokeExpired: jest.fn().mockResolvedValue(2)
    } as unknown as RepositoryCredentialLeaseStore;
    const task = new CredentialLeaseExpiryTask(
      leases,
      {
        isTest: jest.fn(() => true),
        get: jest.fn(() => 60_000)
      } as unknown as ConfigService
    );
    const referenceTime = new Date('2026-07-24T00:10:00.000Z');

    await expect(task.revokeExpired(referenceTime)).resolves.toBe(2);
    expect(leases.revokeExpired).toHaveBeenCalledWith(
      referenceTime.toISOString()
    );
  });
});
