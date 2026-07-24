import { SastAttemptReconciliationTask } from '../../src/scan-plane/sast-attempt-reconciliation.task';

describe('SAST attempt reconciliation task', () => {
  it('forwards an exact reference time to durable overdue-attempt reconciliation', async () => {
    const store = {
      failOverdueAttempts: jest.fn().mockResolvedValue(2)
    };
    const config = {
      isTest: jest.fn().mockReturnValue(true),
      get: jest.fn().mockReturnValue(60_000)
    };
    const task = new SastAttemptReconciliationTask(
      store as never,
      config as never
    );
    const referenceTime = new Date('2026-07-24T12:00:00.000Z');

    await expect(
      task.reconcileOverdueAttempts(referenceTime)
    ).resolves.toBe(2);
    expect(store.failOverdueAttempts).toHaveBeenCalledWith(
      referenceTime.toISOString()
    );
  });
});
