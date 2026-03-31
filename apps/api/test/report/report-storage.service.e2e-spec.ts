const mockAccess = jest.fn();

jest.mock('node:fs/promises', () => {
  const actual = jest.requireActual('node:fs/promises');

  return {
    ...actual,
    access: (...args: unknown[]) => mockAccess(...args)
  };
});

import { ReportStorageService } from '../../src/report/services/report-storage.service';

describe('ReportStorageService', () => {
  beforeEach(() => {
    mockAccess.mockReset();
  });

  it('returns false when the file is missing', async () => {
    const service = new ReportStorageService({
      get: jest.fn().mockReturnValue('./tmp/reports')
    } as never);

    mockAccess.mockRejectedValueOnce(
      Object.assign(new Error('missing'), {
        code: 'ENOENT'
      })
    );

    await expect(service.exists('./tmp/reports/missing.pdf')).resolves.toBe(false);
  });

  it('rethrows filesystem errors other than ENOENT', async () => {
    const service = new ReportStorageService({
      get: jest.fn().mockReturnValue('./tmp/reports')
    } as never);
    const accessDenied = Object.assign(new Error('access denied'), {
      code: 'EACCES'
    });

    mockAccess.mockRejectedValueOnce(accessDenied);

    await expect(service.exists('./tmp/reports/blocked.pdf')).rejects.toThrow('access denied');
  });
});
