import { ScanPlaneService } from '../../src/scan-plane/scan-plane.service';

describe('Scan Plane production reads', () => {
  it('reads tenant-scoped durable scanner metadata without artifact references', async () => {
    const previousNodeEnv = process.env.NODE_ENV;
    const previousMode = process.env.ANALYSIS_CLIENT_MODE;
    process.env.NODE_ENV = 'production';
    process.env.ANALYSIS_CLIENT_MODE = 'internal';
    const findMany = jest.fn().mockResolvedValue([
      {
        id: 'scanner-run-1',
        tenantId: 'tenant-1',
        scanRequestId: 'scan-1',
        scanner: 'OPENGREP',
        status: 'COMPLETED'
      }
    ]);
    const service = new ScanPlaneService(
      {} as never,
      {} as never,
      {} as never,
      { scannerRun: { findMany } } as never
    );

    try {
      await expect(
        service.listScannerRuns('tenant-1', 'scan-1')
      ).resolves.toHaveLength(1);
      const query = findMany.mock.calls[0][0] as {
        where: Record<string, unknown>;
        select: Record<string, boolean>;
      };
      expect(query.where).toEqual({
        tenantId: 'tenant-1',
        scanRequestId: 'scan-1'
      });
      expect(query.select).not.toHaveProperty('rawArtifactObjectKey');
      expect(query.select).not.toHaveProperty('artifactMetadata');
      expect(query.select).not.toHaveProperty('preflightAttestationRef');
    } finally {
      if (previousNodeEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = previousNodeEnv;
      }
      if (previousMode === undefined) {
        delete process.env.ANALYSIS_CLIENT_MODE;
      } else {
        process.env.ANALYSIS_CLIENT_MODE = previousMode;
      }
    }
  });
});
