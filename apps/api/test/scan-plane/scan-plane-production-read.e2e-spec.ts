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
        scannerVersion: '1.1.0',
        status: 'COMPLETED',
        required: true,
        scannerImageDigest: 'sha256:image',
        wrapperDigest: 'sha256:wrapper',
        ruleBundleDigest: 'sha256:rules',
        databaseDigest: null,
        scannerSetDigest: 'sha256:set',
        profileId: 'JAVA_DEEP_V1',
        profileDigest: 'sha256:profile',
        exitCode: 0,
        terminationSignal: null,
        timedOut: false,
        outputLimitExceeded: false,
        durationMilliseconds: 100,
        startedAt: new Date('2026-07-24T12:00:00.000Z'),
        completedAt: new Date('2026-07-24T12:00:00.100Z')
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
      ).resolves.toEqual([
        expect.objectContaining({
          id: 'scanner-run-1',
          required: true,
          scannerImageDigest: 'sha256:image',
          exitCode: 0,
          startedAt: '2026-07-24T12:00:00.000Z',
          completedAt: '2026-07-24T12:00:00.100Z'
        })
      ]);
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
