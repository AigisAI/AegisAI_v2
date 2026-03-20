import { MockAnalysisApiClient } from '../../../src/client/analysis/mock-analysis-api.client';

describe('MockAnalysisApiClient', () => {
  it('derives totals from the request files and preserves consensus-backed results', async () => {
    const client = new MockAnalysisApiClient();

    await expect(
      client.analyze({
        scanId: 'scan-1',
        language: 'java',
        files: [
          {
            path: 'src/main/java/com/example/UserRepository.java',
            content: 'class UserRepository {\n  void query() {}\n}\n'
          },
          {
            path: 'src/main/java/com/example/JwtConfig.java',
            content: 'class JwtConfig {\n  private static final String SECRET = "unsafe";\n}\n'
          }
        ]
      })
    ).resolves.toMatchObject({
      scanId: 'scan-1',
      success: true,
      totalFiles: 2,
      totalLines: 6,
      vulnerabilities: expect.arrayContaining([
        expect.objectContaining({
          consensusScore: expect.any(Number),
          modelResults: expect.arrayContaining([
            expect.objectContaining({
              model: expect.any(String),
              detected: expect.any(Boolean)
            })
          ])
        })
      ])
    });
  });
});
