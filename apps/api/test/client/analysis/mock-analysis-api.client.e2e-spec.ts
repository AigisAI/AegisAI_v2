import type { AnalysisRequest } from '../../../src/client/analysis/analysis-api-client.interface';
import { MockAnalysisApiClient } from '../../../src/client/analysis/mock-analysis-api.client';

describe('MockAnalysisApiClient', () => {
  const request: AnalysisRequest = {
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
  };

  it('derives totals from the request files and preserves consensus-backed results', async () => {
    const client = new MockAnalysisApiClient();

    await expect(client.analyze(request)).resolves.toMatchObject({
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

  it('rejects immediately when the abort signal is already aborted', async () => {
    const client = new MockAnalysisApiClient();
    const controller = new AbortController();

    controller.abort();

    await expect(client.analyze(request, { signal: controller.signal })).rejects.toMatchObject({
      name: 'AbortError'
    });
  });

  it('rejects when aborted during async work', async () => {
    const client = new MockAnalysisApiClient();
    const controller = new AbortController();

    const pendingResult = client.analyze(request, { signal: controller.signal });
    controller.abort();

    await expect(pendingResult).rejects.toMatchObject({
      name: 'AbortError'
    });
  });
});
