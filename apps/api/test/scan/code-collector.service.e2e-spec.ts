import { CodeCollectorService } from '../../src/scan/services/code-collector.service';

describe('CodeCollectorService', () => {
  it('collects only supported Java files and returns commit metadata', async () => {
    const gitClient = {
      getLatestCommitSha: jest.fn().mockResolvedValue('commit-123'),
      getFileTree: jest.fn().mockResolvedValue([
        { path: 'src/App.java', size: 20, type: 'blob' },
        { path: 'src/test/AppTest.java', size: 20, type: 'blob' },
        { path: 'README.md', size: 10, type: 'blob' },
        { path: 'src/LargeFile.java', size: 200_000, type: 'blob' },
        { path: 'src/nested', size: 0, type: 'tree' }
      ]),
      getFileContent: jest.fn().mockImplementation(async (_fullName: string, path: string) => {
        if (path === 'src/App.java') {
          return 'class App {}\nclass Nested {}';
        }

        throw new Error(`unexpected file content request: ${path}`);
      })
    };
    const gitClientRegistry = {
      get: jest.fn().mockReturnValue(gitClient)
    };
    const javaHandler = {
      getLanguage: jest.fn().mockReturnValue('java'),
      getFileExtensions: jest.fn().mockReturnValue(['.java']),
      getExcludePatterns: jest.fn().mockReturnValue(['**/test/**']),
      getMaxFileSize: jest.fn().mockReturnValue(100 * 1024),
      supports: jest.fn((path: string) => path.endsWith('.java'))
    };
    const languageHandlerRegistry = {
      get: jest.fn().mockReturnValue(javaHandler)
    };

    const service = new CodeCollectorService(
      gitClientRegistry as never,
      languageHandlerRegistry as never
    );

    await expect(
      service.collect({
        provider: 'github',
        fullName: 'acme/service',
        branch: 'main',
        accessToken: 'token-1',
        language: 'java',
        scanId: 'scan-1'
      })
    ).resolves.toEqual({
      analysisRequest: {
        scanId: 'scan-1',
        language: 'java',
        files: [
          {
            path: 'src/App.java',
            content: 'class App {}\nclass Nested {}'
          }
        ]
      },
      commitSha: 'commit-123',
      totalFiles: 1,
      totalLines: 2,
      skippedFiles: [
        { path: 'src/test/AppTest.java', reason: 'excluded-pattern' },
        { path: 'README.md', reason: 'unsupported-language' },
        { path: 'src/LargeFile.java', reason: 'file-too-large' }
      ]
    });

    expect(gitClientRegistry.get).toHaveBeenCalledWith('github');
    expect(languageHandlerRegistry.get).toHaveBeenCalledWith('java');
    expect(gitClient.getLatestCommitSha).toHaveBeenCalledWith('acme/service', 'main', 'token-1');
    expect(gitClient.getFileTree).toHaveBeenCalledWith('acme/service', 'main', 'token-1');
    expect(gitClient.getFileContent).toHaveBeenCalledTimes(1);
    expect(gitClient.getFileContent).toHaveBeenCalledWith(
      'acme/service',
      'src/App.java',
      'main',
      'token-1'
    );
  });
});
