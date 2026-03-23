import type { Provider } from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import type { AnalysisRequest } from '../../client/analysis/analysis-api-client.interface';
import { GitClientRegistry } from '../../client/git/git-client.registry';
import { LanguageHandlerRegistry } from '../../language/language-handler.registry';

interface CollectCodeInput {
  provider: Provider;
  fullName: string;
  branch: string;
  accessToken: string;
  language: string;
  scanId: string;
}

interface SkippedFile {
  path: string;
  reason: string;
}

export interface CodeCollectionResult {
  analysisRequest: AnalysisRequest;
  commitSha: string;
  totalFiles: number;
  totalLines: number;
  skippedFiles: SkippedFile[];
}

@Injectable()
export class CodeCollectorService {
  constructor(
    private readonly gitClientRegistry: GitClientRegistry,
    private readonly languageHandlerRegistry: LanguageHandlerRegistry
  ) {}

  async collect(input: CollectCodeInput): Promise<CodeCollectionResult> {
    const gitClient = this.gitClientRegistry.get(input.provider);
    const languageHandler = this.languageHandlerRegistry.get(input.language);
    const [commitSha, fileTree] = await Promise.all([
      gitClient.getLatestCommitSha(input.fullName, input.branch, input.accessToken),
      gitClient.getFileTree(input.fullName, input.branch, input.accessToken)
    ]);
    const excludePatterns = languageHandler.getExcludePatterns();

    const files: AnalysisRequest['files'] = [];
    const skippedFiles: SkippedFile[] = [];

    for (const item of fileTree) {
      if (item.type !== 'blob') {
        continue;
      }

      if (matchesExcludePattern(item.path, excludePatterns)) {
        skippedFiles.push({ path: item.path, reason: 'excluded-pattern' });
        continue;
      }

      if (!languageHandler.supports(item.path)) {
        skippedFiles.push({ path: item.path, reason: 'unsupported-language' });
        continue;
      }

      if (item.size > languageHandler.getMaxFileSize()) {
        skippedFiles.push({ path: item.path, reason: 'file-too-large' });
        continue;
      }

      const content = await gitClient.getFileContent(
        input.fullName,
        item.path,
        input.branch,
        input.accessToken
      );

      files.push({
        path: item.path,
        content
      });
    }

    return {
      analysisRequest: {
        scanId: input.scanId,
        language: input.language,
        files
      },
      commitSha,
      totalFiles: files.length,
      totalLines: files.reduce((count, file) => count + countLines(file.content), 0),
      skippedFiles
    };
  }
}

function countLines(content: string): number {
  if (!content) {
    return 0;
  }

  return content.split(/\r?\n/u).length;
}

function matchesExcludePattern(path: string, excludePatterns: string[]): boolean {
  const normalizedPath = `/${path.replace(/\\/gu, '/')}/`;

  return excludePatterns.some((pattern) => {
    const normalizedPattern = pattern.replace(/\*\*/gu, '').replace(/\*/gu, '').trim();

    if (!normalizedPattern) {
      return false;
    }

    const patternPath = normalizedPattern.startsWith('/')
      ? normalizedPattern
      : `/${normalizedPattern}`;
    const needle = patternPath.endsWith('/') ? patternPath : `${patternPath}/`;

    return normalizedPath.includes(needle);
  });
}
