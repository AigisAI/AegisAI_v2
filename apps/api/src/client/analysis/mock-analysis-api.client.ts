import { Injectable } from '@nestjs/common';

import type {
  AnalysisRequest,
  AnalysisResult,
  IAnalysisApiClient
} from './analysis-api-client.interface';

@Injectable()
export class MockAnalysisApiClient implements IAnalysisApiClient {
  async analyze(
    request: AnalysisRequest,
    options?: { signal?: AbortSignal }
  ): Promise<AnalysisResult> {
    throwIfAborted(options?.signal);
    await Promise.resolve();
    throwIfAborted(options?.signal);

    const totalFiles = request.files.length;
    const totalLines = request.files.reduce((sum, file) => sum + countLines(file.content), 0);

    return {
      scanId: request.scanId,
      success: true,
      totalFiles,
      totalLines,
      vulnerabilities: [
        {
          title: 'SQL Injection in UserRepository.findByName()',
          description:
            'User input is concatenated directly into a SQL query and can be abused for injection.',
          severity: 'CRITICAL',
          filePath: 'src/main/java/com/example/UserRepository.java',
          lineStart: 42,
          lineEnd: 45,
          codeSnippet:
            'String query = "SELECT * FROM users WHERE name = \'" + name + "\'";\nreturn jdbcTemplate.query(query, ...);',
          fixSuggestion:
            '- String query = "SELECT * FROM users WHERE name = \'" + name + "\'";\n+ String query = "SELECT * FROM users WHERE name = ?";',
          fixExplanation:
            'Use a parameterized query so user input is treated as data instead of SQL syntax.',
          cweId: 'CWE-89',
          owaspCategory: 'A03:2021-Injection',
          referenceLinks: [
            {
              title: 'CWE-89: SQL Injection',
              url: 'https://cwe.mitre.org/data/definitions/89.html'
            }
          ],
          consensusScore: 1,
          modelResults: [
            {
              model: 'claude-3-5-sonnet',
              detected: true,
              severity: 'CRITICAL',
              reasoning: 'The SQL string is assembled with direct user input concatenation.'
            },
            {
              model: 'gemini-2.0-flash',
              detected: true,
              severity: 'CRITICAL',
              reasoning: 'Prepared statements are missing and the pattern matches CWE-89.'
            }
          ]
        }
      ]
    };
  }
}

function countLines(content: string): number {
  const normalized = content.trimEnd();

  if (!normalized) {
    return 0;
  }

  return normalized.split(/\r?\n/).length;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (!signal) {
    return;
  }

  if (typeof signal.throwIfAborted === 'function') {
    signal.throwIfAborted();
    return;
  }

  if (signal.aborted) {
    throw createAbortError();
  }
}

function createAbortError(): Error {
  if (typeof DOMException !== 'undefined') {
    return new DOMException('The operation was aborted.', 'AbortError');
  }

  return Object.assign(new Error('The operation was aborted.'), {
    name: 'AbortError'
  });
}
