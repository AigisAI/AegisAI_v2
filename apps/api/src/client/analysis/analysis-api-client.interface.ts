export const ANALYSIS_API_CLIENT = 'IAnalysisApiClient';
export const ANALYSIS_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export type AnalysisSeverity = (typeof ANALYSIS_SEVERITIES)[number];

export interface AnalysisFileItem {
  path: string;
  content: string;
}

export interface AnalysisRequest {
  scanId: string;
  language: string;
  files: AnalysisFileItem[];
}

export interface ModelResult {
  model: string;
  detected: boolean;
  severity: AnalysisSeverity;
  reasoning: string;
}

export interface VulnerabilityItem {
  title: string;
  description: string;
  severity: AnalysisSeverity;
  filePath: string;
  lineStart: number;
  lineEnd?: number;
  codeSnippet?: string;
  fixSuggestion?: string;
  fixExplanation?: string;
  cweId?: string;
  cveId?: string;
  owaspCategory?: string;
  referenceLinks?: { title: string; url: string }[];
  consensusScore: number;
  modelResults: ModelResult[];
}

export interface AnalysisResult {
  scanId: string;
  success: boolean;
  errorMessage?: string;
  totalFiles: number;
  totalLines: number;
  vulnerabilities: VulnerabilityItem[];
}

export interface IAnalysisApiClient {
  analyze(request: AnalysisRequest, options?: { signal?: AbortSignal }): Promise<AnalysisResult>;
}
