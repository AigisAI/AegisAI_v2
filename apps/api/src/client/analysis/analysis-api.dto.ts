export class AnalysisFileItemDto {
  path!: string;
  content!: string;
}

export class AnalysisRequestDto {
  scanId!: string;
  language!: string;
  files!: AnalysisFileItemDto[];
}

export class ModelResultDto {
  model!: string;
  detected!: boolean;
  severity!: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  reasoning!: string;
}

export class VulnerabilityItemDto {
  title!: string;
  description!: string;
  severity!: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  filePath!: string;
  lineStart!: number;
  lineEnd?: number;
  codeSnippet?: string;
  fixSuggestion?: string;
  fixExplanation?: string;
  cweId?: string;
  cveId?: string;
  owaspCategory?: string;
  referenceLinks?: { title: string; url: string }[];
  consensusScore!: number;
  modelResults!: ModelResultDto[];
}

export class AnalysisResultDto {
  scanId!: string;
  success!: boolean;
  errorMessage?: string;
  totalFiles!: number;
  totalLines!: number;
  vulnerabilities!: VulnerabilityItemDto[];
}
