import type { AnalysisResult, AnalysisSeverity } from './analysis-api-client.interface';
import { ANALYSIS_SEVERITIES } from './analysis-api-client.interface';

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
  severity!: AnalysisSeverity;
  reasoning!: string;
}

export class VulnerabilityItemDto {
  title!: string;
  description!: string;
  severity!: AnalysisSeverity;
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

export function parseAnalysisResultDto(input: unknown): AnalysisResult {
  if (!isRecord(input)) {
    throw new Error('Analysis result payload must be an object.');
  }

  assertString(input.scanId, 'scanId');
  assertBoolean(input.success, 'success');
  assertOptionalString(input.errorMessage, 'errorMessage');
  assertNonNegativeInteger(input.totalFiles, 'totalFiles');
  assertNonNegativeInteger(input.totalLines, 'totalLines');

  if (!Array.isArray(input.vulnerabilities)) {
    throw new Error('Analysis result vulnerabilities must be an array.');
  }

  input.vulnerabilities.forEach((item, index) => validateVulnerability(item, index));

  return input as unknown as AnalysisResult;
}

function validateVulnerability(input: unknown, index: number): void {
  if (!isRecord(input)) {
    throw new Error(`Vulnerability at index ${index} must be an object.`);
  }

  assertString(input.title, `vulnerabilities[${index}].title`);
  assertString(input.description, `vulnerabilities[${index}].description`);
  assertSeverity(input.severity, `vulnerabilities[${index}].severity`);
  assertString(input.filePath, `vulnerabilities[${index}].filePath`);
  assertPositiveInteger(input.lineStart, `vulnerabilities[${index}].lineStart`);
  assertOptionalLineEnd(input.lineEnd, input.lineStart, `vulnerabilities[${index}].lineEnd`);
  assertOptionalString(input.codeSnippet, `vulnerabilities[${index}].codeSnippet`);
  assertOptionalString(input.fixSuggestion, `vulnerabilities[${index}].fixSuggestion`);
  assertOptionalString(input.fixExplanation, `vulnerabilities[${index}].fixExplanation`);
  assertOptionalString(input.cweId, `vulnerabilities[${index}].cweId`);
  assertOptionalString(input.cveId, `vulnerabilities[${index}].cveId`);
  assertOptionalString(input.owaspCategory, `vulnerabilities[${index}].owaspCategory`);
  assertReferenceLinks(input.referenceLinks, `vulnerabilities[${index}].referenceLinks`);
  assertConsensusScore(input.consensusScore, `vulnerabilities[${index}].consensusScore`);
  assertModelResults(input.modelResults, `vulnerabilities[${index}].modelResults`);
}

function assertModelResults(value: unknown, fieldName: string): void {
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array.`);
  }

  value.forEach((item, index) => {
    if (!isRecord(item)) {
      throw new Error(`${fieldName}[${index}] must be an object.`);
    }

    assertString(item.model, `${fieldName}[${index}].model`);
    assertBoolean(item.detected, `${fieldName}[${index}].detected`);
    assertSeverity(item.severity, `${fieldName}[${index}].severity`);
    assertString(item.reasoning, `${fieldName}[${index}].reasoning`);
  });
}

function assertReferenceLinks(value: unknown, fieldName: string): void {
  if (value === undefined) {
    return;
  }

  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array when provided.`);
  }

  value.forEach((item, index) => {
    if (!isRecord(item)) {
      throw new Error(`${fieldName}[${index}] must be an object.`);
    }

    assertString(item.title, `${fieldName}[${index}].title`);
    assertString(item.url, `${fieldName}[${index}].url`);
  });
}

function assertString(value: unknown, fieldName: string): void {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${fieldName} must be a non-empty string.`);
  }
}

function assertOptionalString(value: unknown, fieldName: string): void {
  if (value !== undefined && value !== null && typeof value !== 'string') {
    throw new Error(`${fieldName} must be a string when provided.`);
  }
}

function assertBoolean(value: unknown, fieldName: string): void {
  if (typeof value !== 'boolean') {
    throw new Error(`${fieldName} must be a boolean.`);
  }
}

function assertSeverity(value: unknown, fieldName: string): void {
  if (typeof value !== 'string' || !ANALYSIS_SEVERITIES.includes(value as AnalysisSeverity)) {
    throw new Error(`${fieldName} must be a valid severity.`);
  }
}

function assertPositiveInteger(value: unknown, fieldName: string): void {
  if (!Number.isInteger(value) || Number(value) <= 0) {
    throw new Error(`${fieldName} must be a positive integer.`);
  }
}

function assertNonNegativeInteger(value: unknown, fieldName: string): void {
  if (!Number.isInteger(value) || Number(value) < 0) {
    throw new Error(`${fieldName} must be a non-negative integer.`);
  }
}

function assertOptionalLineEnd(value: unknown, lineStart: unknown, fieldName: string): void {
  if (value === undefined) {
    return;
  }

  if (!Number.isInteger(value) || Number(value) < Number(lineStart)) {
    throw new Error(`${fieldName} must be greater than or equal to lineStart.`);
  }
}

function assertConsensusScore(value: unknown, fieldName: string): void {
  if (typeof value !== 'number' || Number.isNaN(value) || value < 0 || value > 1) {
    throw new Error(`${fieldName} must be a number between 0 and 1.`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
