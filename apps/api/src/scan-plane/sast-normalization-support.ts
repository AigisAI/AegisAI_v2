import { createHash } from 'node:crypto';
import { TextEncoder } from 'node:util';

import {
  SAST_ARTIFACT_VALIDATION_LIMITS,
  SAST_MAX_COORDINATE_VALUE,
  SAST_NORMALIZATION_LIMITS,
  type ExpectedScannerArtifactBinding,
  type SastArtifactDispositionDecision,
  type SastArtifactValidationResult,
  type SastFileCoordinateMetadata,
  type SastNormalizationRejectionReasonCode
} from '@aegisai/shared';

import { normalizeArtifactPath } from './sast-artifact-stream-validator';
import type {
  SastFileCoordinateAttestation
} from './sast-file-coordinate-attestation.provider';

const UTF8_ENCODER = new TextEncoder();

export interface SastNormalizedText {
  value?: string;
  reason?: Extract<
    SastNormalizationRejectionReasonCode,
    'NORMALIZATION_TEXT_INVALID' | 'NORMALIZATION_FIELD_LIMIT_EXCEEDED'
  >;
}

interface CoordinateLoadingOptions {
  attestation: Readonly<SastFileCoordinateAttestation> | null;
  expectedBinding: Readonly<ExpectedScannerArtifactBinding>;
  maximumFileCount: number;
  maximumPathDepth: number;
  invalidLocationReason: Extract<
    SastNormalizationRejectionReasonCode,
    | 'NORMALIZATION_OPENGREP_LOCATION_INVALID'
    | 'NORMALIZATION_TRIVY_LOCATION_INVALID'
  >;
  reasons: Set<SastNormalizationRejectionReasonCode>;
}

export function validateSastNormalizationReferenceTime(
  disposition: Readonly<SastArtifactDispositionDecision>,
  referenceTime: Readonly<Date>,
  reasons: Set<SastNormalizationRejectionReasonCode>
): number {
  const referenceTimeMilliseconds =
    referenceTime instanceof Date
      ? referenceTime.getTime()
      : Number.NaN;
  const decidedAtMilliseconds = Date.parse(disposition.decidedAt);
  if (
    !Number.isFinite(referenceTimeMilliseconds) ||
    referenceTimeMilliseconds < decidedAtMilliseconds
  ) {
    reasons.add('NORMALIZATION_ACCEPTANCE_INVALID');
  }
  if (
    !Number.isFinite(referenceTimeMilliseconds) ||
    !disposition.retentionExpiresAt ||
    referenceTimeMilliseconds >=
      Date.parse(disposition.retentionExpiresAt)
  ) {
    reasons.add('NORMALIZATION_RETENTION_EXPIRED');
  }
  return referenceTimeMilliseconds;
}

export function loadSastNormalizationCoordinates({
  attestation,
  expectedBinding,
  maximumFileCount,
  maximumPathDepth,
  invalidLocationReason,
  reasons
}: CoordinateLoadingOptions):
  | ReadonlyMap<string, Readonly<SastFileCoordinateMetadata>>
  | null {
  if (!attestation) return null;
  if (
    attestation.verified !== true ||
    attestation.attestationRef !==
      expectedBinding.preflightAttestationRef ||
    attestation.inventoryDigest !==
      expectedBinding.preflightInventoryDigest
  ) {
    reasons.add('NORMALIZATION_PLAN_BINDING_MISMATCH');
    return null;
  }
  if (
    !Array.isArray(attestation.files) ||
    attestation.files.length > maximumFileCount
  ) {
    reasons.add(invalidLocationReason);
    return null;
  }

  const coordinates = new Map<
    string,
    Readonly<SastFileCoordinateMetadata>
  >();
  const foldedPaths = new Set<string>();
  let totalLines = 0;
  for (const rawFile of attestation.files as readonly unknown[]) {
    if (
      !rawFile ||
      typeof rawFile !== 'object' ||
      Array.isArray(rawFile) ||
      !hasExactObjectKeys(rawFile, [
        'normalizedPath',
        'lineCount',
        'maxColumnByLine'
      ])
    ) {
      reasons.add(invalidLocationReason);
      return null;
    }
    const file = rawFile as Record<string, unknown>;
    const normalizedPath = normalizeArtifactPath(
      file.normalizedPath,
      maximumPathDepth
    );
    const foldedPath = normalizedPath
      ?.toLocaleLowerCase('en-US')
      .normalize('NFC');
    const lineCount = file.lineCount;
    if (
      !normalizedPath ||
      normalizedPath !== file.normalizedPath ||
      !foldedPath ||
      foldedPaths.has(foldedPath) ||
      typeof lineCount !== 'number' ||
      !Number.isSafeInteger(lineCount) ||
      lineCount <= 0 ||
      lineCount > SAST_MAX_COORDINATE_VALUE ||
      lineCount >
        SAST_ARTIFACT_VALIDATION_LIMITS
          .maximumCoordinateAttestationLines -
          totalLines ||
      coordinates.has(normalizedPath) ||
      !Array.isArray(file.maxColumnByLine) ||
      file.maxColumnByLine.length !== lineCount ||
      !file.maxColumnByLine.every(
        (column: unknown) =>
          typeof column === 'number' &&
          Number.isSafeInteger(column) &&
          column > 0 &&
          column <= SAST_MAX_COORDINATE_VALUE
      )
    ) {
      reasons.add(invalidLocationReason);
      return null;
    }
    totalLines += lineCount;
    foldedPaths.add(foldedPath);
    coordinates.set(normalizedPath, {
      normalizedPath,
      lineCount,
      maxColumnByLine: file.maxColumnByLine
    });
  }
  return coordinates;
}

export function normalizeSastTitle(
  value: string | undefined
): SastNormalizedText {
  if (value === undefined) {
    return { reason: 'NORMALIZATION_TEXT_INVALID' };
  }
  const normalized = normalizePlainText(value)
    ?.replace(/[\t\n]+/gu, ' ')
    .replace(/ {2,}/gu, ' ')
    .trim();
  if (!normalized) {
    return { reason: 'NORMALIZATION_TEXT_INVALID' };
  }
  if (
    utf8Bytes(normalized) > SAST_NORMALIZATION_LIMITS.titleBytes
  ) {
    return { reason: 'NORMALIZATION_FIELD_LIMIT_EXCEEDED' };
  }
  return { value: normalized };
}

export function normalizeSastDescription(
  value: string | undefined
): SastNormalizedText {
  const normalized =
    value === undefined ? null : normalizePlainText(value)?.trim();
  if (!normalized) {
    return { reason: 'NORMALIZATION_TEXT_INVALID' };
  }
  if (
    utf8Bytes(normalized) >
    SAST_NORMALIZATION_LIMITS.descriptionBytes
  ) {
    return { reason: 'NORMALIZATION_FIELD_LIMIT_EXCEEDED' };
  }
  return { value: normalized };
}

export function omitResultDigest(
  value: Readonly<SastArtifactValidationResult>
): Omit<SastArtifactValidationResult, 'resultDigest'> {
  const { resultDigest, ...core } = value;
  void resultDigest;
  return core;
}

export function omitDecisionDigest(
  value: Readonly<SastArtifactDispositionDecision>
): Omit<SastArtifactDispositionDecision, 'decisionDigest'> {
  const { decisionDigest, ...core } = value;
  void decisionDigest;
  return core;
}

export function hasUnsafeControls(
  value: string,
  allowTextWhitespace: boolean
): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return (
      (codePoint <= 0x1f &&
        (!allowTextWhitespace ||
          (codePoint !== 0x09 && codePoint !== 0x0a))) ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      (codePoint >= 0xd800 && codePoint <= 0xdfff)
    );
  });
}

export function utf8Bytes(value: string): number {
  return UTF8_ENCODER.encode(value).byteLength;
}

export function hasExactObjectKeys(
  value: object,
  expected: readonly string[]
): boolean {
  const actual = Object.keys(value);
  return (
    actual.length === expected.length &&
    actual.every((key) => expected.includes(key))
  );
}

export function readReferenceTime(clock: () => Date): Date {
  try {
    return new Date(Date.prototype.getTime.call(clock()));
  } catch {
    return new Date(Number.NaN);
  }
}

export function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function normalizePlainText(value: string): string | null {
  const normalized = value
    .replace(/\r\n?/gu, '\n')
    .normalize('NFC');
  return hasUnsafeControls(normalized, true) ? null : normalized;
}
