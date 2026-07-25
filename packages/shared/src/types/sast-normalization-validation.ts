import type {
  SastArtifactDispositionScope
} from './sast-artifact-disposition';

const UTF8_ENCODER = new TextEncoder();

export function isNormalizationScopeValid(
  value: unknown
): value is SastArtifactDispositionScope {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'attemptId',
      'scannerRunId'
    ]) &&
    Object.values(value).every(isBoundedReference)
  );
}

export function isBoundedReference(
  value: unknown
): value is string {
  return isBoundedIdentifier(value, 2048, false);
}

export function isAllowedString(
  value: unknown,
  allowed: readonly string[]
): value is string {
  return typeof value === 'string' && allowed.includes(value);
}

export function isBoundedIdentifier(
  value: unknown,
  maximumBytes: number,
  allowEmpty: boolean
): value is string {
  return (
    typeof value === 'string' &&
    (allowEmpty || value.length > 0) &&
    value === value.normalize('NFC') &&
    value === value.trim() &&
    utf8Length(value) <= maximumBytes &&
    !hasUnsafeControl(value, false)
  );
}

export function hasUnsafeControl(
  value: string,
  allowTextWhitespace: boolean
): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    if (
      allowTextWhitespace &&
      (codePoint === 0x09 || codePoint === 0x0a)
    ) {
      return false;
    }
    return (
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      (codePoint >= 0xd800 && codePoint <= 0xdfff)
    );
  });
}

export function isCommitSha(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(value)
  );
}

export function isSha256Digest(
  value: unknown
): value is `sha256:${string}` {
  return (
    typeof value === 'string' &&
    /^sha256:[a-f0-9]{64}$/u.test(value)
  );
}

export function utf8Length(value: string): number {
  return UTF8_ENCODER.encode(value).byteLength;
}

export function isRecord(
  value: unknown
): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[]
): boolean {
  const actual = Object.keys(value);
  return (
    actual.length === expected.length &&
    actual.every((key) => expected.includes(key))
  );
}
