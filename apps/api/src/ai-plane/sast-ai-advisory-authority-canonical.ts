import { createHash } from 'node:crypto';

export function digestAuthorityCanonical(
  value: string
): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

export function stableAuthorityJson(value: unknown): string {
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableAuthorityJson(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(key)}:${stableAuthorityJson(record[key])}`
    )
    .join(',')}}`;
}
