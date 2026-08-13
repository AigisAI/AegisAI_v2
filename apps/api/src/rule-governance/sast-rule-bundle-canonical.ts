import { createHash } from 'node:crypto';

export function digestSastRuleBundleCanonical(
  value: string
): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
