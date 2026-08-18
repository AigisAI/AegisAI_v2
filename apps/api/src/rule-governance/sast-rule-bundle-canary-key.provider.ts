import { createHash } from 'node:crypto';

import { Injectable } from '@nestjs/common';

const MINIMUM_HMAC_KEY_BYTES = 32;

export interface SastRuleBundleCanaryCohortKey {
  keyRef: string;
  keyVersion: string;
  keyMaterial: Buffer;
}

export class SastRuleBundleCanaryCohortKeyError extends Error {
  constructor(readonly reason: 'UNAVAILABLE' | 'INVALID') {
    super('The SAST canary cohort key provider failed closed.');
    this.name = 'SastRuleBundleCanaryCohortKeyError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleCanaryCohortKeyProvider {
  abstract load(): Promise<SastRuleBundleCanaryCohortKey>;
}

@Injectable()
export class EnvironmentSastRuleBundleCanaryCohortKeyProvider extends SastRuleBundleCanaryCohortKeyProvider {
  async load(): Promise<SastRuleBundleCanaryCohortKey> {
    const encoded = process.env.SAST_CANARY_COHORT_HMAC_KEY_BASE64;
    const keyRef = process.env.SAST_CANARY_COHORT_HMAC_KEY_REF;
    const keyVersion = process.env.SAST_CANARY_COHORT_HMAC_KEY_VERSION;
    if (!encoded || !keyRef || !keyVersion) {
      throw new SastRuleBundleCanaryCohortKeyError('UNAVAILABLE');
    }
    if (
      !/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded) ||
      encoded.length % 4 !== 0 ||
      !isDigestBoundReference(keyRef) ||
      !isBoundedIdentifier(keyVersion)
    ) {
      throw new SastRuleBundleCanaryCohortKeyError('INVALID');
    }
    const keyMaterial = Buffer.from(encoded, 'base64');
    if (
      keyMaterial.length < MINIMUM_HMAC_KEY_BYTES ||
      keyMaterial.toString('base64') !== encoded ||
      !keyRef.endsWith(
        `sha256:${createHash('sha256').update(keyMaterial).digest('hex')}`
      )
    ) {
      keyMaterial.fill(0);
      throw new SastRuleBundleCanaryCohortKeyError('INVALID');
    }
    return { keyRef, keyVersion, keyMaterial };
  }
}

function isDigestBoundReference(value: string): boolean {
  return (
    value.length <= 2_048 &&
    value === value.trim() &&
    value.normalize('NFC') === value &&
    !containsControlCharacter(value) &&
    /^[a-z][a-z0-9+.-]*:\/\/\S*sha256:[0-9a-f]{64}$/u.test(value) &&
    !/^https?:/u.test(value)
  );
}

function isBoundedIdentifier(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 512 &&
    value === value.trim() &&
    value.normalize('NFC') === value &&
    !containsControlCharacter(value)
  );
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 31 || code === 127;
  });
}
