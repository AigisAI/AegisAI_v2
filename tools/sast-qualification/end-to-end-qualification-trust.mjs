import {
  createHash,
  createPublicKey,
  verify as verifySignatureBytes
} from 'node:crypto';

import {
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES
} from '../../packages/shared/dist/index.js';

export function buildEndToEndQualificationTrustVerifier({
  value,
  text,
  dependencySet
}) {
  if (
    !hasExactKeys(value, ['version', 'revision', 'keys', 'immutable']) ||
    value.version !== 'sast-end-to-end-qualification-trust-bundle-v1' ||
    !isSemanticVersion(value.revision) ||
    value.immutable !== true ||
    !Array.isArray(value.keys)
  ) {
    throw new Error('T054 trust bundle shape is invalid');
  }
  const trustArtifact = dependencySet.artifacts.find(
    (item) => item.artifactKey === 'TRUST_POLICY'
  );
  if (!trustArtifact || digest(text) !== trustArtifact.artifactDigest) {
    throw new Error(
      'T054 trust bundle does not match the dependency-set TRUST_POLICY digest'
    );
  }
  if (
    value.keys.length !== SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES.length ||
    !arraysEqual(
      value.keys.map((item) => item.role),
      SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES
    ) ||
    new Set(value.keys.map((item) => item.keyId)).size !== value.keys.length
  ) {
    throw new Error('T054 trust bundle must contain one canonical key per role');
  }
  const trustedKeys = new Map();
  for (const item of value.keys) {
    if (
      !hasExactKeys(item, [
        'keyId',
        'role',
        'algorithm',
        'publicKeyPem',
        'validFrom',
        'validUntil'
      ]) ||
      item.algorithm !== 'ED25519' ||
      !SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES.includes(item.role) ||
      typeof item.keyId !== 'string' ||
      !item.keyId.startsWith('qualification-key://') ||
      typeof item.publicKeyPem !== 'string' ||
      !isIsoInstant(item.validFrom) ||
      !isIsoInstant(item.validUntil) ||
      Date.parse(item.validUntil) <= Date.parse(item.validFrom) ||
      Date.parse(item.validFrom) > Date.parse(dependencySet.validFrom) ||
      Date.parse(item.validUntil) < Date.parse(dependencySet.validUntil)
    ) {
      throw new Error(`T054 trust key is invalid for role ${String(item.role)}`);
    }
    let publicKey;
    try {
      publicKey = createPublicKey(item.publicKeyPem);
    } catch {
      throw new Error(`T054 trust key PEM is invalid for role ${String(item.role)}`);
    }
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      throw new Error(`T054 trust key is not Ed25519 for role ${String(item.role)}`);
    }
    const canonicalPem = publicKey.export({ type: 'spki', format: 'pem' });
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const keyDigest = digestBytes(spki);
    if (canonicalPem !== item.publicKeyPem || !item.keyId.endsWith(`/${keyDigest}`)) {
      throw new Error(`T054 trust key identity drifted for role ${String(item.role)}`);
    }
    trustedKeys.set(item.keyId, Object.freeze({ ...item, publicKey }));
  }
  return (signature, payload) => {
    const trusted = trustedKeys.get(signature.keyId);
    if (
      !trusted ||
      trusted.role !== signature.role ||
      trusted.algorithm !== signature.algorithm ||
      Date.parse(signature.signedAt) < Date.parse(trusted.validFrom) ||
      Date.parse(signature.signedAt) > Date.parse(trusted.validUntil)
    ) {
      return false;
    }
    try {
      return verifySignatureBytes(
        null,
        Buffer.from(payload, 'utf8'),
        trusted.publicKey,
        Buffer.from(signature.valueBase64, 'base64')
      );
    } catch {
      return false;
    }
  };
}

function hasExactKeys(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  return arraysEqual(Object.keys(value).sort(compareText), [...keys].sort(compareText));
}

function isSemanticVersion(value) {
  return (
    typeof value === 'string' &&
    /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u.test(
      value
    )
  );
}

function isIsoInstant(value) {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
