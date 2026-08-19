import {
  createHash,
  createPublicKey,
  verify as verifySignatureBytes
} from 'node:crypto';

import {
  SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES,
  SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
  evaluateSastIsolatedQualificationEvidence,
  isSastIsolatedQualificationDependencySetValid,
  isSastIsolatedQualificationExecutionPlanValid
} from '../../packages/shared/dist/index.js';
import { loadAndValidateIsolatedIntegrationPackage } from './isolated-integration-loader.mjs';
import {
  parseExactArguments,
  readQualificationJson
} from './qualification-json-input.mjs';

const args = parseExactArguments(process.argv.slice(2), {
  '--dependency-set': false,
  '--plan': false,
  '--approvals': false,
  '--receipts': false,
  '--trust-bundle': false
});
const externalNames = [
  '--dependency-set',
  '--plan',
  '--approvals',
  '--receipts',
  '--trust-bundle'
];
const externalCount = externalNames.filter((name) => args[name]).length;
if (externalCount !== 0 && externalCount !== externalNames.length) {
  throw new Error('T053 evidence verification requires either zero or all provider inputs');
}

const qualificationPackage = await loadAndValidateIsolatedIntegrationPackage();
let dependencySet = null;
let plan = null;
let approvals = [];
let signedReceipts = [];
let verifySignature = () => false;

if (externalCount > 0) {
  const [dependencyInput, planInput, approvalInput, receiptInput, trustInput] =
    await Promise.all([
      readQualificationJson(args['--dependency-set'], 2 * 1024 * 1024, 'T053 dependency set'),
      readQualificationJson(args['--plan'], 2 * 1024 * 1024, 'T053 execution plan'),
      readQualificationJson(args['--approvals'], 1024 * 1024, 'T053 plan approvals'),
      readQualificationJson(args['--receipts'], 64 * 1024 * 1024, 'T053 receipt bundle'),
      readQualificationJson(args['--trust-bundle'], 1024 * 1024, 'T053 trust bundle')
    ]);
  dependencySet = dependencyInput.value;
  plan = planInput.value;
  approvals = approvalInput.value;
  signedReceipts = receiptInput.value;
  if (!isSastIsolatedQualificationDependencySetValid(dependencySet, digest)) {
    throw new Error('T053 dependency set failed exact contract validation');
  }
  if (
    !isSastIsolatedQualificationExecutionPlanValid(
      plan,
      qualificationPackage.manifest,
      dependencySet,
      digest
    )
  ) {
    throw new Error('T053 execution plan failed exact binding validation');
  }
  if (!Array.isArray(approvals) || !Array.isArray(signedReceipts)) {
    throw new Error('T053 approvals and receipt bundle must be arrays');
  }
  const trustPolicy = dependencySet.artifacts.find(
    (item) => item.kind === 'TRUST_POLICY'
  );
  if (!trustPolicy || digest(trustInput.text) !== trustPolicy.artifactDigest) {
    throw new Error('T053 trust bundle does not match the dependency-set TRUST_POLICY digest');
  }
  verifySignature = buildTrustVerifier(trustInput.value, dependencySet);
}

const trustedEvaluatedAt = new Date().toISOString();
const result = evaluateSastIsolatedQualificationEvidence(
  {
    manifest: qualificationPackage.manifest,
    dependencySet,
    plan,
    approvals,
    signedReceipts,
    trustedEvaluatedAt,
    verifySignature
  },
  digest
);
if (!result) throw new Error('T053 aggregate evidence input failed structural validation');
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
process.exitCode =
  result.status === 'PASSED'
    ? 0
    : result.status === 'PENDING_PROVIDER_EXECUTION'
      ? 2
      : 1;

function buildTrustVerifier(value, dependencySetValue) {
  if (
    !hasExactKeys(value, ['version', 'revision', 'keys', 'immutable']) ||
    value.version !== 'sast-isolated-integration-trust-bundle-v1' ||
    !isSemanticVersion(value.revision) ||
    value.immutable !== true ||
    !Array.isArray(value.keys)
  ) {
    throw new Error('T053 trust bundle shape is invalid');
  }
  const expectedRoles = [
    ...SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES,
    ...SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES
  ];
  if (
    value.keys.length !== expectedRoles.length ||
    !arraysEqual(
      value.keys.map((item) => item.role),
      expectedRoles
    ) ||
    new Set(value.keys.map((item) => item.keyId)).size !== value.keys.length
  ) {
    throw new Error('T053 trust bundle must contain one canonical key per required role');
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
      typeof item.keyId !== 'string' ||
      !item.keyId.startsWith('qualification-key://') ||
      typeof item.publicKeyPem !== 'string' ||
      !isIsoInstant(item.validFrom) ||
      !isIsoInstant(item.validUntil) ||
      Date.parse(item.validUntil) <= Date.parse(item.validFrom) ||
      Date.parse(item.validFrom) > Date.parse(dependencySetValue.validFrom) ||
      Date.parse(item.validUntil) < Date.parse(dependencySetValue.validUntil)
    ) {
      throw new Error(`T053 trust key is invalid for role ${String(item.role)}`);
    }
    let publicKey;
    try {
      publicKey = createPublicKey(item.publicKeyPem);
    } catch {
      throw new Error(`T053 trust key PEM is invalid for role ${String(item.role)}`);
    }
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      throw new Error(`T053 trust key is not Ed25519 for role ${String(item.role)}`);
    }
    const canonicalPem = publicKey.export({ type: 'spki', format: 'pem' });
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const keyDigest = digestBytes(spki);
    if (
      canonicalPem !== item.publicKeyPem ||
      !item.keyId.endsWith(`/${keyDigest}`)
    ) {
      throw new Error(`T053 trust key identity drifted for role ${String(item.role)}`);
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
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
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
