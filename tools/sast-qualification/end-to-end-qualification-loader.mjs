import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { relative, resolve } from 'node:path';

import {
  evaluateSastEndToEndQualificationEvidence,
  evaluateSastIsolatedQualificationEvidence,
  isSastEndToEndQualificationManifestValid,
  isSastEndToEndQualificationResultValid
} from '../../packages/shared/dist/index.js';
import {
  END_TO_END_QUALIFICATION_ROOT,
  createEndToEndQualificationAssets
} from './end-to-end-qualification-assets.mjs';
import { loadAndValidateIsolatedIntegrationPackage } from './isolated-integration-loader.mjs';

export class SastEndToEndQualificationLoadError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'SastEndToEndQualificationLoadError';
    this.reason = reason;
  }
}

const EXPECTED_ROOT_ENTRIES = [
  'README.md',
  'end-to-end-qualification.manifest.json',
  'measurement-policy.json'
];
const MAXIMUM_FILE_BYTES = Object.freeze({
  'README.md': 48 * 1024,
  'end-to-end-qualification.manifest.json': 8 * 1024 * 1024,
  'measurement-policy.json': 64 * 1024
});
const REPOSITORY_VALIDATION_TIME = '2026-08-20T00:00:00.000Z';

export async function loadAndValidateEndToEndQualificationPackage(
  qualificationRoot = END_TO_END_QUALIFICATION_ROOT
) {
  const root = resolve(qualificationRoot);
  const rootStat = await guardedLstat(root, 'ROOT_INVALID');
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) reject('ROOT_INVALID');
  const canonicalRoot = await guardedRealpath(root, 'ROOT_INVALID');
  const entries = await guardedReaddir(root, 'ROOT_ENTRIES_INVALID');
  entries.sort((left, right) => compareText(left.name, right.name));
  if (!arraysEqual(entries.map((entry) => entry.name), EXPECTED_ROOT_ENTRIES)) {
    reject('ROOT_ENTRIES_INVALID');
  }

  const expected = createEndToEndQualificationAssets();
  const expectedText = new Map([
    ['README.md', expected.readmeText],
    ['end-to-end-qualification.manifest.json', expected.manifestText],
    ['measurement-policy.json', expected.measurementPolicyText]
  ]);
  const actualText = new Map();
  for (const entry of entries) {
    if (entry.isSymbolicLink() || !entry.isFile()) reject('ROOT_ENTRIES_INVALID');
    const path = resolveInside(root, entry.name);
    const buffer = await guardedRead(
      path,
      'ASSET_INVALID',
      canonicalRoot,
      MAXIMUM_FILE_BYTES[entry.name]
    );
    const text = decodeCanonicalText(buffer, 'ASSET_INVALID');
    if (text !== expectedText.get(entry.name)) reject('ASSET_DRIFT');
    actualText.set(entry.name, text);
  }

  const manifest = parseJson(
    actualText.get('end-to-end-qualification.manifest.json'),
    'MANIFEST_INVALID'
  );
  const measurementPolicy = parseJson(
    actualText.get('measurement-policy.json'),
    'POLICY_INVALID'
  );
  if (!isSastEndToEndQualificationManifestValid(manifest, digest)) {
    reject('MANIFEST_INVALID');
  }
  if (
    manifest.executionCellCount !== 3462 ||
    manifest.goldenCandidateCellCount !== 1880 ||
    manifest.goldenNegativeBaselineCellCount !== 940 ||
    manifest.endToEndCandidateCellCount !== 102 ||
    manifest.performanceCellCount !== 540 ||
    manifest.measurementPolicyDigest !==
      digest(actualText.get('measurement-policy.json')) ||
    measurementPolicy.version !==
      'sast-end-to-end-qualification-measurement-policy-v1' ||
    measurementPolicy.prerequisite?.exactT053DependencySetRequired !== true ||
    measurementPolicy.prerequisite?.sameProviderAndAdapterRequired !== true ||
    measurementPolicy.execution?.signedArtifactVerificationSetRequired !== true ||
    measurementPolicy.execution?.artifactVerificationSignatureRole !==
      'SUPPLY_CHAIN_AUTHORITY' ||
    measurementPolicy.execution?.everyArtifactSignatureAndProvenanceVerified !== true ||
    measurementPolicy.execution?.artifactSignatureEnvelopePayloadRequired !== true ||
    measurementPolicy.execution?.artifactProvenanceEnvelopePayloadRequired !== true ||
    measurementPolicy.execution?.perArtifactEd25519VerificationRequired !== true ||
    measurementPolicy.execution?.artifactProvenanceSubjectBindingRequired !== true ||
    measurementPolicy.execution?.independentlyConfiguredTrustPolicyDigestRequired !== true ||
    measurementPolicy.execution?.aggregateMetricsAcceptedFromCaller !== false ||
    measurementPolicy.prohibited?.localExecutionAllowed !== false ||
    measurementPolicy.authority?.productionReadinessAuthority !== false
  ) {
    reject('POLICY_INVALID');
  }

  const isolated = await loadAndValidateIsolatedIntegrationPackage();
  if (
    isolated.manifestId !== manifest.t053ManifestId ||
    isolated.manifestDigest !== manifest.t053ManifestDigest
  ) {
    reject('T053_BINDING_INVALID');
  }
  const t053Result = evaluateSastIsolatedQualificationEvidence(
    {
      manifest: isolated.manifest,
      dependencySet: null,
      plan: null,
      approvals: [],
      signedReceipts: [],
      trustedEvaluatedAt: REPOSITORY_VALIDATION_TIME,
      verifySignature: () => false
    },
    digest
  );
  if (!t053Result || t053Result.status !== 'PENDING_PROVIDER_EXECUTION') {
    reject('T053_BINDING_INVALID');
  }
  const qualificationResult = evaluateSastEndToEndQualificationEvidence(
    {
      manifest,
      t053Result,
      t053DependencySet: null,
      entryAttestation: null,
      dependencySet: null,
      artifactVerificationSet: null,
      plan: null,
      approvals: [],
      signedReceipts: [],
      trustedEvaluatedAt: REPOSITORY_VALIDATION_TIME,
      verifySignature: () => false
    },
    digest
  );
  if (
    !qualificationResult ||
    !isSastEndToEndQualificationResultValid(qualificationResult, digest) ||
    qualificationResult.status !== 'BLOCKED_T053_QUALIFICATION' ||
    qualificationResult.t055EntryAuthorized !== false ||
    qualificationResult.productionReadinessAuthority !== false
  ) {
    reject('RESULT_INVALID');
  }
  await assertStableDirectory(root, rootStat, canonicalRoot, 'ROOT_INVALID');
  return Object.freeze({
    manifest: freezeJsonTree(manifest),
    measurementPolicy: freezeJsonTree(measurementPolicy),
    qualificationResult: freezeJsonTree(qualificationResult),
    manifestId: manifest.manifestId,
    manifestDigest: manifest.manifestDigest,
    executionCellCount: manifest.executionCellCount,
    measurementPolicyDigest: manifest.measurementPolicyDigest,
    qualificationStatus: qualificationResult.status,
    t055EntryAuthorized: qualificationResult.t055EntryAuthorized,
    productionReadinessAuthority: qualificationResult.productionReadinessAuthority
  });
}

async function guardedRead(path, reason, canonicalRoot, maximumBytes) {
  let before;
  try {
    before = await lstat(path, { bigint: true });
  } catch {
    reject(reason);
  }
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1n ||
    before.size < 1n ||
    before.size > BigInt(maximumBytes)
  ) {
    reject(reason);
  }
  const canonicalBefore = await guardedRealpath(path, reason);
  ensureWithin(canonicalRoot, canonicalBefore, reason);
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | noFollowFlag());
    const opened = await handle.stat({ bigint: true });
    if (!sameNodeIdentity(before, opened)) reject(reason);
    const buffer = Buffer.alloc(Number(opened.size));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead !== buffer.length) reject(reason);
    const openedAfter = await handle.stat({ bigint: true });
    if (!sameNodeIdentity(opened, openedAfter)) reject(reason);
    const after = await lstat(path, { bigint: true });
    const canonicalAfter = await guardedRealpath(path, reason);
    ensureWithin(canonicalRoot, canonicalAfter, reason);
    if (!sameNodeIdentity(before, after) || canonicalAfter !== canonicalBefore) {
      reject(reason);
    }
    return buffer;
  } catch (error) {
    if (error instanceof SastEndToEndQualificationLoadError) throw error;
    reject(reason);
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function decodeCanonicalText(buffer, reason) {
  if (
    buffer.length >= 3 &&
    buffer[0] === 0xef &&
    buffer[1] === 0xbb &&
    buffer[2] === 0xbf
  ) {
    reject(reason);
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    reject(reason);
  }
  if (
    text.includes('\u0000') ||
    text.includes('\r') ||
    !text.endsWith('\n') ||
    text !== text.normalize('NFC') ||
    Buffer.from(text, 'utf8').compare(buffer) !== 0
  ) {
    reject(reason);
  }
  return text;
}

function parseJson(text, reason) {
  try {
    return JSON.parse(text);
  } catch {
    reject(reason);
  }
}

async function guardedLstat(path, reason) {
  try {
    return await lstat(path, { bigint: true });
  } catch {
    reject(reason);
  }
}

async function guardedRealpath(path, reason) {
  try {
    return await realpath(path);
  } catch {
    reject(reason);
  }
}

async function guardedReaddir(path, reason) {
  try {
    return await readdir(path, { withFileTypes: true });
  } catch {
    reject(reason);
  }
}

async function assertStableDirectory(path, expected, canonical, reason) {
  const current = await guardedLstat(path, reason);
  const currentCanonical = await guardedRealpath(path, reason);
  if (
    !current.isDirectory() ||
    current.isSymbolicLink() ||
    !sameNodeIdentity(expected, current) ||
    currentCanonical !== canonical
  ) {
    reject(reason);
  }
}

function resolveInside(root, child) {
  const candidate = resolve(root, child);
  ensureWithin(root, candidate, 'PATH_INVALID');
  return candidate;
}

function ensureWithin(root, candidate, reason) {
  const relation = relative(root, candidate);
  if (relation === '' || relation.startsWith('..') || relation.includes(':')) {
    reject(reason);
  }
}

function sameNodeIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function noFollowFlag() {
  return typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function freezeJsonTree(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeJsonTree(child);
  return Object.freeze(value);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function reject(reason) {
  throw new SastEndToEndQualificationLoadError(reason);
}
