import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { relative, resolve } from 'node:path';

import {
  isSastIsolatedQualificationManifestValid
} from '../../packages/shared/dist/index.js';
import {
  ISOLATED_INTEGRATION_ROOT,
  createIsolatedIntegrationAssets
} from './isolated-integration-assets.mjs';

export class SastIsolatedIntegrationLoadError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'SastIsolatedIntegrationLoadError';
    this.reason = reason;
  }
}

const EXPECTED_ROOT_ENTRIES = [
  'README.md',
  'isolated-integration.manifest.json',
  'materialization-policy.json'
];
const MAXIMUM_FILE_BYTES = Object.freeze({
  'README.md': 32 * 1024,
  'isolated-integration.manifest.json': 8 * 1024 * 1024,
  'materialization-policy.json': 64 * 1024
});

export async function loadAndValidateIsolatedIntegrationPackage(
  qualificationRoot = ISOLATED_INTEGRATION_ROOT
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

  const expected = createIsolatedIntegrationAssets();
  const expectedText = new Map([
    ['README.md', expected.readmeText],
    ['isolated-integration.manifest.json', expected.manifestText],
    ['materialization-policy.json', expected.materializationPolicyText]
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
    actualText.get('isolated-integration.manifest.json'),
    'MANIFEST_INVALID'
  );
  const materializationPolicy = parseJson(
    actualText.get('materialization-policy.json'),
    'POLICY_INVALID'
  );
  if (!isSastIsolatedQualificationManifestValid(manifest, digest)) {
    reject('MANIFEST_INVALID');
  }
  if (
    manifest.executionCellCount !== 123 ||
    manifest.caseCount !== 41 ||
    manifest.materializationPolicyDigest !==
      digest(actualText.get('materialization-policy.json')) ||
    materializationPolicy.version !==
      'sast-isolated-integration-materialization-policy-v1' ||
    materializationPolicy.localExecutionAllowed !== false ||
    materializationPolicy.productionReadinessAuthority !== false
  ) {
    reject('POLICY_INVALID');
  }
  await assertStableDirectory(root, rootStat, canonicalRoot, 'ROOT_INVALID');
  const immutableManifest = freezeJsonTree(manifest);
  return Object.freeze({
    manifest: immutableManifest,
    manifestId: manifest.manifestId,
    manifestDigest: manifest.manifestDigest,
    sourceSnapshotDigest: manifest.sourceSnapshotDigest,
    executionCellCount: manifest.executionCellCount,
    materializationPolicyDigest: manifest.materializationPolicyDigest,
    providerExecutionStatus: manifest.providerExecutionStatus,
    productionReadinessAuthority: manifest.productionReadinessAuthority
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
    if (
      !sameNodeIdentity(before, after) ||
      canonicalAfter !== canonicalBefore
    ) {
      reject(reason);
    }
    return buffer;
  } catch (error) {
    if (error instanceof SastIsolatedIntegrationLoadError) throw error;
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
  if (relation === '' || relation.startsWith('..') || relation.includes(':')) reject(reason);
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
  throw new SastIsolatedIntegrationLoadError(reason);
}
