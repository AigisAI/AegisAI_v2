import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { relative, resolve } from 'node:path';

import {
  evaluateSastSupplyChainRollbackQualificationEvidence,
  isSastSupplyChainRollbackQualificationManifestValid,
  isSastSupplyChainRollbackQualificationResultValid
} from '../../packages/shared/dist/index.js';
import { loadAndValidateEndToEndQualificationPackage } from './end-to-end-qualification-loader.mjs';
import {
  SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT,
  createSupplyChainRollbackQualificationAssets
} from './supply-chain-rollback-qualification-assets.mjs';

export class SastSupplyChainRollbackQualificationLoadError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'SastSupplyChainRollbackQualificationLoadError';
    this.reason = reason;
  }
}

const EXPECTED_ROOT_ENTRIES = [
  'README.md',
  'drill-policy.json',
  'supply-chain-rollback-qualification.manifest.json'
];
const MAXIMUM_FILE_BYTES = Object.freeze({
  'README.md': 48 * 1024,
  'drill-policy.json': 96 * 1024,
  'supply-chain-rollback-qualification.manifest.json': 2 * 1024 * 1024
});
const REPOSITORY_VALIDATION_TIME = '2026-08-20T00:00:00.000Z';

export async function loadAndValidateSupplyChainRollbackQualificationPackage(
  qualificationRoot = SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT
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

  const expected = createSupplyChainRollbackQualificationAssets();
  const expectedText = new Map([
    ['README.md', expected.readmeText],
    ['drill-policy.json', expected.drillPolicyText],
    [
      'supply-chain-rollback-qualification.manifest.json',
      expected.manifestText
    ]
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
    actualText.get('supply-chain-rollback-qualification.manifest.json'),
    'MANIFEST_INVALID'
  );
  const drillPolicy = parseJson(
    actualText.get('drill-policy.json'),
    'POLICY_INVALID'
  );
  const t054 = await loadAndValidateEndToEndQualificationPackage();
  if (
    !isSastSupplyChainRollbackQualificationManifestValid(
      manifest,
      t054.manifest,
      digest
    )
  ) {
    reject('MANIFEST_INVALID');
  }
  if (
    manifest.t054ManifestId !== t054.manifestId ||
    manifest.t054ManifestDigest !== t054.manifestDigest
  ) {
    reject('T054_BINDING_INVALID');
  }
  if (
    manifest.artifactKeys.length !== 36 ||
    manifest.artifactSupplyChainDrillCount !== 144 ||
    manifest.allowlistDrillCount !== 1 ||
    manifest.databaseDrillCount !== 6 ||
    manifest.schemaDrillCount !== 3 ||
    manifest.rollbackDrillCount !== 15 ||
    manifest.preExecutionRejectionCount !== 115 ||
    manifest.executionCellCount !== 169 ||
    manifest.drillPolicyDigest !== digest(actualText.get('drill-policy.json')) ||
    drillPolicy.version !== 'sast-supply-chain-rollback-drill-policy-v1' ||
    drillPolicy.prerequisite?.exactT054ResultRequired !== true ||
    drillPolicy.prerequisite?.exactT054DependencySetRequired !== true ||
    drillPolicy.prerequisite?.exactT054ArtifactVerificationSetRequired !== true ||
    drillPolicy.prerequisite?.exactT054PlanRequired !== true ||
    drillPolicy.prerequisite?.sameProviderAndAdapterRequired !== true ||
    drillPolicy.prerequisite?.independentlyConfiguredTrustPolicyDigestRequired !== true ||
    drillPolicy.execution?.readOnlyArtifactMountRequired !== true ||
    drillPolicy.execution?.exactSignatureEnvelopeDigestRequired !== true ||
    drillPolicy.execution?.exactProvenanceEnvelopeDigestRequired !== true ||
    drillPolicy.execution?.externalDatabaseEnrichmentRejectedBeforeEgress !== true ||
    drillPolicy.execution?.aggregateMetricsAcceptedFromCaller !== false ||
    drillPolicy.rollback?.appendOnlyActivationLedgerRequired !== true ||
    drillPolicy.prohibited?.localExecutionAllowed !== false ||
    drillPolicy.prohibited?.productionMutationAllowed !== false ||
    drillPolicy.authority?.kubernetesAuthority !== false ||
    drillPolicy.authority?.productionReadinessAuthority !== false ||
    drillPolicy.authority?.nextStageAuthorizationOnly !== 'T056_ENTRY'
  ) {
    reject('POLICY_INVALID');
  }

  const qualificationResult =
    evaluateSastSupplyChainRollbackQualificationEvidence(
      {
        manifest,
        t054Manifest: t054.manifest,
        t054Result: t054.qualificationResult,
        t054DependencySet: null,
        t054ArtifactVerificationSet: null,
        t054Plan: null,
        entryAttestation: null,
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
    !isSastSupplyChainRollbackQualificationResultValid(
      qualificationResult,
      digest
    ) ||
    qualificationResult.status !== 'BLOCKED_T054_QUALIFICATION' ||
    qualificationResult.t056EntryAuthorized !== false ||
    qualificationResult.deploymentAuthority !== false ||
    qualificationResult.productionReadinessAuthority !== false
  ) {
    reject('RESULT_INVALID');
  }
  await assertStableDirectory(root, rootStat, canonicalRoot, 'ROOT_INVALID');
  return Object.freeze({
    manifest: freezeJsonTree(manifest),
    t054Manifest: t054.manifest,
    drillPolicy: freezeJsonTree(drillPolicy),
    qualificationResult: freezeJsonTree(qualificationResult),
    manifestId: manifest.manifestId,
    manifestDigest: manifest.manifestDigest,
    executionCellCount: manifest.executionCellCount,
    drillPolicyDigest: manifest.drillPolicyDigest,
    qualificationStatus: qualificationResult.status,
    t056EntryAuthorized: qualificationResult.t056EntryAuthorized,
    deploymentAuthority: qualificationResult.deploymentAuthority,
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
    if (error instanceof SastSupplyChainRollbackQualificationLoadError) {
      throw error;
    }
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
  throw new SastSupplyChainRollbackQualificationLoadError(reason);
}
