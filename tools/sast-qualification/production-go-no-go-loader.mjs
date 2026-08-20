import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { relative, resolve } from 'node:path';

import {
  SAST_PRODUCTION_GO_NO_GO_GATE_CATALOG,
  evaluateSastProductionGoNoGoEvidence,
  isSastProductionGoNoGoManifestValid,
  isSastProductionGoNoGoRecordValid
} from '../../packages/shared/dist/index.js';
import { loadAndValidateSupplyChainRollbackQualificationPackage } from './supply-chain-rollback-qualification-loader.mjs';
import {
  PRODUCTION_GO_NO_GO_ROOT,
  createProductionGoNoGoAssets
} from './production-go-no-go-assets.mjs';

export class SastProductionGoNoGoLoadError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'SastProductionGoNoGoLoadError';
    this.reason = reason;
  }
}

const EXPECTED_ROOT_ENTRIES = [
  'README.md',
  'go-no-go-policy.json',
  'production-go-no-go.manifest.json'
];
const MAXIMUM_FILE_BYTES = Object.freeze({
  'README.md': 64 * 1024,
  'go-no-go-policy.json': 256 * 1024,
  'production-go-no-go.manifest.json': 256 * 1024
});
const REPOSITORY_VALIDATION_TIME = '2026-08-20T00:00:00.000Z';

export async function loadAndValidateProductionGoNoGoPackage(
  qualificationRoot = PRODUCTION_GO_NO_GO_ROOT
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

  const expected = createProductionGoNoGoAssets();
  const expectedText = new Map([
    ['README.md', expected.readmeText],
    ['go-no-go-policy.json', expected.policyText],
    ['production-go-no-go.manifest.json', expected.manifestText]
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
    actualText.get('production-go-no-go.manifest.json'),
    'MANIFEST_INVALID'
  );
  const policy = parseJson(actualText.get('go-no-go-policy.json'), 'POLICY_INVALID');
  const t055 = await loadAndValidateSupplyChainRollbackQualificationPackage();
  if (
    !isSastProductionGoNoGoManifestValid(
      manifest,
      t055.manifest,
      t055.t054Manifest,
      digest
    ) ||
    manifest.t055ManifestId !== t055.manifestId ||
    manifest.t055ManifestDigest !== t055.manifestDigest
  ) {
    reject('MANIFEST_INVALID');
  }
  if (
    manifest.requiredGateCount !== SAST_PRODUCTION_GO_NO_GO_GATE_CATALOG.length ||
    manifest.notApplicableGateCount !== 0 ||
    manifest.gatePolicyDigest !== digest(actualText.get('go-no-go-policy.json')) ||
    policy.version !== 'sast-production-go-no-go-policy-v1' ||
    policy.prerequisite?.requiredStatus !== 'PASSED' ||
    policy.prerequisite?.requiredEntryAuthorization !== 't056EntryAuthorized' ||
    policy.prerequisite?.exactT054ManifestResultDependencyVerificationPlanRequired !== true ||
    policy.prerequisite?.exactT055ManifestEntryPlanResultRequired !== true ||
    policy.prerequisite?.sameProviderAndAdapterRequired !== true ||
    policy.prerequisite?.independentlyConfiguredTrustPolicyDigestRequired !== true ||
    policy.evidence?.aggregateDecisionAcceptedFromCaller !== false ||
    policy.evidence?.callerSelectedEvaluationTimeAllowed !== false ||
    policy.evidence?.missingCategoryOutcome !== 'PENDING_FINAL_EVIDENCE' ||
    policy.evidence?.malformedStaleOrBreachedOutcome !== 'NO_GO' ||
    policy.evidence?.notApplicableAllowedForV1 !== false ||
    !arraysEqual(policy.evidence?.finalApprovalRoles ?? [], ['SECURITY_ENGINEERING', 'SCAN_PLATFORM']) ||
    !Array.isArray(policy.gateCatalog) ||
    policy.gateCatalog.length !== SAST_PRODUCTION_GO_NO_GO_GATE_CATALOG.length ||
    !policy.gateCatalog.every((item) => item.notApplicableAllowed === false) ||
    policy.handoff?.goAuthorizesOnly !== 'DEPLOYMENT_OPERATIONS_ENTRY' ||
    policy.handoff?.passingDoesNotExecuteKubernetes !== true ||
    policy.handoff?.passingDoesNotEstablishProductionReadiness !== true ||
    policy.prohibited?.localProviderEvidenceAllowed !== false ||
    policy.prohibited?.productionMutationAllowed !== false ||
    policy.prohibited?.kubernetesExecutionAllowed !== false ||
    policy.authority?.goAuthorizationOnly !== '005_DEPLOYMENT_OPERATIONS_ENTRY' ||
    policy.authority?.deploymentAuthority !== false ||
    policy.authority?.kubernetesExecutionAuthority !== false ||
    policy.authority?.productionReadinessAuthority !== false
  ) {
    reject('POLICY_INVALID');
  }

  const qualificationRecord = evaluateSastProductionGoNoGoEvidence(
    {
      manifest,
      t054Manifest: t055.t054Manifest,
      t055Manifest: t055.manifest,
      upstream: null,
      entryAttestation: null,
      evidenceAttestations: [],
      plan: null,
      approvals: [],
      trustedEvaluatedAt: REPOSITORY_VALIDATION_TIME,
      verifySignature: () => false
    },
    digest
  );
  if (
    !qualificationRecord ||
    !isSastProductionGoNoGoRecordValid(qualificationRecord, digest) ||
    qualificationRecord.status !== 'BLOCKED_T055_QUALIFICATION' ||
    qualificationRecord.deploymentOperationsEntryAuthorized !== false ||
    qualificationRecord.deploymentAuthority !== false ||
    qualificationRecord.kubernetesExecutionAuthority !== false ||
    qualificationRecord.productionReadinessAuthority !== false
  ) {
    reject('RECORD_INVALID');
  }
  await assertStableDirectory(root, rootStat, canonicalRoot, 'ROOT_INVALID');
  return Object.freeze({
    manifest: freezeJsonTree(manifest),
    t054Manifest: t055.t054Manifest,
    t055Manifest: t055.manifest,
    policy: freezeJsonTree(policy),
    qualificationRecord: freezeJsonTree(qualificationRecord),
    manifestId: manifest.manifestId,
    manifestDigest: manifest.manifestDigest,
    gateCount: manifest.requiredGateCount,
    gatePolicyDigest: manifest.gatePolicyDigest,
    qualificationStatus: qualificationRecord.status,
    deploymentOperationsEntryAuthorized:
      qualificationRecord.deploymentOperationsEntryAuthorized,
    deploymentAuthority: qualificationRecord.deploymentAuthority,
    kubernetesExecutionAuthority: qualificationRecord.kubernetesExecutionAuthority,
    productionReadinessAuthority: qualificationRecord.productionReadinessAuthority
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
    if (!sameNodeIdentity(before, after) || canonicalAfter !== canonicalBefore) reject(reason);
    return buffer;
  } catch (error) {
    if (error instanceof SastProductionGoNoGoLoadError) throw error;
    reject(reason);
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function decodeCanonicalText(buffer, reason) {
  if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
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
  throw new SastProductionGoNoGoLoadError(reason);
}
