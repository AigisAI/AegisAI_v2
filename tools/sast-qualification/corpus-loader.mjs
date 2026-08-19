import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';

import {
  SAST_QUALIFICATION_CORPUS_LIMITS,
  isSastQualificationCorpusSnapshotValid,
  isSastQualificationPriorReleaseManifestValid
} from '../../packages/shared/dist/index.js';
import {
  GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_DIGEST,
  GOLDEN_CORPUS_ROOT,
  createGoldenCorpusAssets
} from './golden-corpus-assets.mjs';

export class SastQualificationCorpusLoadError extends Error {
  constructor(reason) {
    super(`SAST qualification corpus rejected: ${reason}`);
    this.name = 'SastQualificationCorpusLoadError';
    this.reason = reason;
  }
}

const EXPECTED_ROOT_ENTRIES = [
  'README.md',
  'golden-corpus.snapshot.json',
  'prior-release-must-detect.manifest.json',
  'sources'
];

export async function loadAndValidateGoldenCorpus(corpusRoot = GOLDEN_CORPUS_ROOT) {
  const root = resolve(corpusRoot);
  const rootStat = await guardedLstat(root, 'ROOT_INVALID');
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) reject('ROOT_INVALID');
  const canonicalRoot = await guardedRealpath(root, 'ROOT_INVALID');
  await assertExactRootEntries(root, rootStat, canonicalRoot);

  const priorReleaseManifestPath = resolveInside(
    root,
    'prior-release-must-detect.manifest.json'
  );
  const priorReleaseManifestStat = await guardedLstat(
    priorReleaseManifestPath,
    'PRIOR_RELEASE_MANIFEST_INVALID'
  );
  if (
    !priorReleaseManifestStat.isFile() ||
    priorReleaseManifestStat.isSymbolicLink()
  ) {
    reject('PRIOR_RELEASE_MANIFEST_INVALID');
  }
  const priorReleaseManifestBuffer = await guardedRead(
    priorReleaseManifestPath,
    'PRIOR_RELEASE_MANIFEST_INVALID',
    canonicalRoot
  );
  if (
    priorReleaseManifestBuffer.byteLength === 0 ||
    priorReleaseManifestBuffer.byteLength > 4 * 1024 * 1024
  ) {
    reject('PRIOR_RELEASE_MANIFEST_INVALID');
  }
  const priorReleaseManifestText = decodeCanonicalText(
    priorReleaseManifestBuffer,
    'PRIOR_RELEASE_MANIFEST_INVALID'
  );
  let priorReleaseManifest;
  try {
    priorReleaseManifest = JSON.parse(priorReleaseManifestText);
  } catch {
    reject('PRIOR_RELEASE_MANIFEST_INVALID');
  }
  if (
    !isSastQualificationPriorReleaseManifestValid(priorReleaseManifest, digest) ||
    priorReleaseManifest.manifestDigest !==
      GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_DIGEST ||
    priorReleaseManifestText !==
      `${JSON.stringify(priorReleaseManifest, null, 2)}\n`
  ) {
    reject('PRIOR_RELEASE_MANIFEST_INVALID');
  }

  let expected;
  try {
    expected = createGoldenCorpusAssets(priorReleaseManifest);
  } catch {
    reject('PRIOR_RELEASE_SET_INCOMPLETE');
  }
  const snapshotPath = resolveInside(root, 'golden-corpus.snapshot.json');
  const snapshotStat = await guardedLstat(snapshotPath, 'SNAPSHOT_INVALID');
  if (!snapshotStat.isFile() || snapshotStat.isSymbolicLink()) {
    reject('SNAPSHOT_INVALID');
  }
  const snapshotBuffer = await guardedRead(
    snapshotPath,
    'SNAPSHOT_INVALID',
    canonicalRoot
  );
  if (snapshotBuffer.byteLength === 0 || snapshotBuffer.byteLength > 8 * 1024 * 1024) {
    reject('SNAPSHOT_INVALID');
  }
  const snapshotText = decodeCanonicalText(snapshotBuffer, 'SNAPSHOT_INVALID');
  const expectedSnapshotText = `${JSON.stringify(expected.snapshot, null, 2)}\n`;
  if (snapshotText !== expectedSnapshotText) reject('SNAPSHOT_DRIFT');

  let snapshot;
  try {
    snapshot = JSON.parse(snapshotText);
  } catch {
    reject('SNAPSHOT_INVALID');
  }
  if (
    !isSastQualificationCorpusSnapshotValid(
      snapshot,
      digest,
      priorReleaseManifest
    )
  ) {
    reject('SNAPSHOT_INVALID');
  }

  const expectedSourcePaths = [...new Set(snapshot.cases.map((item) => item.sourcePath))]
    .sort(compareText);
  const generatedSourcePaths = [...expected.sources.keys()].sort(compareText);
  if (!arraysEqual(expectedSourcePaths, generatedSourcePaths)) {
    reject('SOURCE_SET_INVALID');
  }
  const actualSourcePaths = await listRegularFiles(root, 'sources');
  if (!arraysEqual(actualSourcePaths, expectedSourcePaths)) {
    reject('SOURCE_SET_INVALID');
  }

  const scanPaths = snapshot.cases.map((item) => item.scanPath);
  if (new Set(scanPaths).size !== scanPaths.length) reject('CASE_RANGE_INVALID');
  for (const sourcePath of expectedSourcePaths) {
    const absolute = resolveInside(root, sourcePath);
    const canonical = await guardedRealpath(absolute, 'SOURCE_PATH_INVALID');
    ensureInside(canonicalRoot, canonical, 'SOURCE_PATH_INVALID');
    const stat = await guardedLstat(absolute, 'SOURCE_PATH_INVALID');
    if (!stat.isFile() || stat.isSymbolicLink()) reject('SOURCE_PATH_INVALID');
    const buffer = await guardedRead(absolute, 'SOURCE_INVALID', canonicalRoot);
    if (
      buffer.byteLength === 0 ||
      buffer.byteLength > SAST_QUALIFICATION_CORPUS_LIMITS.maximumSourceBytes
    ) {
      reject('SOURCE_INVALID');
    }
    const text = decodeCanonicalText(buffer, 'SOURCE_INVALID');
    const generated = expected.sources.get(sourcePath);
    if (
      typeof generated !== 'string' ||
      text !== generated ||
      digest(text) !== digest(generated)
    ) {
      reject('SOURCE_DRIFT');
    }
    const lines = text.split('\n');
    for (const item of snapshot.cases.filter(
      (candidate) => candidate.sourcePath === sourcePath
    )) {
      if (
        item.sourceBytes !== buffer.byteLength ||
        item.sourceDigest !== digest(text) ||
        item.startLine < 1 ||
        item.endLine < item.startLine ||
        item.endLine > lines.length
      ) {
        reject('CASE_RANGE_INVALID');
      }
      const boundedSource = lines.slice(item.startLine - 1, item.endLine).join('\n');
      if (!boundedSource.includes(item.expectedAnchor)) {
        reject('CASE_RANGE_INVALID');
      }
    }
  }

  await assertStableDirectory(root, rootStat, canonicalRoot, 'ROOT_INVALID');

  return Object.freeze({
    corpusId: snapshot.corpusId,
    snapshotDigest: snapshot.snapshotDigest,
    caseCount: snapshot.caseCount,
    positiveCaseCount: snapshot.positiveCaseCount,
    negativeCaseCount: snapshot.negativeCaseCount,
    priorMustDetectCaseCount: snapshot.priorMustDetectCaseCount,
    priorReleaseRef: snapshot.priorReleaseRef,
    priorReleaseManifestDigest: snapshot.priorReleaseManifestDigest,
    sourceBundleCount: expectedSourcePaths.length,
    profileCounts: snapshot.profileCounts.map((item) => Object.freeze({ ...item }))
  });
}

async function listRegularFiles(root, relativeDirectory) {
  const start = resolveInside(root, relativeDirectory);
  const output = [];
  await walk(root, start, output);
  return output.sort(compareText);
}

async function assertExactRootEntries(root, rootStat, canonicalRoot) {
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    reject('ROOT_ENTRIES_INVALID');
  }
  entries.sort((left, right) => compareText(left.name, right.name));
  if (!arraysEqual(entries.map((entry) => entry.name), EXPECTED_ROOT_ENTRIES)) {
    reject('ROOT_ENTRIES_INVALID');
  }
  for (const entry of entries) {
    const stat = await guardedLstat(join(root, entry.name), 'ROOT_ENTRIES_INVALID');
    if (
      entry.isSymbolicLink() ||
      stat.isSymbolicLink() ||
      (entry.name === 'sources'
        ? !entry.isDirectory() || !stat.isDirectory()
        : !entry.isFile() || !stat.isFile())
    ) {
      reject('ROOT_ENTRIES_INVALID');
    }
  }
  await assertStableDirectory(root, rootStat, canonicalRoot, 'ROOT_ENTRIES_INVALID');
}

async function walk(root, directory, output) {
  const stat = await guardedLstat(directory, 'SOURCE_PATH_INVALID');
  if (!stat.isDirectory() || stat.isSymbolicLink()) reject('SOURCE_PATH_INVALID');
  const canonicalRoot = await guardedRealpath(root, 'ROOT_INVALID');
  const canonicalDirectory = await guardedRealpath(directory, 'SOURCE_PATH_INVALID');
  ensureInside(canonicalRoot, canonicalDirectory, 'SOURCE_PATH_INVALID');
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    reject('SOURCE_PATH_INVALID');
  }
  entries.sort((left, right) => compareText(left.name, right.name));
  for (const entry of entries) {
    const absolute = join(directory, entry.name);
    const entryStat = await guardedLstat(absolute, 'SOURCE_PATH_INVALID');
    if (entry.isSymbolicLink() || entryStat.isSymbolicLink()) {
      reject('SOURCE_PATH_INVALID');
    }
    if (entry.isDirectory() && entryStat.isDirectory()) {
      await walk(root, absolute, output);
    } else if (entry.isFile() && entryStat.isFile()) {
      const canonical = await guardedRealpath(absolute, 'SOURCE_PATH_INVALID');
      ensureInside(canonicalRoot, canonical, 'SOURCE_PATH_INVALID');
      output.push(relative(root, absolute).replaceAll('\\', '/'));
    } else {
      reject('SOURCE_PATH_INVALID');
    }
  }
  await assertStableDirectory(
    directory,
    stat,
    canonicalDirectory,
    'SOURCE_PATH_INVALID'
  );
}

function resolveInside(root, relativePath) {
  if (
    typeof relativePath !== 'string' ||
    relativePath.length === 0 ||
    relativePath.includes('\\') ||
    relativePath.startsWith('/') ||
    relativePath.split('/').some((part) => part === '' || part === '.' || part === '..')
  ) {
    reject('SOURCE_PATH_INVALID');
  }
  const output = resolve(root, ...relativePath.split('/'));
  ensureInside(root, output, 'SOURCE_PATH_INVALID');
  return output;
}

function ensureInside(root, candidate, reason) {
  const relation = relative(root, candidate);
  if (relation === '' || relation.startsWith('..') || relation.includes(':')) {
    reject(reason);
  }
}

function decodeCanonicalText(buffer, reason) {
  let value;
  try {
    value = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    reject(reason);
  }
  if (
    value.startsWith('\uFEFF') ||
    value.includes('\r') ||
    value.includes('\0') ||
    !value.endsWith('\n') ||
    value !== value.normalize('NFC')
  ) {
    reject(reason);
  }
  return value;
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

async function guardedRead(path, reason, canonicalRoot) {
  const before = await guardedLstat(path, reason);
  if (!before.isFile() || before.isSymbolicLink()) reject(reason);
  const canonicalBefore = await guardedRealpath(path, reason);
  ensureInside(canonicalRoot, canonicalBefore, reason);
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
    );
  } catch {
    reject(reason);
  }
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameEntryIdentity(before, opened)) reject(reason);
    const buffer = await handle.readFile();
    const openedAfter = await handle.stat({ bigint: true });
    const after = await guardedLstat(path, reason);
    const canonicalAfter = await guardedRealpath(path, reason);
    if (
      !sameEntryIdentity(opened, openedAfter) ||
      !sameEntryIdentity(before, after) ||
      canonicalAfter !== canonicalBefore
    ) {
      reject(reason);
    }
    ensureInside(canonicalRoot, canonicalAfter, reason);
    return buffer;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

async function assertStableDirectory(path, before, canonicalBefore, reason) {
  const after = await guardedLstat(path, reason);
  const canonicalAfter = await guardedRealpath(path, reason);
  if (
    !after.isDirectory() ||
    after.isSymbolicLink() ||
    !sameEntryIdentity(before, after) ||
    canonicalAfter !== canonicalBefore
  ) {
    reject(reason);
  }
}

function sameEntryIdentity(left, right) {
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

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function reject(reason) {
  throw new SastQualificationCorpusLoadError(reason);
}
