import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';

import {
  SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES,
  SAST_MULTI_CLASS_QUALIFICATION_LIMITS,
  isSastMultiClassQualificationFixtureValid,
  isSastMultiClassQualificationSnapshotValid
} from '../../packages/shared/dist/index.js';
import {
  MULTI_CLASS_CORPUS_ROOT,
  createMultiClassCorpusAssets
} from './multi-class-corpus-assets.mjs';

export class SastMultiClassCorpusLoadError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'SastMultiClassCorpusLoadError';
    this.reason = reason;
  }
}

const EXPECTED_ROOT_ENTRIES = [
  'README.md',
  'fixtures',
  'multi-class-corpus.snapshot.json'
];
const SNAPSHOT_MAXIMUM_BYTES = 4 * 1024 * 1024;
const README_MAXIMUM_BYTES = 16 * 1024;

export async function loadAndValidateMultiClassCorpus(
  corpusRoot = MULTI_CLASS_CORPUS_ROOT
) {
  const root = resolve(corpusRoot);
  const rootStat = await guardedLstat(root, 'ROOT_INVALID');
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) reject('ROOT_INVALID');
  const canonicalRoot = await guardedRealpath(root, 'ROOT_INVALID');
  await assertExactRootEntries(root, rootStat, canonicalRoot);

  const expected = createMultiClassCorpusAssets();
  const readmePath = resolveInside(root, 'README.md');
  const readmeBuffer = await guardedRead(
    readmePath,
    'README_INVALID',
    canonicalRoot,
    README_MAXIMUM_BYTES
  );
  const readmeText = decodeCanonicalText(readmeBuffer, 'README_INVALID');
  if (readmeText !== expected.readmeText) reject('README_DRIFT');

  const snapshotPath = resolveInside(root, 'multi-class-corpus.snapshot.json');
  const snapshotBuffer = await guardedRead(
    snapshotPath,
    'SNAPSHOT_INVALID',
    canonicalRoot,
    SNAPSHOT_MAXIMUM_BYTES
  );
  const snapshotText = decodeCanonicalText(snapshotBuffer, 'SNAPSHOT_INVALID');
  if (snapshotText !== expected.snapshotText) reject('SNAPSHOT_DRIFT');
  const snapshot = parseJson(snapshotText, 'SNAPSHOT_INVALID');
  if (!isSastMultiClassQualificationSnapshotValid(snapshot, digest)) {
    reject('SNAPSHOT_INVALID');
  }

  const fixtureRoot = resolveInside(root, 'fixtures');
  const actualFixturePaths = await assertExactFixtureTree(
    root,
    fixtureRoot,
    canonicalRoot,
    expected.fixtures
  );
  const expectedFixturePaths = [...expected.fixtures.keys()].sort(compareText);
  if (!arraysEqual(actualFixturePaths, expectedFixturePaths)) {
    reject('FIXTURE_SET_INVALID');
  }

  const casesByFixturePath = new Map(
    snapshot.cases.map((item) => [item.fixturePath, item])
  );
  const loadedCases = [];
  for (const fixturePath of expectedFixturePaths) {
    const item = casesByFixturePath.get(fixturePath);
    if (!item) reject('FIXTURE_BINDING_INVALID');
    const absolute = resolveInside(root, fixturePath);
    const buffer = await guardedRead(
      absolute,
      'FIXTURE_INVALID',
      canonicalRoot,
      SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumFixtureBytes
    );
    const text = decodeCanonicalText(buffer, 'FIXTURE_INVALID');
    const expectedText = expected.fixtures.get(fixturePath);
    if (text !== expectedText) reject('FIXTURE_DRIFT');
    const fixture = parseJson(text, 'FIXTURE_INVALID');
    if (!isSastMultiClassQualificationFixtureValid(fixture, digest)) {
      reject('FIXTURE_INVALID');
    }
    if (
      buffer.byteLength !== item.fixtureBytes ||
      fixture.caseKey !== item.caseKey ||
      fixture.corpusClass !== item.corpusClass ||
      fixture.scenario !== item.scenario ||
      fixture.materializationKind !== item.materializationKind ||
      fixture.fixtureId !== item.fixtureId ||
      fixture.fixtureDigest !== item.fixtureDigest
    ) {
      reject('FIXTURE_BINDING_INVALID');
    }
    loadedCases.push(freezeJsonTree({ case: item, fixture }));
  }
  if (
    loadedCases.length !== snapshot.caseCount ||
    loadedCases.length !== snapshot.fixtureCount
  ) {
    reject('FIXTURE_SET_INVALID');
  }
  await assertStableDirectory(root, rootStat, canonicalRoot, 'ROOT_INVALID');
  return Object.freeze({
    corpusId: snapshot.corpusId,
    snapshotDigest: snapshot.snapshotDigest,
    caseCount: snapshot.caseCount,
    fixtureCount: snapshot.fixtureCount,
    classCounts: Object.freeze(
      snapshot.classCounts.map((item) => Object.freeze({ ...item }))
    ),
    profileCounts: Object.freeze(
      snapshot.profileCounts.map((item) => Object.freeze({ ...item }))
    ),
    performanceHardwareClassRef: snapshot.performanceHardwareClassRef,
    cases: Object.freeze(loadedCases)
  });
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
      (entry.name === 'fixtures'
        ? !entry.isDirectory() || !stat.isDirectory()
        : !entry.isFile() || !stat.isFile())
    ) {
      reject('ROOT_ENTRIES_INVALID');
    }
  }
  await assertStableDirectory(
    root,
    rootStat,
    canonicalRoot,
    'ROOT_ENTRIES_INVALID'
  );
}

async function assertExactFixtureTree(root, fixtureRoot, canonicalRoot, expectedFixtures) {
  const fixtureRootStat = await guardedLstat(fixtureRoot, 'FIXTURE_SET_INVALID');
  if (!fixtureRootStat.isDirectory() || fixtureRootStat.isSymbolicLink()) {
    reject('FIXTURE_SET_INVALID');
  }
  const canonicalFixtureRoot = await guardedRealpath(
    fixtureRoot,
    'FIXTURE_SET_INVALID'
  );
  ensureInside(canonicalRoot, canonicalFixtureRoot, 'FIXTURE_SET_INVALID');
  const classEntries = await guardedReadDirectory(
    fixtureRoot,
    'FIXTURE_SET_INVALID'
  );
  const expectedClassDirectories = SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES.map(
    slug
  ).sort(compareText);
  if (!arraysEqual(classEntries.map((entry) => entry.name), expectedClassDirectories)) {
    reject('FIXTURE_SET_INVALID');
  }
  const output = [];
  for (const classEntry of classEntries) {
    const classDirectory = join(fixtureRoot, classEntry.name);
    const classStat = await guardedLstat(classDirectory, 'FIXTURE_SET_INVALID');
    if (
      classEntry.isSymbolicLink() ||
      !classEntry.isDirectory() ||
      classStat.isSymbolicLink() ||
      !classStat.isDirectory()
    ) {
      reject('FIXTURE_SET_INVALID');
    }
    const canonicalClassDirectory = await guardedRealpath(
      classDirectory,
      'FIXTURE_SET_INVALID'
    );
    ensureInside(canonicalRoot, canonicalClassDirectory, 'FIXTURE_SET_INVALID');
    const entries = await guardedReadDirectory(classDirectory, 'FIXTURE_SET_INVALID');
    const expectedBasenames = [...expectedFixtures.keys()]
      .filter((path) => path.startsWith(`fixtures/${classEntry.name}/`))
      .map((path) => basename(path))
      .sort(compareText);
    if (!arraysEqual(entries.map((entry) => entry.name), expectedBasenames)) {
      reject('FIXTURE_SET_INVALID');
    }
    for (const entry of entries) {
      const absolute = join(classDirectory, entry.name);
      const stat = await guardedLstat(absolute, 'FIXTURE_SET_INVALID');
      if (
        entry.isSymbolicLink() ||
        !entry.isFile() ||
        stat.isSymbolicLink() ||
        !stat.isFile()
      ) {
        reject('FIXTURE_SET_INVALID');
      }
      const canonical = await guardedRealpath(absolute, 'FIXTURE_SET_INVALID');
      ensureInside(canonicalRoot, canonical, 'FIXTURE_SET_INVALID');
      output.push(relative(root, absolute).replaceAll('\\', '/'));
    }
    await assertStableDirectory(
      classDirectory,
      classStat,
      canonicalClassDirectory,
      'FIXTURE_SET_INVALID'
    );
  }
  await assertStableDirectory(
    fixtureRoot,
    fixtureRootStat,
    canonicalFixtureRoot,
    'FIXTURE_SET_INVALID'
  );
  return output.sort(compareText);
}

async function guardedReadDirectory(path, reason) {
  try {
    return (await readdir(path, { withFileTypes: true })).sort((left, right) =>
      compareText(left.name, right.name)
    );
  } catch {
    reject(reason);
  }
}

function resolveInside(root, relativePath) {
  const candidate = resolve(root, relativePath);
  const relation = relative(root, candidate);
  if (relation === '' || relation.startsWith('..') || relation.includes(':')) {
    reject('PATH_INVALID');
  }
  return candidate;
}

function ensureInside(root, candidate, reason) {
  const relation = relative(root, candidate);
  if (relation === '' || relation.startsWith('..') || relation.includes(':')) reject(reason);
}

function decodeCanonicalText(buffer, reason) {
  let value;
  try {
    value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer);
  } catch {
    reject(reason);
  }
  if (
    value.startsWith('\uFEFF') ||
    value.includes('\r') ||
    value.includes('\0') ||
    value !== value.normalize('NFC') ||
    !value.endsWith('\n')
  ) {
    reject(reason);
  }
  return value;
}

function parseJson(value, reason) {
  try {
    return JSON.parse(value);
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

async function guardedRead(path, reason, canonicalRoot, maximumBytes) {
  const before = await guardedLstat(path, reason);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.size <= 0n ||
    before.size > BigInt(maximumBytes)
  ) {
    reject(reason);
  }
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
    if (
      !opened.isFile() ||
      opened.size <= 0n ||
      opened.size > BigInt(maximumBytes) ||
      !sameStableIdentity(before, opened)
    ) {
      reject(reason);
    }
    const buffer = await handle.readFile();
    const openedAfter = await handle.stat({ bigint: true });
    const after = await guardedLstat(path, reason);
    const canonicalAfter = await guardedRealpath(path, reason);
    if (
      buffer.byteLength > maximumBytes ||
      !sameStableIdentity(opened, openedAfter) ||
      !sameStableIdentity(before, after) ||
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
    !sameStableIdentity(before, after) ||
    canonicalAfter !== canonicalBefore
  ) {
    reject(reason);
  }
}

function sameStableIdentity(left, right) {
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

function freezeJsonTree(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) freezeJsonTree(child, seen);
  return Object.freeze(value);
}

function slug(value) {
  return value.toLowerCase().replaceAll('_', '-');
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function reject(reason) {
  throw new SastMultiClassCorpusLoadError(reason);
}
