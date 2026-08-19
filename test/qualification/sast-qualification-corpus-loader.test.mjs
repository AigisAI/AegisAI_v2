import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { SAST_QUALIFICATION_CORPUS_LIMITS } from '../../packages/shared/dist/index.js';
import {
  SastQualificationCorpusLoadError,
  loadAndValidateGoldenCorpus
} from '../../tools/sast-qualification/corpus-loader.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const canonicalCorpusRoot = join(repositoryRoot, 'qualification', 'corpora', 'v1');
const representativeSource = join(
  'sources',
  'common',
  'aws-access-key.positive.bundle'
);

test('T051 loader accepts only the canonical immutable golden corpus', async () => {
  const result = await loadAndValidateGoldenCorpus();

  assert.equal(result.caseCount, 800);
  assert.equal(result.positiveCaseCount, 400);
  assert.equal(result.negativeCaseCount, 400);
  assert.equal(result.priorMustDetectCaseCount, 400);
  assert.equal(result.sourceBundleCount, 40);
  assert.equal(result.profileCounts.length, 3);
  assert.match(result.corpusId, /^sast-qualification-corpus:\/\/golden\/[a-f0-9]{64}$/u);
  assert.match(result.snapshotDigest, /^sha256:[a-f0-9]{64}$/u);
});

test('T051 loader rejects snapshot byte and count drift before use', async (t) => {
  const root = await copyCorpus(t);
  const snapshotPath = join(root, 'golden-corpus.snapshot.json');
  const current = await readFile(snapshotPath, 'utf8');
  const tampered = current.replace('"caseCount": 800', '"caseCount": 799');
  assert.notEqual(tampered, current);
  await writeFile(snapshotPath, tampered, 'utf8');

  await assertLoadError(root, 'SNAPSHOT_DRIFT');
});

test('T051 loader rejects source drift and CRLF ambiguity', async (t) => {
  const driftRoot = await copyCorpus(t);
  const driftPath = join(driftRoot, representativeSource);
  await writeFile(driftPath, `${await readFile(driftPath, 'utf8')}# drift\n`, 'utf8');
  await assertLoadError(driftRoot, 'SOURCE_DRIFT');

  const crlfRoot = await copyCorpus(t);
  const crlfPath = join(crlfRoot, representativeSource);
  const current = await readFile(crlfPath, 'utf8');
  await writeFile(crlfPath, current.replace('\n', '\r\n'), 'utf8');
  await assertLoadError(crlfRoot, 'SOURCE_INVALID');
});

test('T051 loader rejects oversized source bundles', async (t) => {
  const root = await copyCorpus(t);
  await writeFile(
    join(root, representativeSource),
    Buffer.alloc(SAST_QUALIFICATION_CORPUS_LIMITS.maximumSourceBytes + 1, 0x61)
  );

  await assertLoadError(root, 'SOURCE_INVALID');
});

test('T051 loader rejects unregistered source files', async (t) => {
  const root = await copyCorpus(t);
  await writeFile(join(root, 'sources', 'extra.bundle'), 'unregistered\n', 'utf8');

  await assertLoadError(root, 'SOURCE_SET_INVALID');
});

test('T051 loader rejects symlink or junction traversal', async (t) => {
  const root = await copyCorpus(t);
  const target = join(root, 'sources', 'common');
  const link = join(root, 'sources', 'linked');
  try {
    await symlink(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip(`symlink creation is unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  await assertLoadError(root, 'SOURCE_PATH_INVALID');
});

async function copyCorpus(t) {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'aegis-t051-corpus-'));
  const root = join(temporaryRoot, 'corpus');
  await cp(canonicalCorpusRoot, root, { recursive: true });
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  return root;
}

async function assertLoadError(root, reason) {
  await assert.rejects(
    loadAndValidateGoldenCorpus(root),
    (error) =>
      error instanceof SastQualificationCorpusLoadError && error.reason === reason
  );
}
