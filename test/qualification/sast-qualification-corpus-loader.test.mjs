import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  SAST_QUALIFICATION_CORPUS_LIMITS,
  buildSastQualificationPriorReleaseManifest
} from '../../packages/shared/dist/index.js';
import {
  SastQualificationCorpusLoadError,
  loadAndValidateGoldenCorpus
} from '../../tools/sast-qualification/corpus-loader.mjs';
import {
  initializePriorReleaseManifest
} from '../../tools/sast-qualification/golden-corpus-assets.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const canonicalCorpusRoot = join(repositoryRoot, 'qualification', 'corpora', 'v1');
const representativeSource = join(
  'sources',
  'common',
  'aws-access-key.positive.bundle'
);
const javaSafeFlowSinks = new Map([
  ['aegis.java.cwe-89.sql-injection', /\.executeQuery\(/u],
  ['aegis.java.cwe-78.command-injection', /\.start\(\)/u],
  ['aegis.java.cwe-22.path-traversal', /Files\.readString\(/u],
  ['aegis.java.cwe-918.ssrf', /\.openConnection\(\)/u],
  ['aegis.java.cwe-90.ldap-injection', /\.search\(/u],
  ['aegis.java.cwe-643.xpath-injection', /\.evaluate\(/u],
  ['aegis.java.cwe-502.unsafe-deserialization', /\.(?:readObject|readUTF)\(/u],
  ['aegis.java.cwe-611.xxe', /\.parse\(/u],
  ['aegis.java.cwe-327.weak-crypto', /\.(?:digest|doFinal)\(/u],
  ['aegis.java.cwe-117.log-injection', /\.log\(/u]
]);

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

test('T051 loader pins the reviewed prior-release manifest digest', async (t) => {
  const root = await copyCorpus(t);
  const manifestPath = join(root, 'prior-release-must-detect.manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const rebuilt = buildSastQualificationPriorReleaseManifest(
    {
      releaseRevision: manifest.releaseRevision,
      publishedAt: manifest.publishedAt,
      ownerRef: manifest.ownerRef,
      provenanceRef: manifest.provenanceRef,
      bindings: manifest.bindings.slice(1)
    },
    digest
  );
  assert.ok(rebuilt);
  await writeFile(manifestPath, `${JSON.stringify(rebuilt, null, 2)}\n`, 'utf8');

  await assertLoadError(root, 'PRIOR_RELEASE_MANIFEST_INVALID');
});

test('T051 prior-release manifest bootstrap refuses overwrite', async () => {
  await assert.rejects(
    initializePriorReleaseManifest(),
    /refusing to overwrite immutable prior-release must-detect manifest/u
  );
});

test('T051 negative fixtures match their declared behavior class', async () => {
  const snapshot = JSON.parse(
    await readFile(join(canonicalCorpusRoot, 'golden-corpus.snapshot.json'), 'utf8')
  );
  const sourceCache = new Map();
  const counts = Object.fromEntries(
    snapshot.negativeKindCounts.map((item) => [item.negativeKind, item.cases])
  );
  assert.deepEqual(counts, {
    PATCHED: 95,
    SANITIZER: 35,
    SAFE_API: 95,
    COMMENT_OR_STRING: 80,
    GENERATED_OR_VENDOR: 95
  });

  for (const corpusCase of snapshot.cases.filter(
    (item) => item.corpusClass === 'GOLDEN_NEGATIVE'
  )) {
    let source = sourceCache.get(corpusCase.sourcePath);
    if (!source) {
      source = await readFile(join(canonicalCorpusRoot, corpusCase.sourcePath), 'utf8');
      sourceCache.set(corpusCase.sourcePath, source);
    }
    const snippet = source
      .split('\n')
      .slice(corpusCase.startLine - 1, corpusCase.endLine)
      .join('\n');
    assert.match(
      snippet,
      new RegExp(
        `(?:t051-negative-kind: ${corpusCase.negativeKind}|qualificationNegativeKind": "${corpusCase.negativeKind})`,
        'u'
      )
    );

    if (corpusCase.negativeKind === 'GENERATED_OR_VENDOR') {
      assert.match(corpusCase.scanPath, /\/(?:generated|vendor)\//u);
      assert.doesNotMatch(snippet, /documentation only/u);
    } else {
      assert.doesNotMatch(corpusCase.scanPath, /\/(?:generated|vendor)\//u);
    }
    if (corpusCase.negativeKind === 'COMMENT_OR_STRING') {
      assert.match(snippet, /documentation only/u);
    }
    if (corpusCase.negativeKind === 'SANITIZER') {
      assert.match(snippet, /(?:sanitized|\[REDACTED\])/u);
    }
    if (corpusCase.negativeKind === 'SAFE_API') {
      assert.match(snippet, /(?:SAFE_API|PreparedStatement|allowed|startsWith|VariableResolver|DataInputStream|SAXParserFactory|HmacSHA256|LogRecord)/u);
    }
    if (
      corpusCase.language === 'JAVA' &&
      ['PATCHED', 'SANITIZER', 'SAFE_API'].includes(corpusCase.negativeKind)
    ) {
      const sink = javaSafeFlowSinks.get(corpusCase.ruleSemanticId);
      assert.ok(sink);
      assert.match(snippet, sink);
    }
  }
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

test('T051 loader rejects unexpected corpus-root entries', async (t) => {
  const root = await copyCorpus(t);
  await writeFile(join(root, 'unregistered.json'), '{}\n', 'utf8');

  await assertLoadError(root, 'ROOT_ENTRIES_INVALID');
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

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
