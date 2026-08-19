import assert from 'node:assert/strict';
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { SAST_MULTI_CLASS_QUALIFICATION_LIMITS } from '../../packages/shared/dist/index.js';
import {
  SastMultiClassCorpusLoadError,
  loadAndValidateMultiClassCorpus
} from '../../tools/sast-qualification/multi-class-corpus-loader.mjs';
import { initializeMultiClassCorpusAssets } from '../../tools/sast-qualification/multi-class-corpus-assets.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const canonicalCorpusRoot = join(
  repositoryRoot,
  'qualification',
  'corpora',
  't052-v1'
);
const representativeFixture = join(
  'fixtures',
  'schema-parser',
  'malformed-syntax.fixture.json'
);

test('T052 loader accepts only the canonical immutable multi-class corpus', async () => {
  const result = await loadAndValidateMultiClassCorpus();
  assert.equal(result.caseCount, 84);
  assert.equal(result.fixtureCount, 84);
  assert.equal(result.classCounts.length, 5);
  assert.equal(result.profileCounts.length, 3);
  assert.equal(result.cases.length, 84);
  assert.match(
    result.corpusId,
    /^sast-multi-class-qualification-corpus:\/\/[a-f0-9]{64}$/u
  );
  assert.match(result.snapshotDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.match(
    result.performanceHardwareClassRef,
    /^hardware-class:\/\/[^\s]+\/sha256:[a-f0-9]{64}$/u
  );
  assert.throws(() => result.cases.push(result.cases[0]), TypeError);
  assert.throws(() => result.cases[0].case.profiles.push('JAVA_FAST_V1'), TypeError);
  assert.throws(
    () => {
      result.cases[0].fixture.parameters[0].stringValue = 'changed';
    },
    TypeError
  );
});

test('T052 corpus bootstrap refuses to overwrite the immutable root', async () => {
  await assert.rejects(
    initializeMultiClassCorpusAssets(),
    /refusing to overwrite existing T052 corpus root/u
  );
});

test('T052 loader rejects snapshot and fixture byte drift', async (t) => {
  const snapshotRoot = await copyCorpus(t);
  const snapshotPath = join(snapshotRoot, 'multi-class-corpus.snapshot.json');
  const snapshot = await readFile(snapshotPath, 'utf8');
  const changedSnapshot = snapshot.replace('"caseCount": 84', '"caseCount": 83');
  assert.notEqual(changedSnapshot, snapshot);
  await writeFile(snapshotPath, changedSnapshot, 'utf8');
  await assertLoadError(snapshotRoot, 'SNAPSHOT_DRIFT');

  const fixtureRoot = await copyCorpus(t);
  const fixturePath = join(fixtureRoot, representativeFixture);
  const fixture = await readFile(fixturePath, 'utf8');
  await writeFile(
    fixturePath,
    fixture.replace('"MALFORMED_SYNTAX"', '"UNKNOWN_ENUM"'),
    'utf8'
  );
  await assertLoadError(fixtureRoot, 'FIXTURE_DRIFT');
});

test('T052 loader rejects missing, extra, and empty fixture-tree entries', async (t) => {
  const missingRoot = await copyCorpus(t);
  await rm(join(missingRoot, representativeFixture));
  await assertLoadError(missingRoot, 'FIXTURE_SET_INVALID');

  const extraRoot = await copyCorpus(t);
  await writeFile(
    join(extraRoot, 'fixtures', 'schema-parser', 'unregistered.fixture.json'),
    '{}\n',
    'utf8'
  );
  await assertLoadError(extraRoot, 'FIXTURE_SET_INVALID');

  const directoryRoot = await copyCorpus(t);
  await mkdir(join(directoryRoot, 'fixtures', 'unregistered-empty'));
  await assertLoadError(directoryRoot, 'FIXTURE_SET_INVALID');
});

test('T052 loader rejects unexpected corpus-root entries', async (t) => {
  const root = await copyCorpus(t);
  await writeFile(join(root, 'unregistered.json'), '{}\n', 'utf8');
  await assertLoadError(root, 'ROOT_ENTRIES_INVALID');
});

test('T052 loader rejects invalid encoding, CRLF, BOM, NUL, non-NFC, missing final LF, and oversize', async (t) => {
  const mutations = [
    {
      value: Buffer.from([0xff, 0x0a]),
      reason: 'FIXTURE_INVALID'
    },
    {
      mutate: (value) => value.replace('\n', '\r\n'),
      reason: 'FIXTURE_INVALID'
    },
    {
      mutate: (value) => `\uFEFF${value}`,
      reason: 'FIXTURE_INVALID'
    },
    {
      mutate: (value) => value.replace('\n', '\0\n'),
      reason: 'FIXTURE_INVALID'
    },
    {
      mutate: (value) => value.replace('version', 'versio\u0301n'),
      reason: 'FIXTURE_INVALID'
    },
    {
      mutate: (value) => value.slice(0, -1),
      reason: 'FIXTURE_INVALID'
    },
    {
      value: Buffer.alloc(
        SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumFixtureBytes + 1,
        0x61
      ),
      reason: 'FIXTURE_INVALID'
    }
  ];
  for (const mutation of mutations) {
    const root = await copyCorpus(t);
    const path = join(root, representativeFixture);
    const current = await readFile(path, 'utf8');
    await writeFile(path, mutation.value ?? mutation.mutate(current));
    await assertLoadError(root, mutation.reason);
  }
});

test('T052 loader rejects symlink or junction entries', async (t) => {
  const root = await copyCorpus(t);
  const target = join(root, 'fixtures', 'schema-parser');
  const link = join(root, 'fixtures', 'linked');
  try {
    await symlink(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip(`symlink creation is unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  await assertLoadError(root, 'FIXTURE_SET_INVALID');
});

test('T052 fixture files remain declarative and never contain executable fields', async () => {
  const snapshot = JSON.parse(
    await readFile(join(canonicalCorpusRoot, 'multi-class-corpus.snapshot.json'), 'utf8')
  );
  for (const item of snapshot.cases) {
    const fixture = JSON.parse(
      await readFile(join(canonicalCorpusRoot, item.fixturePath), 'utf8')
    );
    assert.equal(fixture.executable, false);
    assert.equal(fixture.packageInstallRequired, false);
    assert.equal(fixture.buildRequired, false);
    assert.equal(fixture.dynamicExecutionRequired, false);
    assert.equal(fixture.networkRequired, false);
    assert.equal(fixture.hostMutationAllowed, false);
    assert.equal('command' in fixture, false);
    assert.equal('argv' in fixture, false);
    assert.equal('environment' in fixture, false);
    assert.ok(
      fixture.steps.every((step) =>
        step.arguments.every(
          (argument) =>
            !/^(?:argv|command|environment|executable|script|shell|url)=/iu.test(
              argument
            )
        )
      )
    );
  }
});

async function copyCorpus(t) {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'aegis-t052-corpus-'));
  const root = join(temporaryRoot, 'corpus');
  await cp(canonicalCorpusRoot, root, { recursive: true });
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  return root;
}

async function assertLoadError(root, reason) {
  await assert.rejects(
    loadAndValidateMultiClassCorpus(root),
    (error) =>
      error instanceof SastMultiClassCorpusLoadError && error.reason === reason
  );
}
