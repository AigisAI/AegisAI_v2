import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  SAST_PROFILE_IDS,
  SAST_QUALIFICATION_CORPUS_LIMITS,
  SAST_QUALIFICATION_NEGATIVE_KINDS,
  buildSastQualificationCorpusCase,
  buildSastQualificationCorpusSnapshot,
  buildSastQualificationPriorReleaseManifest,
  isSastQualificationCorpusCaseValid,
  isSastQualificationCorpusSnapshotValid,
  isSastQualificationPriorReleaseManifestValid
} from '../dist/index.js';

const snapshot = JSON.parse(
  readFileSync(
    new URL(
      '../../../qualification/corpora/v1/golden-corpus.snapshot.json',
      import.meta.url
    ),
    'utf8'
  )
);
const priorReleaseManifest = JSON.parse(
  readFileSync(
    new URL(
      '../../../qualification/corpora/v1/prior-release-must-detect.manifest.json',
      import.meta.url
    ),
    'utf8'
  )
);

test('T051 accepts the immutable 800-case golden corpus and its release floor', () => {
  assert.equal(
    isSastQualificationPriorReleaseManifestValid(priorReleaseManifest, digest),
    true
  );
  assert.equal(
    isSastQualificationCorpusSnapshotValid(
      snapshot,
      digest,
      priorReleaseManifest
    ),
    true
  );
  assert.equal(snapshot.caseCount, 800);
  assert.equal(snapshot.positiveCaseCount, 400);
  assert.equal(snapshot.negativeCaseCount, 400);
  assert.equal(snapshot.priorMustDetectCaseCount, 400);
  assert.deepEqual(snapshot.profiles, [...SAST_PROFILE_IDS]);
  assert.equal(snapshot.ruleCounts.length, 20);

  for (const count of snapshot.profileCounts) {
    assert.ok(
      count.positiveCases >=
        SAST_QUALIFICATION_CORPUS_LIMITS.minimumPositiveCasesPerProfile
    );
    assert.ok(
      count.negativeCases >=
        SAST_QUALIFICATION_CORPUS_LIMITS.minimumNegativeCasesPerProfile
    );
  }
  for (const count of snapshot.ruleCounts) {
    assert.equal(count.positiveCases, 20);
    assert.equal(count.negativeCases, 20);
    assert.equal(count.priorMustDetectCases, 20);
    assert.match(count.severity, /^(?:CRITICAL|HIGH)$/u);
  }
  assert.deepEqual(
    snapshot.negativeKindCounts.map((count) => count.negativeKind),
    [...SAST_QUALIFICATION_NEGATIVE_KINDS]
  );
  assert.ok(snapshot.negativeKindCounts.every((count) => count.cases > 0));
  assert.equal(
    snapshot.negativeKindCounts.reduce((total, count) => total + count.cases, 0),
    snapshot.negativeCaseCount
  );
  assert.equal(snapshot.priorReleaseRef, priorReleaseManifest.releaseRef);
  assert.equal(
    snapshot.priorReleaseManifestDigest,
    priorReleaseManifest.manifestDigest
  );
  assert.equal(
    snapshot.priorMustDetectSetDigest,
    priorReleaseManifest.caseSetDigest
  );

  const scanPaths = new Set();
  for (const corpusCase of snapshot.cases) {
    assert.equal(isSastQualificationCorpusCaseValid(corpusCase, digest), true);
    assert.equal(corpusCase.sourcePlatformOwned, true);
    assert.equal(corpusCase.customerContentAccepted, false);
    assert.equal(corpusCase.executable, false);
    assert.equal(corpusCase.packageInstallRequired, false);
    assert.equal(corpusCase.buildRequired, false);
    assert.equal(corpusCase.dynamicExecutionRequired, false);
    assert.equal(corpusCase.networkRequired, false);
    assert.equal(corpusCase.immutable, true);
    assert.equal(scanPaths.has(corpusCase.scanPath), false);
    scanPaths.add(corpusCase.scanPath);
  }
});

test('T051 canonicalizes case order to the same corpus identity', () => {
  const rebuilt = buildSastQualificationCorpusSnapshot(
    snapshotInput([...snapshot.cases].reverse()),
    digest
  );

  assert.ok(rebuilt);
  assert.deepEqual(rebuilt, snapshot);
  assert.equal(rebuilt.snapshotDigest, snapshot.snapshotDigest);
  assert.equal(rebuilt.caseSetDigest, snapshot.caseSetDigest);
  assert.equal(
    rebuilt.priorMustDetectSetDigest,
    snapshot.priorMustDetectSetDigest
  );
});

test('T051 authenticates the exact prior-release set instead of deriving it from current positives', () => {
  const cases = structuredClone(snapshot.cases);
  const replacedPairKey = cases.find(
    (item) => item.corpusClass === 'GOLDEN_POSITIVE'
  ).pairKey;
  for (const [index, corpusCase] of cases.entries()) {
    if (corpusCase.pairKey !== replacedPairKey) continue;
    cases[index] = rebuildCaseWithSuffix(corpusCase, 'replacement');
  }

  assert.equal(
    buildSastQualificationCorpusSnapshot(snapshotInput(cases), digest),
    null,
    'replacing a released case must fail even when all current floors and pairs remain complete'
  );

  const derivedFromCurrent = buildSastQualificationPriorReleaseManifest(
    manifestInput(
      cases
        .filter((item) => item.corpusClass === 'GOLDEN_POSITIVE')
        .map(priorBinding)
    ),
    digest
  );
  assert.ok(derivedFromCurrent);
  assert.ok(
    buildSastQualificationCorpusSnapshot(
      { ...snapshotInput(cases), priorReleaseManifest: derivedFromCurrent },
      digest
    ),
    'the replacement corpus itself is complete; only the immutable release authority rejects it'
  );
});

test('T051 keeps new positives outside the prior-release denominator', () => {
  const positive = snapshot.cases.find(
    (item) => item.corpusClass === 'GOLDEN_POSITIVE'
  );
  const negative = snapshot.cases.find(
    (item) =>
      item.pairKey === positive.pairKey && item.corpusClass === 'GOLDEN_NEGATIVE'
  );
  assert.ok(positive);
  assert.ok(negative);
  const futureCases = [
    ...snapshot.cases,
    rebuildCaseWithSuffix(positive, 'future', 9_999),
    rebuildCaseWithSuffix(negative, 'future', 9_999)
  ];
  const futureSnapshot = buildSastQualificationCorpusSnapshot(
    {
      ...snapshotInput(futureCases),
      revision: '1.1.0',
      publishedAt: '2026-08-21T00:00:00.000Z'
    },
    digest
  );

  assert.ok(futureSnapshot);
  assert.equal(futureSnapshot.positiveCaseCount, 401);
  assert.equal(futureSnapshot.priorMustDetectCaseCount, 400);
  assert.equal(
    futureSnapshot.priorReleaseManifestDigest,
    priorReleaseManifest.manifestDigest
  );
});

test('T051 rejects changed prior case bytes and forged prior manifests', () => {
  const cases = structuredClone(snapshot.cases);
  const priorIndex = cases.findIndex(
    (item) => item.caseId === priorReleaseManifest.bindings[0].caseId
  );
  assert.notEqual(priorIndex, -1);
  const changedInput = caseInput(cases[priorIndex]);
  changedInput.sourceDigest = digest('changed-prior-source');
  const changed = buildSastQualificationCorpusCase(changedInput, digest);
  assert.ok(changed);
  cases[priorIndex] = changed;
  assert.equal(
    buildSastQualificationCorpusSnapshot(snapshotInput(cases), digest),
    null
  );

  for (const hostile of [
    null,
    [],
    { ...priorReleaseManifest, unknown: true },
    { ...priorReleaseManifest, bindings: null },
    { ...priorReleaseManifest, bindings: [null] },
    {
      ...priorReleaseManifest,
      bindings: [
        { ...priorReleaseManifest.bindings[0], caseDigest: digest('forged') },
        ...priorReleaseManifest.bindings.slice(1)
      ]
    },
    { ...priorReleaseManifest, releaseRef: snapshot.provenanceRef },
    { ...priorReleaseManifest, manifestDigest: digest('forged') },
    { ...priorReleaseManifest, immutable: false }
  ]) {
    assert.doesNotThrow(() =>
      isSastQualificationPriorReleaseManifestValid(hostile, digest)
    );
    assert.equal(
      isSastQualificationPriorReleaseManifestValid(hostile, digest),
      false
    );
  }
});

test('T051 case builders reject hostile metadata and materialization paths', () => {
  const source = snapshot.cases[0];
  const input = caseInput(source);
  const hostileInputs = [
    { ...input, unknown: 'forbidden' },
    { ...input, sourcePath: 'sources/java/../escape.java' },
    { ...input, sourcePath: 'sources/java\\escape.java' },
    { ...input, scanPath: 'workspace/java/../../escape.java' },
    { ...input, scanPath: '/workspace/java/escape.java' },
    { ...input, ownerRef: 'user://attacker' },
    { ...input, licenseExpression: 'Apache-2.0\nmalicious' },
    { ...input, provenanceRef: 'https://mutable.example/corpus' },
    { ...input, profiles: ['COMMON_DEEP_V1'] },
    { ...input, sourceBytes: 0 },
    {
      ...input,
      sourceBytes: SAST_QUALIFICATION_CORPUS_LIMITS.maximumSourceBytes + 1
    },
    { ...input, expectedAnchor: 'decomposed-e\u0301' },
    { ...input, startLine: 0 },
    { ...input, endLine: input.startLine - 1 }
  ];

  for (const hostile of hostileInputs) {
    assert.doesNotThrow(() => buildSastQualificationCorpusCase(hostile, digest));
    assert.equal(buildSastQualificationCorpusCase(hostile, digest), null);
  }
});

test('T051 snapshot builder rejects incomplete floors and colliding scan paths', () => {
  assert.equal(
    buildSastQualificationCorpusSnapshot(
      snapshotInput(snapshot.cases.slice(0, 200)),
      digest
    ),
    null
  );
  assert.equal(
    buildSastQualificationCorpusSnapshot(
      snapshotInput(snapshot.cases.slice(1)),
      digest
    ),
    null
  );

  const cases = structuredClone(snapshot.cases);
  const replacementInput = caseInput(cases[1]);
  replacementInput.scanPath = cases[0].scanPath;
  const replacement = buildSastQualificationCorpusCase(replacementInput, digest);
  assert.ok(replacement);
  cases[1] = replacement;
  assert.equal(
    buildSastQualificationCorpusSnapshot(snapshotInput(cases), digest),
    null
  );

  const portableCollisionCases = structuredClone(snapshot.cases);
  const portableCollisionInput = caseInput(portableCollisionCases[1]);
  const existingPath = portableCollisionCases[0].scanPath;
  const lastSeparator = existingPath.lastIndexOf('/');
  portableCollisionInput.scanPath = `${existingPath.slice(0, lastSeparator + 1)}${existingPath
    .slice(lastSeparator + 1)
    .toUpperCase()}`;
  const portableCollision = buildSastQualificationCorpusCase(
    portableCollisionInput,
    digest
  );
  assert.ok(portableCollision);
  portableCollisionCases[1] = portableCollision;
  assert.equal(
    buildSastQualificationCorpusSnapshot(
      snapshotInput(portableCollisionCases),
      digest
    ),
    null
  );
});

test('T051 snapshot rejects semantic rule identity reuse across revisions', () => {
  const cases = structuredClone(snapshot.cases);
  const pairKey = cases[0].pairKey;
  for (const [index, corpusCase] of cases.entries()) {
    if (corpusCase.pairKey !== pairKey) continue;
    const input = caseInput(corpusCase);
    input.ruleRevision = '2.0.0';
    const replacement = buildSastQualificationCorpusCase(input, digest);
    assert.ok(replacement);
    cases[index] = replacement;
  }

  assert.equal(
    buildSastQualificationCorpusSnapshot(snapshotInput(cases), digest),
    null
  );
});

test('T051 validators reject tampering and malformed hostile shapes without throwing', () => {
  const corpusCase = snapshot.cases[0];
  for (const hostile of [
    null,
    [],
    { ...corpusCase, unknown: true },
    { ...corpusCase, profiles: null },
    { ...corpusCase, caseDigest: digest('tampered') },
    { ...corpusCase, sourcePlatformOwned: false },
    { ...corpusCase, customerContentAccepted: true },
    { ...corpusCase, executable: true },
    { ...corpusCase, packageInstallRequired: true },
    { ...corpusCase, buildRequired: true },
    { ...corpusCase, dynamicExecutionRequired: true },
    { ...corpusCase, networkRequired: true },
    { ...corpusCase, immutable: false }
  ]) {
    assert.doesNotThrow(() =>
      isSastQualificationCorpusCaseValid(hostile, digest)
    );
    assert.equal(isSastQualificationCorpusCaseValid(hostile, digest), false);
  }

  for (const hostile of [
    null,
    [],
    { ...snapshot, unknown: true },
    { ...snapshot, cases: null },
    { ...snapshot, cases: [null] },
    {
      ...snapshot,
      cases: [{ ...snapshot.cases[0], profiles: null }, ...snapshot.cases.slice(1)]
    },
    { ...snapshot, caseCount: 799 },
    { ...snapshot, snapshotDigest: digest('tampered') },
    { ...snapshot, priorMustDetectCaseIds: [] },
    { ...snapshot, ownerRef: 'user://attacker' },
    { ...snapshot, source: 'CUSTOMER_MANAGED' },
    { ...snapshot, immutable: false },
    { ...snapshot, customerContentAccepted: true },
    { ...snapshot, customerExecutableConfigAccepted: true },
    { ...snapshot, networkRequired: true },
    { ...snapshot, packageInstallRequired: true },
    { ...snapshot, buildRequired: true },
    { ...snapshot, dynamicExecutionRequired: true }
  ]) {
    assert.doesNotThrow(() =>
      isSastQualificationCorpusSnapshotValid(
        hostile,
        digest,
        priorReleaseManifest
      )
    );
    assert.equal(
      isSastQualificationCorpusSnapshotValid(
        hostile,
        digest,
        priorReleaseManifest
      ),
      false
    );
  }
});

function snapshotInput(cases) {
  return {
    revision: snapshot.revision,
    publishedAt: snapshot.publishedAt,
    ownerRef: snapshot.ownerRef,
    licenseExpression: snapshot.licenseExpression,
    provenanceRef: snapshot.provenanceRef,
    priorReleaseManifest,
    cases
  };
}

function manifestInput(bindings) {
  return {
    releaseRevision: priorReleaseManifest.releaseRevision,
    publishedAt: priorReleaseManifest.publishedAt,
    ownerRef: priorReleaseManifest.ownerRef,
    provenanceRef: priorReleaseManifest.provenanceRef,
    bindings
  };
}

function priorBinding(value) {
  return {
    caseId: value.caseId,
    caseDigest: value.caseDigest,
    caseKey: value.caseKey,
    caseRevision: value.caseRevision,
    ruleSemanticId: value.ruleSemanticId,
    ruleRevision: value.ruleRevision,
    severity: value.severity
  };
}

function rebuildCaseWithSuffix(value, suffix, line = value.startLine) {
  const input = caseInput(value);
  input.caseKey = `${input.caseKey}.${suffix}`;
  input.pairKey = `${input.pairKey}.${suffix}`;
  input.scanPath = input.scanPath.replace(
    /^(workspace\/(?:java|common)\/)/u,
    `$1${suffix}/`
  );
  input.expectedAnchor = `${input.expectedAnchor}.${suffix}`;
  input.startLine = line;
  input.endLine = line;
  const rebuilt = buildSastQualificationCorpusCase(input, digest);
  assert.ok(rebuilt);
  return rebuilt;
}

function caseInput(value) {
  const derivedKeys = new Set([
    'version',
    'caseId',
    'caseDigest',
    'sourcePlatformOwned',
    'customerContentAccepted',
    'executable',
    'packageInstallRequired',
    'buildRequired',
    'dynamicExecutionRequired',
    'networkRequired',
    'immutable'
  ]);
  return structuredClone(
    Object.fromEntries(
      Object.entries(value).filter(([key]) => !derivedKeys.has(key))
    )
  );
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
