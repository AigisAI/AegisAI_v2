import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES,
  SAST_MULTI_CLASS_QUALIFICATION_LIMITS,
  SAST_MULTI_CLASS_QUALIFICATION_REQUIRED_SCENARIOS,
  SAST_PROFILE_IDS,
  buildSastMultiClassQualificationCase,
  buildSastMultiClassQualificationFixture,
  buildSastMultiClassQualificationSnapshot,
  isSastMultiClassQualificationCaseValid,
  isSastMultiClassQualificationFixtureValid,
  isSastMultiClassQualificationSnapshotValid
} from '../dist/index.js';

const corpusRoot = new URL(
  '../../../qualification/corpora/t052-v1/',
  import.meta.url
);
const snapshot = JSON.parse(
  readFileSync(new URL('multi-class-corpus.snapshot.json', corpusRoot), 'utf8')
);
const fixtures = new Map(
  snapshot.cases.map((item) => [
    item.fixturePath,
    JSON.parse(readFileSync(new URL(item.fixturePath, corpusRoot), 'utf8'))
  ])
);

test('T052 accepts the immutable 84-case five-class qualification corpus', () => {
  assert.equal(isSastMultiClassQualificationSnapshotValid(snapshot, digest), true);
  assert.equal(snapshot.caseCount, SAST_MULTI_CLASS_QUALIFICATION_LIMITS.expectedCaseCount);
  assert.equal(snapshot.fixtureCount, snapshot.caseCount);
  assert.deepEqual(snapshot.requiredClasses, [
    ...SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES
  ]);
  assert.deepEqual(snapshot.profiles, [...SAST_PROFILE_IDS]);
  assert.equal(snapshot.classCounts.length, 5);
  assert.equal(snapshot.scenarioCounts.length, snapshot.caseCount);
  assert.ok(snapshot.classCounts.every((item) => item.cases > 0));
  assert.ok(snapshot.scenarioCounts.every((item) => item.cases === 1));
  assert.ok(snapshot.profileCounts.every((item) => item.performanceBuckets === 3));
  assert.equal(snapshot.minimumPerformanceRunsPerBucket, 30);
});

test('T052 fixture and case contracts bind every recipe without execution authority', () => {
  for (const item of snapshot.cases) {
    const fixture = fixtures.get(item.fixturePath);
    assert.ok(fixture);
    assert.equal(isSastMultiClassQualificationFixtureValid(fixture, digest), true);
    assert.equal(isSastMultiClassQualificationCaseValid(item, digest), true);
    assert.equal(fixture.fixtureId, item.fixtureId);
    assert.equal(fixture.fixtureDigest, item.fixtureDigest);
    assert.equal(fixture.materializationKind, item.materializationKind);
    assert.equal(fixture.scenario, item.scenario);
    assert.equal(item.scannerExecutionAuthorized, false);
    assert.equal(item.productionReadinessAuthority, false);
    assert.equal(fixture.executable, false);
    assert.equal(fixture.dynamicExecutionRequired, false);
    assert.equal(fixture.networkRequired, false);
  }
});

test('T052 requires each declared scenario exactly once', () => {
  for (const corpusClass of SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES) {
    const actual = snapshot.cases
      .filter((item) => item.corpusClass === corpusClass)
      .map((item) => item.scenario)
      .sort();
    const expected = [
      ...SAST_MULTI_CLASS_QUALIFICATION_REQUIRED_SCENARIOS[corpusClass]
    ].sort();
    assert.deepEqual(actual, expected);
  }
  assert.equal(
    buildSastMultiClassQualificationSnapshot(
      { ...snapshotInput(snapshot), cases: snapshot.cases.slice(1) },
      digest
    ),
    null
  );
  const duplicate = snapshot.cases.map((item) => structuredClone(item));
  duplicate[0] = structuredClone(duplicate[1]);
  assert.equal(
    buildSastMultiClassQualificationSnapshot(
      { ...snapshotInput(snapshot), cases: duplicate },
      digest
    ),
    null
  );
});

test('T052 canonical ordering produces stable fixture and snapshot identities', () => {
  const firstFixture = [...fixtures.values()].find((fixture) =>
    fixture.steps.some((step) => step.arguments.length > 1)
  );
  assert.ok(firstFixture);
  const rebuiltFixture = buildSastMultiClassQualificationFixture(
    {
      ...fixtureInput(firstFixture),
      parameters: [...firstFixture.parameters].reverse(),
      steps: [...firstFixture.steps]
        .reverse()
        .map((step) => ({ ...step, arguments: [...step.arguments].reverse() }))
    },
    digest
  );
  assert.ok(rebuiltFixture);
  assert.equal(rebuiltFixture.fixtureDigest, firstFixture.fixtureDigest);

  const rebuiltSnapshot = buildSastMultiClassQualificationSnapshot(
    { ...snapshotInput(snapshot), cases: [...snapshot.cases].reverse() },
    digest
  );
  assert.ok(rebuiltSnapshot);
  assert.equal(rebuiltSnapshot.snapshotDigest, snapshot.snapshotDigest);
  assert.deepEqual(rebuiltSnapshot.cases, snapshot.cases);
});

test('T052 rejects executable recipe fields and authority widening', () => {
  const firstFixture = structuredClone(fixtures.values().next().value);
  const hostileFixtures = [
    { ...firstFixture, command: 'run-customer-code' },
    {
      ...firstFixture,
      parameters: [
        ...firstFixture.parameters,
        {
          name: 'COMMAND',
          valueType: 'STRING',
          stringValue: 'run-customer-code',
          integerValue: null,
          booleanValue: null
        }
      ]
    },
    {
      ...firstFixture,
      parameters: [
        ...firstFixture.parameters,
        {
          name: 'CUSTOM_COMMAND',
          valueType: 'STRING',
          stringValue: 'run-customer-code',
          integerValue: null,
          booleanValue: null
        }
      ]
    },
    {
      ...firstFixture,
      steps: [
        ...firstFixture.steps,
        {
          ordinal: firstFixture.steps.length + 1,
          action: 'EMIT_ARTIFACT_BYTES',
          arguments: ['command=run-customer-code']
        }
      ]
    },
    {
      ...firstFixture,
      steps: [
        ...firstFixture.steps,
        {
          ordinal: firstFixture.steps.length + 1,
          action: 'EMIT_ARTIFACT_BYTES',
          arguments: ['path=safe;command=run-customer-code']
        }
      ]
    },
    { ...firstFixture, executable: true },
    { ...firstFixture, networkRequired: true },
    { ...firstFixture, hostMutationAllowed: true }
  ];
  for (const fixture of hostileFixtures) {
    assert.equal(isSastMultiClassQualificationFixtureValid(fixture, digest), false);
  }

  const firstCase = structuredClone(snapshot.cases[0]);
  for (const item of [
    { ...firstCase, scannerExecutionAuthorized: true },
    { ...firstCase, findingAuthority: true },
    { ...firstCase, policyAuthority: true },
    { ...firstCase, productionReadinessAuthority: true },
    { ...firstCase, unknownAuthority: true }
  ]) {
    assert.equal(isSastMultiClassQualificationCaseValid(item, digest), false);
  }
});

test('T052 malformed nested values fail closed without throwing', () => {
  const firstFixture = structuredClone(fixtures.values().next().value);
  const invalidName = structuredClone(firstFixture);
  invalidName.parameters[0].name = Symbol('COMMAND');
  const invalidString = structuredClone(firstFixture);
  invalidString.parameters[0].stringValue = '\ud800';
  const invalidRepeat = structuredClone(firstFixture);
  invalidRepeat.segments[0].repeat = 1n;
  const invalidArguments = structuredClone(firstFixture);
  invalidArguments.steps[0].arguments = null;
  for (const fixture of [
    invalidName,
    invalidString,
    invalidRepeat,
    invalidArguments
  ]) {
    assert.doesNotThrow(() =>
      assert.equal(isSastMultiClassQualificationFixtureValid(fixture, digest), false)
    );
  }

  const invalidCase = structuredClone(snapshot.cases[0]);
  invalidCase.corpusClass = Symbol('PERFORMANCE');
  assert.doesNotThrow(() =>
    assert.equal(isSastMultiClassQualificationCaseValid(invalidCase, digest), false)
  );

  const invalidSnapshot = structuredClone(snapshot);
  invalidSnapshot.classCounts[0].cases = 1n;
  assert.doesNotThrow(() =>
    assert.equal(
      isSastMultiClassQualificationSnapshotValid(invalidSnapshot, digest),
      false
    )
  );
});

test('T052 rejects expected-outcome, stage, hardware, and profile drift', () => {
  const parserCase = snapshot.cases.find(
    (item) => item.scenario === 'MALFORMED_SYNTAX'
  );
  const performanceCase = snapshot.cases.find(
    (item) => item.scenario === 'JAVA_FAST_LARGE_LIMIT'
  );
  assert.ok(parserCase);
  assert.ok(performanceCase);
  assert.equal(
    buildSastMultiClassQualificationCase(
      { ...caseInput(parserCase), expectedOutcome: 'ACCEPT' },
      digest
    ),
    null
  );
  assert.equal(
    buildSastMultiClassQualificationCase(
      { ...caseInput(parserCase), evidenceStage: 'T054_END_TO_END' },
      digest
    ),
    null
  );
  assert.equal(
    buildSastMultiClassQualificationCase(
      { ...caseInput(parserCase), hardwareClassRef: snapshot.performanceHardwareClassRef },
      digest
    ),
    null
  );
  assert.equal(
    buildSastMultiClassQualificationCase(
      { ...caseInput(performanceCase), profiles: ['JAVA_DEEP_V1'] },
      digest
    ),
    null
  );
  assert.equal(
    buildSastMultiClassQualificationCase(
      { ...caseInput(performanceCase), minimumRuns: 29 },
      digest
    ),
    null
  );
  assert.equal(
    buildSastMultiClassQualificationCase(
      {
        ...caseInput(performanceCase),
        fixtureDigest: `sha256:${'0'.repeat(64)}`
      },
      digest
    ),
    null
  );
  assert.equal(
    buildSastMultiClassQualificationSnapshot(
      {
        ...snapshotInput(snapshot),
        performanceHardwareClassDigest: `sha256:${'0'.repeat(64)}`
      },
      digest
    ),
    null
  );
});

test('T052 performance recipes pin profile limits and one hardware class', () => {
  const performanceCases = snapshot.cases.filter(
    (item) => item.corpusClass === 'PERFORMANCE'
  );
  assert.equal(performanceCases.length, 9);
  assert.equal(new Set(performanceCases.map((item) => item.hardwareClassRef)).size, 1);
  assert.equal(performanceCases.every((item) => item.minimumRuns === 30), true);
  for (const profileId of SAST_PROFILE_IDS) {
    assert.equal(
      performanceCases.filter((item) => item.profiles[0] === profileId).length,
      3
    );
  }
  const fastLimit = fixtures.get(
    performanceCases.find((item) => item.scenario === 'JAVA_FAST_LARGE_LIMIT')
      .fixturePath
  );
  const deepLimit = fixtures.get(
    performanceCases.find((item) => item.scenario === 'JAVA_DEEP_LARGE_LIMIT')
      .fixturePath
  );
  assert.equal(fastLimit.materializedEntries, 25_000);
  assert.equal(fastLimit.materializedBytes, 268_435_456);
  assert.equal(deepLimit.materializedEntries, 250_000);
  assert.equal(deepLimit.materializedBytes, 2_147_483_648);
});

test('T052 hostile cyclic and over-depth snapshots fail without throwing', () => {
  const cyclic = structuredClone(snapshot);
  cyclic.classCounts[0].cases = cyclic;
  assert.doesNotThrow(() =>
    assert.equal(isSastMultiClassQualificationSnapshotValid(cyclic, digest), false)
  );

  const deep = structuredClone(snapshot);
  let value = {};
  const root = value;
  for (let index = 0; index < 40; index += 1) {
    value.next = {};
    value = value.next;
  }
  deep.profileCounts[0].cases = root;
  assert.doesNotThrow(() =>
    assert.equal(isSastMultiClassQualificationSnapshotValid(deep, digest), false)
  );
});

function fixtureInput(value) {
  return {
    caseKey: value.caseKey,
    corpusClass: value.corpusClass,
    scenario: value.scenario,
    materializationKind: value.materializationKind,
    parameters: value.parameters,
    segments: value.segments,
    steps: value.steps,
    materializedBytes: value.materializedBytes,
    materializedEntries: value.materializedEntries,
    materializedPathDepth: value.materializedPathDepth,
    simulatedDurationSeconds: value.simulatedDurationSeconds
  };
}

function caseInput(value) {
  return {
    caseKey: value.caseKey,
    caseRevision: value.caseRevision,
    corpusClass: value.corpusClass,
    scenario: value.scenario,
    profiles: value.profiles,
    fixturePath: value.fixturePath,
    fixtureId: value.fixtureId,
    fixtureDigest: value.fixtureDigest,
    fixtureBytes: value.fixtureBytes,
    materializationKind: value.materializationKind,
    expectedOutcome: value.expectedOutcome,
    evidenceStage: value.evidenceStage,
    minimumRuns: value.minimumRuns,
    hardwareClassRef: value.hardwareClassRef,
    ownerRef: value.ownerRef,
    licenseExpression: value.licenseExpression,
    provenanceRef: value.provenanceRef
  };
}

function snapshotInput(value) {
  return {
    revision: value.revision,
    publishedAt: value.publishedAt,
    ownerRef: value.ownerRef,
    licenseExpression: value.licenseExpression,
    provenanceRef: value.provenanceRef,
    performanceHardwareClassRef: value.performanceHardwareClassRef,
    performanceHardwareClassDigest: value.performanceHardwareClassDigest,
    cases: value.cases
  };
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
