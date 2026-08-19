import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  SAST_ARTIFACT_VALIDATION_LIMITS,
  SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES,
  SAST_MULTI_CLASS_QUALIFICATION_LIMITS,
  SAST_MULTI_CLASS_QUALIFICATION_REQUIRED_SCENARIOS,
  SAST_PROFILE_IDS,
  SAST_SCAN_PROFILES,
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

test('T052 fingerprint invariance recipes bind two complete vectors that differ only by the excluded field', () => {
  const invariantFieldByScenario = new Map([
    ['LINE_SHIFT_INVARIANT', 'line'],
    ['BRANCH_CHANGE_INVARIANT', 'branch'],
    ['COMMIT_CHANGE_INVARIANT', 'commit-sha'],
    ['UNKNOWN_LOCATION_REASON_INVARIANT', 'location-reason']
  ]);
  const stableFields = [
    'repository-binding-id',
    'capability',
    'rule-semantic-id',
    'normalized-path',
    'symbol-anchor',
    'sink-kind',
    'structural-hash'
  ];

  for (const [scenario, varyingField] of invariantFieldByScenario) {
    const fixture = fixtureForScenario(scenario);
    const identityInputs = fixture.steps
      .filter((step) => step.action === 'DECLARE_IDENTITY_INPUT')
      .map((step) => Object.fromEntries(step.arguments.map(splitArgument)));
    assert.equal(identityInputs.length, 2, scenario);
    for (const field of stableFields) {
      assert.equal(Object.hasOwn(identityInputs[0], field), true, `${scenario}:${field}`);
      assert.equal(Object.hasOwn(identityInputs[1], field), true, `${scenario}:${field}`);
      assert.equal(identityInputs[0][field], identityInputs[1][field], `${scenario}:${field}`);
    }
    const differingFields = Object.keys(identityInputs[0])
      .filter((field) => field !== 'ordinal')
      .filter((field) => identityInputs[0][field] !== identityInputs[1][field]);
    assert.deepEqual(differingFields, [varyingField], scenario);
    if (scenario === 'UNKNOWN_LOCATION_REASON_INVARIANT') {
      assert.equal(identityInputs[0]['normalized-path'], '');
      assert.equal(identityInputs[0]['location-kind'], 'UNKNOWN');
    }
  }
});

test('T052 symlink cycle recipe declares both directed links', () => {
  const fixture = fixtureForScenario('SYMLINK_CYCLE');
  const links = fixture.steps
    .filter((step) => step.action === 'DECLARE_SYMLINK')
    .map((step) => Object.fromEntries(step.arguments.map(splitArgument)));
  assert.deepEqual(
    links.map(({ path, target }) => ({ path, target })),
    [
      { path: 'a', target: 'b' },
      { path: 'b', target: 'a' }
    ]
  );
});

test('T052 evidence encoding recipes carry the intended raw bytes', () => {
  const binary = fixtureForScenario('BINARY_INPUT_REJECT');
  const invalidUtf8 = fixtureForScenario('INVALID_ENCODING_REJECT');
  assert.equal(
    binary.steps.some((step) => step.action === 'DECLARE_EVIDENCE_BYTES'),
    true
  );
  assert.equal(
    invalidUtf8.steps.some((step) => step.action === 'DECLARE_EVIDENCE_BYTES'),
    true
  );
  assert.deepEqual(Buffer.from(binary.segments[0].valueBase64, 'base64'),
    Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]));
  assert.deepEqual(
    Buffer.from(invalidUtf8.segments[0].valueBase64, 'base64'),
    Buffer.from([0xff])
  );
});

test('T052 limit-plus-one recipes bind the exact selected-profile boundary', () => {
  const metricByScenario = new Map([
    ['ARTIFACT_BYTES_LIMIT_PLUS_ONE', 'maxArtifactBytes'],
    ['RECORD_COUNT_LIMIT_PLUS_ONE', 'maxArtifactRecords'],
    ['PATH_DEPTH_LIMIT_PLUS_ONE', 'maxPathDepth'],
    ['REPOSITORY_BYTES_LIMIT_PLUS_ONE', 'maxRepositoryBytes'],
    ['SELECTED_BYTES_LIMIT_PLUS_ONE', 'maxSelectedBytes'],
    ['FILE_COUNT_LIMIT_PLUS_ONE', 'maxFileCount'],
    ['SINGLE_FILE_BYTES_LIMIT_PLUS_ONE', 'maxSingleFileBytes'],
    ['OUTPUT_BYTES_LIMIT_PLUS_ONE', 'maxStdoutStderrBytes'],
    ['FINDING_COUNT_LIMIT_PLUS_ONE', 'maxFindings'],
    ['TIMEOUT_PLUS_ONE', 'wallClockTimeoutSeconds']
  ]);

  for (const [scenario, metric] of metricByScenario) {
    const fixture = fixtureForScenario(scenario);
    const parameters = new Map(
      fixture.parameters.map((parameter) => [
        parameter.name,
        parameter.stringValue ?? parameter.integerValue ?? parameter.booleanValue
      ])
    );
    assert.equal(parameters.get('BOUNDARY_METRIC'), metric, scenario);
    assert.equal(
      parameters.get('PROFILE_LIMIT_MODE'),
      'SELECTED_PROFILE_LIMIT_PLUS_ONE',
      scenario
    );
    assert.equal(parameters.get('PROFILE_SELECTION_SOURCE'), 'CASE_PROFILE', scenario);
    for (const profileId of SAST_PROFILE_IDS) {
      assert.equal(
        parameters.get(`${profileId}_LIMIT_PLUS_ONE`),
        SAST_SCAN_PROFILES[profileId].limits[metric] + 1,
        `${scenario}:${profileId}`
      );
    }
    if (
      scenario === 'ARTIFACT_BYTES_LIMIT_PLUS_ONE' ||
      scenario === 'RECORD_COUNT_LIMIT_PLUS_ONE'
    ) {
      const materializationMetric =
        scenario === 'ARTIFACT_BYTES_LIMIT_PLUS_ONE'
          ? 'MATERIALIZED_BYTES'
          : 'MATERIALIZED_ENTRIES';
      assert.equal(parameters.get('PROFILE_BOUND_SEGMENT_ORDINAL'), 2, scenario);
      assert.equal(
        parameters.get('PROFILE_BOUND_MATERIALIZATION_METRIC'),
        materializationMetric,
        scenario
      );
      assert.equal(
        parameters.get('PROFILE_BOUND_UNIT_CONTRIBUTION'),
        1,
        scenario
      );
      assert.equal(
        parameters.get('PROFILE_BOUND_REPEAT_FORMULA'),
        'SELECTED_LIMIT_PLUS_ONE_MINUS_FIXED_CONTRIBUTION',
        scenario
      );
      const fixedContribution = parameters.get(
        'PROFILE_BOUND_FIXED_CONTRIBUTION'
      );
      assert.equal(Number.isSafeInteger(fixedContribution), true, scenario);
      for (const profileId of SAST_PROFILE_IDS) {
        const selectedBoundary = parameters.get(`${profileId}_LIMIT_PLUS_ONE`);
        const selectedRepeat = selectedBoundary - fixedContribution;
        assert.equal(
          selectedRepeat + fixedContribution,
          SAST_SCAN_PROFILES[profileId].limits[metric] + 1,
          `${scenario}:${profileId}:projection`
        );
      }
    }
  }
});

test('T052 parser-wide boundaries are the exact validator limit plus one', () => {
  const nesting = fixtureForScenario('NESTING_DEPTH_LIMIT_PLUS_ONE');
  const nestingUnit = nesting.segments.find((segment) => segment.role === 'PREFIX');
  assert.ok(nestingUnit);
  assert.equal(
    nestingUnit.repeat,
    SAST_ARTIFACT_VALIDATION_LIMITS.maximumJsonDepth + 1
  );
  assert.equal(
    nesting.segments.find((segment) => segment.role === 'SUFFIX')?.repeat,
    SAST_ARTIFACT_VALIDATION_LIMITS.maximumJsonDepth + 1
  );
  assertBoundaryParameters(
    nesting,
    'maximumJsonDepth',
    SAST_ARTIFACT_VALIDATION_LIMITS.maximumJsonDepth
  );

  const string = fixtureForScenario('STRING_BYTES_LIMIT_PLUS_ONE');
  const stringUnit = string.segments.find((segment) => segment.role === 'UNIT');
  assert.ok(stringUnit);
  assert.equal(
    stringUnit.repeat,
    SAST_ARTIFACT_VALIDATION_LIMITS.maximumStringBytes + 1
  );
  assertBoundaryParameters(
    string,
    'maximumStringBytes',
    SAST_ARTIFACT_VALIDATION_LIMITS.maximumStringBytes
  );
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

function assertBoundaryParameters(fixture, metric, limit) {
  const parameters = new Map(
    fixture.parameters.map((parameter) => [
      parameter.name,
      parameter.stringValue ?? parameter.integerValue ?? parameter.booleanValue
    ])
  );
  assert.equal(parameters.get('BOUNDARY_METRIC'), metric);
  assert.equal(parameters.get('BOUNDARY_LIMIT'), limit);
  assert.equal(parameters.get('BOUNDARY_LIMIT_PLUS_ONE'), limit + 1);
  assert.equal(parameters.get('BOUNDARY_SOURCE'), 'SAST_ARTIFACT_VALIDATION_LIMITS');
}

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

function fixtureForScenario(scenario) {
  const item = snapshot.cases.find((candidate) => candidate.scenario === scenario);
  assert.ok(item, scenario);
  const fixture = fixtures.get(item.fixturePath);
  assert.ok(fixture, scenario);
  return fixture;
}

function splitArgument(argument) {
  const separator = argument.indexOf('=');
  assert.notEqual(separator, -1, argument);
  return [argument.slice(0, separator), argument.slice(separator + 1)];
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
