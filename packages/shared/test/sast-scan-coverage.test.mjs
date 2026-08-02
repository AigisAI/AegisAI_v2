import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  SAST_SCAN_COVERAGE_VERSION,
  SAST_SCANNER_COVERAGE_VERSION,
  buildFailClosedSastExternalPublicationDecision,
  buildSastScanCoverageRecordsPreimage,
  canonicalizeSastScanCoverageDecision,
  canonicalizeSastScanCoverageRejection,
  canonicalizeSastScannerCoverageRecord,
  evaluateSastScanCoverageRecords,
  isSastExternalPublicationDecisionShapeValid,
  isSastScanCoverageDecisionShapeValid,
  isSastScanCoverageRejectionShapeValid,
  isSastScannerCoverageRecordShapeValid,
  sastScanCoverageAuthority,
  toSastScanCoverageAuditMetadata
} from '../dist/index.js';

test('derives complete Java Deep scanner and capability coverage from canonical records', () => {
  const records = [
    completeRecord('OPENGREP', true, ['SAST']),
    completeRecord('TRIVY', true, [
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION'
    ]),
    completeRecord('SYFT', true, ['SBOM'])
  ];

  assert.deepEqual(
    evaluateSastScanCoverageRecords({
      profileId: 'JAVA_DEEP_V1',
      records
    }),
    {
      state: 'COMPLETE',
      missingRequiredScanners: [],
      pendingRequiredScanners: [],
      failedRequiredScanners: [],
      achievedRequiredCapabilities: [
        'SAST',
        'DEPENDENCY_VULNERABILITY',
        'SECRET_DETECTION',
        'IAC_MISCONFIGURATION',
        'SBOM'
      ],
      missingRequiredCapabilities: [],
      duplicateScanners: [],
      optionalIncompleteScanners: [],
      reasonCodes: []
    }
  );
});

test('keeps an absent optional scanner visible without lowering required coverage', () => {
  const records = [
    completeRecord('OPENGREP', true, ['SAST']),
    completeRecord('TRIVY', true, [
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION'
    ]),
    notStartedRecord('SYFT', false, ['SBOM'])
  ];
  const evaluation = evaluateSastScanCoverageRecords({
    profileId: 'JAVA_FAST_V1',
    records
  });

  assert.equal(evaluation.state, 'COMPLETE');
  assert.deepEqual(evaluation.optionalIncompleteScanners, ['SYFT']);
  assert.deepEqual(evaluation.reasonCodes, [
    'OPTIONAL_SCANNER_INCOMPLETE'
  ]);
});

test('distinguishes pending coverage from security-blocked quarantine', () => {
  const base = [
    completeRecord('OPENGREP', true, ['SAST']),
    completeRecord('TRIVY', true, [
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION'
    ]),
    completeRecord('SYFT', true, ['SBOM'])
  ];
  const pending = replaceRecord(
    base,
    'SYFT',
    incompleteRecord('SYFT', true, ['SBOM'], 'PENDING', [
      'SCANNER_PENDING'
    ])
  );
  const quarantined = replaceRecord(
    base,
    'TRIVY',
    incompleteRecord(
      'TRIVY',
      true,
      [
        'DEPENDENCY_VULNERABILITY',
        'SECRET_DETECTION',
        'IAC_MISCONFIGURATION'
      ],
      'QUARANTINED',
      ['SCANNER_QUARANTINED']
    )
  );

  assert.equal(
    evaluateSastScanCoverageRecords({
      profileId: 'JAVA_DEEP_V1',
      records: pending
    }).state,
    'PENDING'
  );
  const security = evaluateSastScanCoverageRecords({
    profileId: 'JAVA_DEEP_V1',
    records: quarantined
  });
  assert.equal(security.state, 'FAILED');
  assert.equal(security.reasonCodes.includes('SECURITY_BLOCKED'), true);
});

test('persists complete coverage while fail-closing every external publication authority', () => {
  const records = [
    completeRecord('OPENGREP', true, ['SAST']),
    completeRecord('TRIVY', true, [
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION'
    ]),
    completeRecord('SYFT', true, ['SBOM'])
  ];
  const scope = {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    lifecycleContextKey: digest('lifecycle'),
    targetRef: 'refs/heads/main',
    commitSha: 'a'.repeat(40),
    lane: 'DEEP',
    profileId: 'JAVA_DEEP_V1',
    profileDigest: digest('profile'),
    canonicalScanKey: digest('canonical-key'),
    planDigest: digest('plan'),
    scannerSetDigest: digest('scanner-set'),
    correlationBatchId: id('finding-correlation', 'batch'),
    correlationSourceSetDigest: digest('source-set')
  };
  const core = {
    version: SAST_SCAN_COVERAGE_VERSION,
    coverageDecisionId: id('sast-coverage', 'coverage'),
    scope,
    state: 'COMPLETE',
    requiredScanners: ['OPENGREP', 'TRIVY', 'SYFT'],
    optionalScanners: [],
    missingRequiredScanners: [],
    pendingRequiredScanners: [],
    failedRequiredScanners: [],
    achievedRequiredCapabilities: [
      'SAST',
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION',
      'SBOM'
    ],
    missingRequiredCapabilities: [],
    duplicateScanners: [],
    optionalIncompleteScanners: [],
    reasonCodes: [],
    recordsDigest: digest(buildSastScanCoverageRecordsPreimage(records)),
    authority: sastScanCoverageAuthority(),
    decidedAt: '2026-08-02T13:00:00.000Z'
  };
  const decision = {
    ...core,
    decisionDigest: digest(
      canonicalizeSastScanCoverageDecision(core)
    )
  };
  const publication = buildFailClosedSastExternalPublicationDecision({
    publicationDecisionId: id('sast-publication', 'publication'),
    decision,
    profileAiAdvisoryEligible: true,
    digestCanonical: digest
  });

  assert.equal(
    isSastScanCoverageDecisionShapeValid(decision, digest),
    true
  );
  assert.equal(
    isSastExternalPublicationDecisionShapeValid(publication, digest),
    true
  );
  assert.deepEqual(
    {
      externalCommentAllowed: publication.externalCommentAllowed,
      blockingStatusAllowed: publication.blockingStatusAllowed,
      aiAdvisoryAllowed: publication.aiAdvisoryAllowed,
      lifecycleMutationAllowed: publication.lifecycleMutationAllowed
    },
    {
      externalCommentAllowed: false,
      blockingStatusAllowed: false,
      aiAdvisoryAllowed: false,
      lifecycleMutationAllowed: false
    }
  );
  assert.equal(
    publication.reasonCodes.includes(
      'LATEST_TARGET_AUTHORITY_UNAVAILABLE'
    ),
    true
  );
});

test('rejects a scanner record whose canonical provenance digest is changed', () => {
  const record = completeRecord('OPENGREP', true, ['SAST']);
  assert.equal(
    isSastScannerCoverageRecordShapeValid(record, digest),
    true
  );
  assert.equal(
    isSastScannerCoverageRecordShapeValid(
      { ...record, scannerVersion: 'changed' },
      digest
    ),
    false
  );
});

test('validates and projects a bounded fail-closed rejection', () => {
  const core = {
    version: SAST_SCAN_COVERAGE_VERSION,
    outcome: 'REJECTED',
    reasonCodes: ['SCAN_COVERAGE_DURABLE_SCOPE_INVALID'],
    scannerRunIdsStored: false,
    artifactReferencesStored: false,
    correlationReferencesStored: false,
    publicationAttempted: false,
    secretValueStored: false
  };
  const rejection = {
    ...core,
    rejectionDigest: digest(
      canonicalizeSastScanCoverageRejection(core)
    )
  };

  assert.equal(
    isSastScanCoverageRejectionShapeValid(rejection, digest),
    true
  );
  assert.deepEqual(
    toSastScanCoverageAuditMetadata(rejection, digest),
    {
      version: SAST_SCAN_COVERAGE_VERSION,
      outcome: 'REJECTED',
      reasonCodes: ['SCAN_COVERAGE_DURABLE_SCOPE_INVALID'],
      rejectionDigest: rejection.rejectionDigest
    }
  );
});

function completeRecord(scanner, required, capabilities) {
  const findingScanner = scanner !== 'SYFT';
  return finalize({
    ...baseRecord(scanner, required, capabilities),
    executionStatus: 'SUCCEEDED',
    achievedCapabilities: capabilities,
    scannerRunId: `scanner-run-${scanner.toLowerCase()}`,
    scannerVersion: '1.0.0',
    scannerImageDigest: digest(`${scanner}-image`),
    wrapperDigest: digest(`${scanner}-wrapper`),
    ruleBundleDigest:
      scanner === 'SYFT' ? null : digest(`${scanner}-rules`),
    vulnerabilityDatabaseDigest:
      scanner === 'TRIVY' ? digest('trivy-db') : null,
    schemaBundleDigest: digest('schema-bundle'),
    normalizerBundleDigest: digest('normalizer-bundle'),
    artifactIngestionId: `ingestion-${scanner.toLowerCase()}`,
    artifactEnvelopeDigest: digest(`${scanner}-envelope`),
    artifactDigest: digest(`${scanner}-artifact`),
    dispositionDecisionId: `disposition-${scanner.toLowerCase()}`,
    dispositionDecisionDigest: digest(`${scanner}-disposition`),
    correlationSourceId: findingScanner
      ? `correlation-source-${scanner.toLowerCase()}`
      : null,
    observationBatchId: findingScanner
      ? id('finding-observation', scanner)
      : null,
    correlationSourceBindingDigest: findingScanner
      ? digest(`${scanner}-source`)
      : null,
    artifactAccepted: true,
    normalizationEligible: true,
    findingObservationClosed: true,
    reasonCodes: []
  });
}

function notStartedRecord(scanner, required, capabilities) {
  return finalize(baseRecord(scanner, required, capabilities));
}

function incompleteRecord(
  scanner,
  required,
  capabilities,
  executionStatus,
  reasonCodes
) {
  return finalize({
    ...baseRecord(scanner, required, capabilities),
    executionStatus,
    scannerRunId: `scanner-run-${scanner.toLowerCase()}`,
    scannerVersion: '1.0.0',
    scannerImageDigest: digest(`${scanner}-image`),
    wrapperDigest: digest(`${scanner}-wrapper`),
    ruleBundleDigest:
      scanner === 'SYFT' ? null : digest(`${scanner}-rules`),
    vulnerabilityDatabaseDigest:
      scanner === 'TRIVY' ? digest('trivy-db') : null,
    schemaBundleDigest: digest('schema-bundle'),
    normalizerBundleDigest: digest('normalizer-bundle'),
    findingObservationClosed: scanner === 'SYFT',
    reasonCodes
  });
}

function baseRecord(scanner, required, capabilities) {
  return {
    version: SAST_SCANNER_COVERAGE_VERSION,
    scannerCoverageId: id(
      'sast-scanner-coverage',
      `${scanner}-${required}`
    ),
    scanner,
    required,
    executionStatus: 'NOT_STARTED',
    authoritativeCapabilities: capabilities,
    requiredCapabilities: required ? capabilities : [],
    achievedCapabilities: [],
    scannerRunId: null,
    scannerVersion: null,
    scannerImageDigest: null,
    wrapperDigest: null,
    ruleBundleDigest: null,
    vulnerabilityDatabaseDigest: null,
    schemaBundleDigest: null,
    normalizerBundleDigest: null,
    artifactIngestionId: null,
    artifactEnvelopeDigest: null,
    artifactDigest: null,
    dispositionDecisionId: null,
    dispositionDecisionDigest: null,
    correlationSourceId: null,
    observationBatchId: null,
    correlationSourceBindingDigest: null,
    artifactAccepted: false,
    normalizationEligible: false,
    findingObservationRequired: scanner !== 'SYFT',
    findingObservationClosed: scanner === 'SYFT',
    reasonCodes: ['SCANNER_NOT_STARTED']
  };
}

function finalize(core) {
  return {
    ...core,
    recordDigest: digest(canonicalizeSastScannerCoverageRecord(core))
  };
}

function replaceRecord(records, scanner, replacement) {
  return records.map((record) =>
    record.scanner === scanner ? replacement : record
  );
}

function id(prefix, value) {
  return `${prefix}://${createHash('sha256')
    .update(String(value), 'utf8')
    .digest('hex')}`;
}

function digest(value) {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}
