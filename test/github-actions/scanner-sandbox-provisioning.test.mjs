import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const contractFile = new URL('../../deploy/scanner-sandbox/provisioning-contract.json', import.meta.url);
const forbiddenSecretFields = ['tokenValue', 'secretValue', 'accessToken', 'refreshToken', 'privateKey'];

const readContract = () => JSON.parse(readFileSync(contractFile, 'utf8'));

test('microVM scanner sandbox provisioning contract defines stronger-than-pod scan isolation', () => {
  assert.equal(existsSync(contractFile), true, `Expected scanner sandbox contract at ${contractFile.pathname}`);

  const contract = readContract();

  assert.equal(contract.kind, 'ScannerSandboxProvisioning');
  assert.equal(contract.sandboxProvider, 'MICROVM');
  assert.deepEqual(contract.supportedIsolationClasses, ['HARDENED', 'RESTRICTED']);
  assert.equal(contract.defaultIsolationClass, 'HARDENED');
  assert.equal(contract.ttlSeconds, 3960);
  assert.deepEqual(contract.ttlPolicy, {
    source: 'SIGNED_PROFILE',
    maximumExecutionSeconds: 3600,
    provisioningGraceSeconds: 300,
    cleanupGraceSeconds: 60,
    hardMaximumSeconds: 3960
  });
  assert.equal(contract.networkEgressPolicy, 'PHASE_BOUND_DENY_BY_DEFAULT');
  assert.deepEqual(contract.networkEgressPhases.REPOSITORY_FETCH, {
    allowedDestinationPolicy: 'BOUND_SCM_HOST_ONLY',
    boundHostSource: 'SIGNED_REPOSITORY_BINDING',
    allowedProtocols: ['HTTPS'],
    unboundPublicInternetEgressAllowed: false,
    resultIngressAllowed: false,
    transitionRequires: [
      'FIXED_COMMIT_FETCHED',
      'REMOTE_REMOVED',
      'GIT_METADATA_REMOVED',
      'CREDENTIAL_WIPED_AND_REVOKED',
      'SCM_EGRESS_RULE_REMOVED'
    ]
  });
  assert.equal(
    contract.networkEgressPhases.SCANNER_EXECUTION.allowedDestinationPolicy,
    'RESULT_INGRESS_AND_TELEMETRY_ONLY'
  );
  assert.equal(
    contract.networkEgressPhases.SCANNER_EXECUTION.boundScmHostAllowed,
    false
  );
  assert.equal(contract.publicInternetEgressAllowed, false);
  assert.equal(contract.cloudMetadataAccessAllowed, false);
  assert.equal(contract.executionBoundary.runAsNonRoot, true);
  assert.equal(contract.executionBoundary.readOnlyRootFilesystem, true);
  assert.equal(contract.executionBoundary.signedAttemptDeadlineRequired, true);
  assert.equal(
    contract.executionBoundary.orphanedAttemptReconciliationRequired,
    true
  );
  assert.deepEqual(contract.scannerInputBoundary, {
    deepScanMount: '/workspace/repository',
    fastScanMountTemplate:
      '/workspace/selected/<preflight-inventory-sha256>',
    fastScanMaterializer: 'PLATFORM_OWNED',
    fastScanSelectionSource: 'ATTESTED_PATH_ALLOWLIST',
    fastScanContentBinding: 'PREFLIGHT_INVENTORY_DIGEST',
    fastScanReadOnly: true,
    fastScanUnselectedEntriesAllowed: false,
    scannerReceivesRepositoryRootForFastScan: false,
    preScannerProjectionAttestationRequired: true,
    projectionMismatchPolicy: 'FAIL_CLOSED'
  });
  assert.equal(contract.repositoryAccess.principal, 'REPO_READ');
  assert.equal(contract.repositoryAccess.tokenScope, 'tenant-repository-scan');
  assert.equal(contract.repositoryAccess.shortLived, true);
  assert.equal(contract.repositoryAccess.persistTokenValue, false);
  assert.deepEqual(
    contract.resultIngress.artifactDisposition.storageActions,
    [
      'RETAIN_ACCEPTED',
      'DELETE_REJECTED',
      'MOVE_REENCRYPT_QUARANTINE'
    ]
  );
  assert.equal(
    contract.resultIngress.artifactDisposition.storagePortMode,
    'NO_READ_SERVER_SIDE_ONLY'
  );
  assert.equal(
    contract.resultIngress.artifactDisposition.operationIdBinding,
    'IMMUTABLE_INTENT_DIGEST'
  );
  assert.equal(
    contract.resultIngress.artifactDisposition
      .storageReceiptReferencePrefix,
    'storage-receipt://'
  );
  assert.equal(
    contract.resultIngress.artifactDisposition
      .sourceMissingOperationIdBehavior,
    'PRESERVE_ABSENCE_RECEIPT_OPERATION'
  );
  assert.equal(
    contract.resultIngress.artifactDisposition
      .acceptedRequiresExplicitAcceptanceGate,
    true
  );
  assert.equal(
    contract.resultIngress.artifactDisposition
      .normalizationEligibleState,
    'ACCEPTED'
  );
  assert.equal(
    contract.resultIngress.artifactDisposition.maximumRetentionSeconds,
    604800
  );
  assert.equal(
    contract.resultIngress.artifactDisposition.quarantine.objectPrefix,
    'restricted/sast-artifact-quarantine/'
  );
  assert.equal(
    contract.resultIngress.artifactDisposition.quarantine
      .keyMaterialInDurableMetadataAllowed,
    false
  );
  assert.equal(
    contract.resultIngress.artifactDisposition
      .objectKeyInDecisionOrAuditAllowed,
    false
  );
  assert.equal(contract.evidenceHandoff.targetPlane, 'DATA_SECURITY_PLANE');
  assert.equal(contract.evidenceHandoff.output, 'redacted-evidence-pack-metadata');
});

test('microVM scanner sandbox forbids package install, builds, dynamic tests, direct upload, and AI repository access', () => {
  const contract = readContract();

  assert.deepEqual(contract.allowedOperations, [
    'SCAN_SCOPED_REPOSITORY_FETCH',
    'STATIC_SCANNER_RUN',
    'NORMALIZED_FINDING_OUTPUT',
    'REDACTED_EVIDENCE_PACK_BUILD'
  ]);
  assert.deepEqual(contract.forbiddenOperations, [
    'PACKAGE_INSTALL',
    'CUSTOMER_REPOSITORY_BUILD',
    'DYNAMIC_TESTING',
    'SHELL_INTERPOLATION',
    'ARBITRARY_COMMAND_OR_ARGUMENT',
    'CUSTOMER_ENVIRONMENT',
    'CUSTOMER_EXECUTABLE_CONFIG',
    'RUNTIME_RULE_OR_DATABASE_UPDATE',
    'PUBLIC_INTERNET_EGRESS',
    'CLOUD_METADATA_ACCESS',
    'DIRECT_SOURCE_UPLOAD',
    'AI_FULL_REPOSITORY_ACCESS',
    'AUTO_FIX_PR_OR_MR'
  ]);

  for (const forbiddenOperation of contract.forbiddenOperations) {
    assert.equal(
      contract.allowedOperations.includes(forbiddenOperation),
      false,
      `Forbidden operation ${forbiddenOperation} must not be allowed`
    );
  }

  assert.equal(contract.aiPlaneAccess.fullRepository, false);
  assert.equal(contract.aiPlaneAccess.sourceArchive, false);
  assert.equal(contract.aiPlaneAccess.scmCredentials, false);
  assert.equal(contract.aiPlaneAccess.rawScannerPayload, false);
  assert.equal(contract.aiPlaneAccess.reducedEvidenceOnly, true);
  for (const forbiddenField of forbiddenSecretFields) {
    assert.equal(forbiddenField in contract.repositoryAccess, false);
  }
});
