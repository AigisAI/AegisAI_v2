import type {
  SastPreflightDecision,
  SastRepositoryPreflightSelection,
  SastRepositoryTreeEntry
} from './sast-fetch';
import {
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_SCANNER_KINDS,
  isSastScanPlanValid,
  type SastArtifactSchema,
  type SastProfileId,
  type SastResourceLimits,
  type SastScanPlan,
  type SastScannerKind,
  type ScannerExecutionStatus
} from './sast-runtime';

export const SAST_SCANNER_WRAPPER_SCHEMA_VERSION = 'sast-wrapper-v1' as const;
export const SAST_SCANNER_PLAN_DIGEST_VERSION = 'sast-scan-plan-v1' as const;
export const SAST_SANDBOX_ATTESTATION_VERSION = '1' as const;
export const SAST_SANDBOX_ATTESTATION_ISSUER =
  'aegisai-microvm-provisioner' as const;
export const SAST_SANDBOX_ATTESTATION_AUDIENCE =
  'aegisai-scanner-wrapper' as const;
export const MAX_SAST_SANDBOX_ATTESTATION_TTL_SECONDS = 5 * 60;
export const SAST_SANDBOX_CLEANUP_TIMEOUT_SECONDS = 60;
export const SAST_SCANNER_WORKSPACE_ROOT = '/workspace/repository' as const;
export const SAST_SCANNER_SELECTED_WORKSPACE_ROOT =
  '/workspace/selected' as const;
export const SAST_SCANNER_OUTPUT_ROOT = '/workspace/output' as const;
export const SAST_SCANNER_ASSET_ROOT = '/opt/aegis/assets' as const;
export const SAST_SCANNER_WORKING_DIRECTORY =
  SAST_SCANNER_OUTPUT_ROOT;

export const SAST_SCANNER_RUNTIME_EVENT_TYPES = [
  'sandbox.ready',
  'scanner.started',
  'scanner.completed',
  'scanner.failed',
  'sandbox.cleanup_pending',
  'sandbox.terminated',
  'sandbox.cleanup_failed'
] as const;
export type SastScannerRuntimeEventType =
  (typeof SAST_SCANNER_RUNTIME_EVENT_TYPES)[number];

export interface SastSandboxRuntimePolicy {
  sandboxProvider: 'MICROVM';
  isolationClass: 'HARDENED' | 'RESTRICTED';
  runAsNonRoot: true;
  readOnlyRootFilesystem: true;
  readOnlyRepository: true;
  privateWritableOutput: true;
  shellInterpolationAllowed: false;
  customerEnvironmentAllowed: false;
  customerExecutableConfigAllowed: false;
  customerSuppressionConfigAllowed: false;
  repositoryToolConfigDiscoveryAllowed: false;
  packageInstallAllowed: false;
  repositoryBuildAllowed: false;
  dynamicExecutionAllowed: false;
  runtimeAssetUpdateAllowed: false;
  publicInternetEgressAllowed: false;
  cloudMetadataAccessAllowed: false;
  networkEgressPolicy: 'RESULT_INGRESS_AND_TELEMETRY_ONLY';
  resourceLimits: Readonly<
    Pick<
      SastResourceLimits,
      | 'cpuMillicores'
      | 'memoryMiB'
      | 'ephemeralDiskMiB'
      | 'processLimit'
      | 'fileDescriptorLimit'
      | 'maxFindings'
      | 'maxArtifactBytes'
      | 'maxArtifactRecords'
      | 'maxStdoutStderrBytes'
      | 'wallClockTimeoutSeconds'
    >
  >;
}

export interface SastSandboxRuntimeAttestationClaims {
  version: typeof SAST_SANDBOX_ATTESTATION_VERSION;
  issuer: typeof SAST_SANDBOX_ATTESTATION_ISSUER;
  audience: typeof SAST_SANDBOX_ATTESTATION_AUDIENCE;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  attemptNumber: number;
  sandboxId: string;
  workloadIdentityRef: string;
  planDigest: `sha256:${string}`;
  canonicalScanKey: `sha256:${string}`;
  fixedCommitSha: string;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  scannerSetDigest: `sha256:${string}`;
  preflightAttestationRef: string;
  preflightInventoryDigest: `sha256:${string}`;
  policy: Readonly<SastSandboxRuntimePolicy>;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  attemptDeadlineAt: string;
}

export interface SastSandboxRuntimeAttestation {
  claims: Readonly<SastSandboxRuntimeAttestationClaims>;
  signature: `sha256:${string}`;
}

export interface SastScannerPreflightBinding {
  pathPolicyVersion: string;
  attestationRef: string;
  inventoryDigest: `sha256:${string}`;
  decision: Extract<SastPreflightDecision, 'ACCEPT' | 'RESTRICTED_ESCALATION'>;
}

export interface SastScannerRepositoryManifest {
  scanner: SastScannerKind;
  source: 'MICROVM_READ_ONLY_MOUNT';
  observedAt: string;
  scannerInput: Readonly<SastScannerInputBinding>;
  selection: Readonly<SastRepositoryPreflightSelection>;
  entries: readonly SastRepositoryTreeEntry[];
}

export interface SastScannerInputBinding {
  mode: 'FULL_REPOSITORY' | 'CONTENT_BOUND_PATH_ALLOWLIST';
  path: string;
  sourceInventoryDigest: `sha256:${string}`;
  readOnly: true;
}

export interface SastScannerWrapperExecutionRequest {
  plan: Readonly<SastScanPlan>;
  attemptId: string;
  attemptNumber: number;
  sandboxId: string;
  workloadIdentityRef: string;
  preflight: Readonly<SastScannerPreflightBinding>;
  sandboxAttestation: Readonly<SastSandboxRuntimeAttestation>;
}

export interface SastScannerInvocation {
  wrapperSchemaVersion: typeof SAST_SCANNER_WRAPPER_SCHEMA_VERSION;
  scanner: SastScannerKind;
  required: boolean;
  executable: string;
  args: readonly string[];
  environment: Readonly<Record<string, string>>;
  workingDirectory: string;
  scannerInputPath: string;
  outputPath: string;
  artifactSchema: SastArtifactSchema;
  artifactSchemaVersion: string;
  schemaBundleDigest: `sha256:${string}`;
  normalizerBundleDigest: `sha256:${string}`;
  scannerVersion: string;
  scannerImageDigest: `sha256:${string}`;
  wrapperDigest: `sha256:${string}`;
  ruleBundleDigest?: `sha256:${string}`;
  vulnerabilityDatabaseDigest?: `sha256:${string}`;
  scannerSetDigest: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  preflightAttestationRef: string;
  preflightInventoryDigest: `sha256:${string}`;
  sandboxPolicy: Readonly<SastSandboxRuntimePolicy>;
}

export interface SastBoundedLogObservation {
  byteSize: number;
  contentDigest: `sha256:${string}`;
  truncated: boolean;
  secretRedactionApplied: true;
}

export interface SastScannerResourceObservation {
  cpuTimeMilliseconds: number;
  peakMemoryBytes: number;
  bytesRead: number;
  bytesWritten: number;
  peakProcessCount: number;
  peakFileDescriptorCount: number;
}

export interface SastScannerArtifactObservation {
  artifactRef: string;
  contentDigest: `sha256:${string}`;
  byteSize: number;
  recordCount: number;
  truncated: boolean;
}

export interface SastScannerProcessObservation {
  scanner: SastScannerKind;
  scannerVersion: string;
  scannerImageDigest: `sha256:${string}`;
  wrapperDigest: `sha256:${string}`;
  ruleBundleDigest?: `sha256:${string}`;
  vulnerabilityDatabaseDigest?: `sha256:${string}`;
  scannerWorkspaceInventoryDigest: `sha256:${string}`;
  exitCode: number;
  terminationSignal?: string;
  timedOut: boolean;
  outputLimitExceeded: boolean;
  startedAt: string;
  completedAt: string;
  stdout: Readonly<SastBoundedLogObservation>;
  stderr: Readonly<SastBoundedLogObservation>;
  resources: Readonly<SastScannerResourceObservation>;
  artifact?: Readonly<SastScannerArtifactObservation>;
}

export interface SastScannerExecutionRecord {
  scannerRunId: string;
  attemptId: string;
  invocation: Readonly<SastScannerInvocation>;
  status: ScannerExecutionStatus;
  observation: Readonly<SastScannerProcessObservation>;
}

export interface SastScannerRuntimeExecutionResult {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  attemptNumber: number;
  sandboxId: string;
  workloadIdentityRef: string;
  stage: 'COMPLETED';
  scannerRuns: readonly SastScannerExecutionRecord[];
  cleanup: Readonly<SastSignedSandboxCleanupObservation>;
  auditSignals: readonly SastScannerRuntimeAuditSignal[];
}

export interface SastSandboxCleanupObservation {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  sandboxId: string;
  workloadIdentityRef: string;
  credentialRevokedAndWiped: boolean;
  scannerProcessesTerminated: boolean;
  writableVolumesDestroyed: boolean;
  microVmTerminated: boolean;
  resultIngressClosed: boolean;
  completedAt: string;
  nonce: string;
}

export interface SastSignedSandboxCleanupObservation {
  observation: Readonly<SastSandboxCleanupObservation>;
  signature: `sha256:${string}`;
}

export interface SastScannerRuntimeAuditSignal {
  eventId: string;
  eventType: SastScannerRuntimeEventType;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  sandboxId: string;
  workloadIdentityRef: string;
  scanner?: SastScannerKind;
  scannerRunId?: string;
  executionStatus?: ScannerExecutionStatus;
  reasonCode?: string;
  occurredAt: string;
  metadataDigest: `sha256:${string}`;
}

export function isSastSandboxRuntimePolicyValid(
  policy: SastSandboxRuntimePolicy,
  plan: SastScanPlan
): boolean {
  if (!policy || !plan?.profile?.limits) {
    return false;
  }
  const expectedLimits = scannerRuntimeLimits(plan.profile.limits);
  return (
    hasOnlyKeys(policy, [
      'cloudMetadataAccessAllowed',
      'customerEnvironmentAllowed',
      'customerExecutableConfigAllowed',
      'customerSuppressionConfigAllowed',
      'dynamicExecutionAllowed',
      'isolationClass',
      'networkEgressPolicy',
      'packageInstallAllowed',
      'privateWritableOutput',
      'publicInternetEgressAllowed',
      'readOnlyRepository',
      'readOnlyRootFilesystem',
      'repositoryBuildAllowed',
      'repositoryToolConfigDiscoveryAllowed',
      'resourceLimits',
      'runAsNonRoot',
      'runtimeAssetUpdateAllowed',
      'sandboxProvider',
      'shellInterpolationAllowed'
    ]) &&
    policy.sandboxProvider === 'MICROVM' &&
    policy.isolationClass === plan.isolationClass &&
    (policy.isolationClass === 'HARDENED' ||
      policy.isolationClass === 'RESTRICTED') &&
    policy.runAsNonRoot === true &&
    policy.readOnlyRootFilesystem === true &&
    policy.readOnlyRepository === true &&
    policy.privateWritableOutput === true &&
    policy.shellInterpolationAllowed === false &&
    policy.customerEnvironmentAllowed === false &&
    policy.customerExecutableConfigAllowed === false &&
    policy.customerSuppressionConfigAllowed === false &&
    policy.repositoryToolConfigDiscoveryAllowed === false &&
    policy.packageInstallAllowed === false &&
    policy.repositoryBuildAllowed === false &&
    policy.dynamicExecutionAllowed === false &&
    policy.runtimeAssetUpdateAllowed === false &&
    policy.publicInternetEgressAllowed === false &&
    policy.cloudMetadataAccessAllowed === false &&
    policy.networkEgressPolicy === 'RESULT_INGRESS_AND_TELEMETRY_ONLY' &&
    hasOnlyKeys(policy.resourceLimits, Object.keys(expectedLimits)) &&
    sameRecord(policy.resourceLimits, expectedLimits)
  );
}

export function buildSastScanPlanDigestPreimage(plan: SastScanPlan): string {
  return canonicalJson({
    version: SAST_SCANNER_PLAN_DIGEST_VERSION,
    plan
  });
}

export function isSastScannerWrapperExecutionRequestValid(
  request: SastScannerWrapperExecutionRequest
): boolean {
  if (
    !request ||
    !hasOnlyKeys(request, [
      'attemptId',
      'attemptNumber',
      'plan',
      'preflight',
      'sandboxAttestation',
      'sandboxId',
      'workloadIdentityRef'
    ]) ||
    !hasOnlyKeys(request.preflight, [
      'attestationRef',
      'decision',
      'inventoryDigest',
      'pathPolicyVersion'
    ]) ||
    !hasOnlyKeys(request.sandboxAttestation, ['claims', 'signature']) ||
    !request.sandboxAttestation?.claims ||
    !hasOnlyKeys(request.sandboxAttestation.claims, [
      'attemptDeadlineAt',
      'attemptId',
      'attemptNumber',
      'audience',
      'canonicalScanKey',
      'expiresAt',
      'fixedCommitSha',
      'issuedAt',
      'issuer',
      'nonce',
      'planDigest',
      'policy',
      'preflightAttestationRef',
      'preflightInventoryDigest',
      'profileDigest',
      'profileId',
      'repositoryBindingId',
      'sandboxId',
      'scannerSetDigest',
      'scanRequestId',
      'tenantId',
      'version',
      'workloadIdentityRef'
    ]) ||
    !isSha256Digest(request.sandboxAttestation.signature) ||
    !isSastScanPlanValid(request.plan) ||
    !isBoundedIdentifier(request.attemptId, 255) ||
    !Number.isSafeInteger(request.attemptNumber) ||
    request.attemptNumber < 1 ||
    request.attemptNumber > 2 ||
    !isBoundedIdentifier(request.sandboxId, 255) ||
    !isBoundedIdentifier(request.workloadIdentityRef, 512) ||
    !request.preflight ||
    !request.sandboxAttestation
  ) {
    return false;
  }

  return (
    isBoundedIdentifier(request.preflight.pathPolicyVersion, 255) &&
    request.sandboxAttestation.claims.version ===
      SAST_SANDBOX_ATTESTATION_VERSION &&
    request.sandboxAttestation.claims.issuer ===
      SAST_SANDBOX_ATTESTATION_ISSUER &&
    request.sandboxAttestation.claims.audience ===
      SAST_SANDBOX_ATTESTATION_AUDIENCE &&
    isSha256Digest(request.sandboxAttestation.claims.planDigest) &&
    /^[a-f0-9]{32}$/u.test(request.sandboxAttestation.claims.nonce) &&
    Number.isFinite(
      Date.parse(request.sandboxAttestation.claims.issuedAt)
    ) &&
    Number.isFinite(
      Date.parse(request.sandboxAttestation.claims.expiresAt)
    ) &&
    Number.isFinite(
      Date.parse(request.sandboxAttestation.claims.attemptDeadlineAt)
    ) &&
    request.sandboxAttestation.claims.tenantId ===
      request.plan.tenantId &&
    request.sandboxAttestation.claims.repositoryBindingId ===
      request.plan.repositoryState.repositoryBindingId &&
    request.sandboxAttestation.claims.scanRequestId ===
      request.plan.scanRequestId &&
    request.sandboxAttestation.claims.attemptId === request.attemptId &&
    request.sandboxAttestation.claims.attemptNumber ===
      request.attemptNumber &&
    request.sandboxAttestation.claims.sandboxId === request.sandboxId &&
    request.sandboxAttestation.claims.workloadIdentityRef ===
      request.workloadIdentityRef &&
    request.sandboxAttestation.claims.canonicalScanKey ===
      request.plan.canonicalScanKey &&
    request.sandboxAttestation.claims.fixedCommitSha ===
      request.plan.repositoryState.fixedCommitSha &&
    request.sandboxAttestation.claims.profileId ===
      request.plan.profile.id &&
    request.sandboxAttestation.claims.profileDigest ===
      request.plan.profileDigest &&
    request.sandboxAttestation.claims.scannerSetDigest ===
      request.plan.scannerSet.scannerSetDigest &&
    request.sandboxAttestation.claims.preflightAttestationRef ===
      request.preflight.attestationRef &&
    request.sandboxAttestation.claims.preflightInventoryDigest ===
      request.preflight.inventoryDigest &&
    isBoundedIdentifier(request.preflight.attestationRef, 8192) &&
    (request.attemptNumber === 1
      ? request.preflight.attestationRef ===
        request.plan.repositoryState.attestationRef
      : request.preflight.attestationRef !==
        request.plan.repositoryState.attestationRef) &&
    request.preflight.inventoryDigest ===
      request.plan.repositoryState.inventoryDigest &&
    (request.preflight.decision === 'ACCEPT' ||
      (request.preflight.decision === 'RESTRICTED_ESCALATION' &&
        request.plan.isolationClass === 'RESTRICTED')) &&
    isSastSandboxRuntimePolicyValid(
      request.sandboxAttestation.claims.policy,
      request.plan
    )
  );
}

export function isSastScannerInvocationBoundToPlan(
  invocation: SastScannerInvocation,
  plan: SastScanPlan,
  preflight: SastScannerPreflightBinding
): boolean {
  if (
    !invocation ||
    !hasOnlyKeys(invocation, [
      'args',
      'artifactSchema',
      'artifactSchemaVersion',
      'environment',
      'executable',
      'outputPath',
      'preflightAttestationRef',
      'preflightInventoryDigest',
      'profileDigest',
      'profileId',
      'required',
      'ruleBundleDigest',
      'sandboxPolicy',
      'scanner',
      'scannerInputPath',
      'scannerImageDigest',
      'schemaBundleDigest',
      'normalizerBundleDigest',
      'scannerSetDigest',
      'scannerVersion',
      'vulnerabilityDatabaseDigest',
      'workingDirectory',
      'wrapperDigest',
      'wrapperSchemaVersion'
    ]) ||
    !Array.isArray(invocation.args) ||
    !invocation.environment ||
    typeof invocation.environment !== 'object' ||
    Array.isArray(invocation.environment) ||
    !invocation.sandboxPolicy ||
    !isSastScanPlanValid(plan) ||
    !SAST_SCANNER_KINDS.includes(invocation.scanner) ||
    !plan.profile.requiredScanners.includes(invocation.scanner)
  ) {
    return false;
  }

  const scanner = plan.scannerSet.scanners[invocation.scanner];
  const ruleBundles = plan.scannerSet.ruleBundles.filter(
    (bundle) => bundle.scanner === invocation.scanner
  );
  const ruleBundleDigests = ruleBundles.map((bundle) => bundle.digest);
  const expectedOutputPath = expectedScannerOutputPath(invocation.scanner);
  const expectedInputPath = expectedScannerInputPath(plan, preflight);
  const expectedArgs = expectedScannerArguments(
    invocation.scanner,
    plan,
    ruleBundles[0]?.digest,
    expectedOutputPath,
    expectedInputPath
  );
  const expectedEnvironment = expectedScannerEnvironment(
    invocation.scanner,
    plan
  );
  const expectedArtifactSchema =
    invocation.scanner === 'OPENGREP'
      ? 'OPENGREP_SARIF'
      : invocation.scanner === 'TRIVY'
        ? 'TRIVY_JSON'
        : 'CYCLONEDX_JSON';

  return (
    invocation.wrapperSchemaVersion ===
      SAST_SCANNER_WRAPPER_SCHEMA_VERSION &&
    invocation.required === true &&
    invocation.executable ===
      `/opt/aegis/scanners/${invocation.scanner.toLowerCase()}` &&
    sameArray(invocation.args, expectedArgs) &&
    sameRecord(invocation.environment, expectedEnvironment) &&
    invocation.scannerInputPath === expectedInputPath &&
    invocation.outputPath === expectedOutputPath &&
    invocation.artifactSchema === expectedArtifactSchema &&
    invocation.artifactSchemaVersion ===
      SAST_ARTIFACT_SCHEMA_VERSIONS[expectedArtifactSchema] &&
    invocation.schemaBundleDigest === plan.scannerSet.schemaBundle.digest &&
    invocation.normalizerBundleDigest ===
      plan.scannerSet.normalizerBundle.digest &&
    invocation.scannerVersion === scanner.version &&
    invocation.scannerImageDigest === scanner.digest &&
    invocation.wrapperDigest === scanner.wrapper.digest &&
    invocation.scannerSetDigest === plan.scannerSet.scannerSetDigest &&
    invocation.profileId === plan.profile.id &&
    invocation.profileDigest === plan.profileDigest &&
    invocation.preflightAttestationRef === preflight.attestationRef &&
    invocation.preflightInventoryDigest === preflight.inventoryDigest &&
    invocation.workingDirectory === SAST_SCANNER_WORKING_DIRECTORY &&
    invocation.outputPath.startsWith(`${SAST_SCANNER_OUTPUT_ROOT}/`) &&
    invocation.args.every(
      (argument) =>
        typeof argument === 'string' &&
        argument.length > 0 &&
        !containsControlCharacter(argument)
    ) &&
    Object.entries(invocation.environment).every(
      ([key, value]) =>
        /^[A-Z][A-Z0-9_]{0,63}$/u.test(key) &&
        isBoundedIdentifier(value, 1024)
    ) &&
    (invocation.scanner === 'SYFT'
      ? invocation.ruleBundleDigest === undefined
      : ruleBundles.length === 1 &&
        invocation.ruleBundleDigest !== undefined &&
        ruleBundleDigests.includes(invocation.ruleBundleDigest)) &&
    (invocation.scanner === 'TRIVY'
      ? invocation.vulnerabilityDatabaseDigest ===
        plan.scannerSet.vulnerabilityDatabase.digest
      : invocation.vulnerabilityDatabaseDigest === undefined) &&
    isSastSandboxRuntimePolicyValid(invocation.sandboxPolicy, plan)
  );
}

export function isSastScannerProcessObservationValid(
  observation: SastScannerProcessObservation,
  invocation: SastScannerInvocation,
  plan: SastScanPlan
): boolean {
  if (
    !observation ||
    !invocation ||
    !plan ||
    !hasOnlyKeys(observation, [
      'artifact',
      'completedAt',
      'exitCode',
      'outputLimitExceeded',
      'resources',
      'ruleBundleDigest',
      'scanner',
      'scannerImageDigest',
      'scannerVersion',
      'scannerWorkspaceInventoryDigest',
      'startedAt',
      'stderr',
      'stdout',
      'terminationSignal',
      'timedOut',
      'vulnerabilityDatabaseDigest',
      'wrapperDigest'
    ]) ||
    observation.scanner !== invocation.scanner ||
    !SAST_SCANNER_KINDS.includes(observation.scanner)
  ) {
    return false;
  }
  const startedAt = Date.parse(observation.startedAt);
  const completedAt = Date.parse(observation.completedAt);
  const elapsed = completedAt - startedAt;
  const limits = plan.profile.limits;
  const artifact = observation.artifact;
  return (
    observation.scannerVersion === invocation.scannerVersion &&
    observation.scannerImageDigest === invocation.scannerImageDigest &&
    observation.wrapperDigest === invocation.wrapperDigest &&
    observation.ruleBundleDigest === invocation.ruleBundleDigest &&
    observation.vulnerabilityDatabaseDigest ===
      invocation.vulnerabilityDatabaseDigest &&
    observation.scannerWorkspaceInventoryDigest ===
      invocation.preflightInventoryDigest &&
    Number.isSafeInteger(observation.exitCode) &&
    observation.exitCode >= -1 &&
    observation.exitCode <= 255 &&
    (observation.terminationSignal === undefined ||
      [
        'SIGABRT',
        'SIGKILL',
        'SIGSEGV',
        'SIGTERM',
        'SIGXCPU',
        'SIGXFSZ'
      ].includes(observation.terminationSignal)) &&
    typeof observation.timedOut === 'boolean' &&
    typeof observation.outputLimitExceeded === 'boolean' &&
    (!observation.timedOut || observation.exitCode === -1) &&
    (observation.terminationSignal === undefined ||
      observation.exitCode === -1) &&
    (observation.exitCode !== 0 ||
      (observation.terminationSignal === undefined &&
        observation.timedOut === false)) &&
    Number.isFinite(startedAt) &&
    Number.isFinite(completedAt) &&
    completedAt >= startedAt &&
    elapsed <= limits.wallClockTimeoutSeconds * 1000 + 1_000 &&
    isBoundedLog(observation.stdout, limits.maxStdoutStderrBytes) &&
    isBoundedLog(observation.stderr, limits.maxStdoutStderrBytes) &&
    ((!observation.stdout.truncated && !observation.stderr.truncated) ||
      observation.outputLimitExceeded) &&
    observation.stdout.byteSize + observation.stderr.byteSize <=
      limits.maxStdoutStderrBytes &&
    isResourceObservationValid(observation.resources, limits) &&
    (artifact === undefined ||
      (artifact !== null &&
        hasOnlyKeys(artifact, [
          'artifactRef',
          'byteSize',
          'contentDigest',
          'recordCount',
          'truncated'
        ]) &&
        artifact.artifactRef ===
        `${plan.resultIngressRef}/${observation.scanner.toLowerCase()}` &&
        isBoundedIdentifier(artifact.artifactRef, 2048) &&
        isSha256Digest(artifact.contentDigest) &&
        Number.isSafeInteger(artifact.byteSize) &&
        artifact.byteSize > 0 &&
        artifact.byteSize <= limits.maxArtifactBytes &&
        Number.isSafeInteger(artifact.recordCount) &&
        artifact.recordCount >= 0 &&
        artifact.recordCount <=
          (observation.scanner === 'SYFT'
            ? limits.maxArtifactRecords
            : Math.min(
                limits.maxArtifactRecords,
                limits.maxFindings
              )) &&
        typeof artifact.truncated === 'boolean'))
  );
}

export function deriveScannerExecutionStatus(
  observation: SastScannerProcessObservation
): ScannerExecutionStatus {
  if (observation.outputLimitExceeded || observation.artifact?.truncated) {
    return 'QUARANTINED';
  }
  if (observation.timedOut) {
    return 'TIMED_OUT';
  }
  if (
    observation.exitCode === 0 &&
    observation.artifact &&
    observation.artifact.byteSize > 0
  ) {
    return 'SUCCEEDED';
  }
  return 'FAILED';
}

export function scannerRuntimeLimits(
  limits: SastResourceLimits
): SastSandboxRuntimePolicy['resourceLimits'] {
  return {
    cpuMillicores: limits.cpuMillicores,
    memoryMiB: limits.memoryMiB,
    ephemeralDiskMiB: limits.ephemeralDiskMiB,
    processLimit: limits.processLimit,
    fileDescriptorLimit: limits.fileDescriptorLimit,
    maxFindings: limits.maxFindings,
    maxArtifactBytes: limits.maxArtifactBytes,
    maxArtifactRecords: limits.maxArtifactRecords,
    maxStdoutStderrBytes: limits.maxStdoutStderrBytes,
    wallClockTimeoutSeconds: limits.wallClockTimeoutSeconds
  };
}

function isBoundedLog(
  observation: SastBoundedLogObservation,
  maximumBytes: number
): boolean {
  return (
    observation !== undefined &&
    observation !== null &&
    typeof observation === 'object' &&
    !Array.isArray(observation) &&
    hasOnlyKeys(observation, [
      'byteSize',
      'contentDigest',
      'secretRedactionApplied',
      'truncated'
    ]) &&
    Number.isSafeInteger(observation.byteSize) &&
    observation.byteSize >= 0 &&
    observation.byteSize <= maximumBytes &&
    isSha256Digest(observation.contentDigest) &&
    typeof observation.truncated === 'boolean' &&
    observation.secretRedactionApplied === true
  );
}

function isResourceObservationValid(
  observation: SastScannerResourceObservation,
  limits: SastResourceLimits
): boolean {
  return (
    observation !== undefined &&
    observation !== null &&
    typeof observation === 'object' &&
    !Array.isArray(observation) &&
    hasOnlyKeys(observation, [
      'bytesRead',
      'bytesWritten',
      'cpuTimeMilliseconds',
      'peakFileDescriptorCount',
      'peakMemoryBytes',
      'peakProcessCount'
    ]) &&
    isNonNegativeSafeInteger(observation.cpuTimeMilliseconds) &&
    observation.cpuTimeMilliseconds <=
      limits.wallClockTimeoutSeconds * limits.cpuMillicores &&
    isNonNegativeSafeInteger(observation.peakMemoryBytes) &&
    observation.peakMemoryBytes <= limits.memoryMiB * 1024 * 1024 &&
    isNonNegativeSafeInteger(observation.bytesRead) &&
    isNonNegativeSafeInteger(observation.bytesWritten) &&
    observation.bytesWritten <= limits.ephemeralDiskMiB * 1024 * 1024 &&
    isNonNegativeSafeInteger(observation.peakProcessCount) &&
    observation.peakProcessCount <= limits.processLimit &&
    isNonNegativeSafeInteger(observation.peakFileDescriptorCount) &&
    observation.peakFileDescriptorCount <= limits.fileDescriptorLimit
  );
}

function sameRecord(
  left: Readonly<Record<string, unknown>>,
  right: Readonly<Record<string, unknown>>
): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) =>
        key === rightKeys[index] && Object.is(left[key], right[key])
    )
  );
}

function isNonNegativeSafeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function isSha256Digest(value: unknown): value is `sha256:${string}` {
  return (
    typeof value === 'string' &&
    /^sha256:[a-f0-9]{64}$/u.test(value)
  );
}

function isBoundedIdentifier(value: string, maximumBytes: number): boolean {
  return (
    typeof value === 'string' &&
    value.trim().length > 0 &&
    new TextEncoder().encode(value).byteLength <= maximumBytes &&
    !containsControlCharacter(value)
  );
}

function containsControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}

function expectedScannerOutputPath(scanner: SastScannerKind): string {
  if (scanner === 'OPENGREP') {
    return `${SAST_SCANNER_OUTPUT_ROOT}/opengrep.sarif`;
  }
  if (scanner === 'TRIVY') {
    return `${SAST_SCANNER_OUTPUT_ROOT}/trivy.json`;
  }
  return `${SAST_SCANNER_OUTPUT_ROOT}/syft.cdx.json`;
}

function expectedScannerInputPath(
  plan: SastScanPlan,
  preflight: SastScannerPreflightBinding
): string {
  return plan.profile.scope === 'CHANGED_FILES_WITH_CONTEXT'
    ? `${SAST_SCANNER_SELECTED_WORKSPACE_ROOT}/${digestId(
        preflight.inventoryDigest
      )}`
    : SAST_SCANNER_WORKSPACE_ROOT;
}

function expectedScannerArguments(
  scanner: SastScannerKind,
  plan: SastScanPlan,
  ruleBundleDigest: `sha256:${string}` | undefined,
  outputPath: string,
  scannerInputPath: string
): readonly string[] {
  if (scanner === 'OPENGREP') {
    if (!ruleBundleDigest) return [];
    return [
      'scan',
      '-f',
      `${SAST_SCANNER_ASSET_ROOT}/rules/opengrep/${digestId(ruleBundleDigest)}`,
      `--sarif-output=${outputPath}`,
      '--no-autofix',
      '--disable-nosem',
      '--no-git-ignore',
      '--x-ignore-semgrepignore-files',
      '--disable-version-check',
      '--strict',
      '--jobs=1',
      `--max-memory=${plan.profile.limits.memoryMiB}`,
      `--max-target-bytes=${plan.profile.limits.maxSingleFileBytes}`,
      scannerInputPath
    ];
  }
  if (scanner === 'TRIVY') {
    if (!ruleBundleDigest) return [];
    const wrapperAssetRoot = scannerWrapperAssetRoot(
      scanner,
      plan.scannerSet.scanners.TRIVY.wrapper.digest
    );
    return [
      'filesystem',
      '--config',
      `${wrapperAssetRoot}/config.yaml`,
      '--format',
      'json',
      '--output',
      outputPath,
      '--scanners',
      'vuln,misconfig,secret',
      '--cache-dir',
      `${SAST_SCANNER_ASSET_ROOT}/trivy/${digestId(
        plan.scannerSet.vulnerabilityDatabase.digest
      )}/${digestId(ruleBundleDigest)}`,
      '--ignorefile',
      `${wrapperAssetRoot}/empty.trivyignore`,
      '--secret-config',
      `${SAST_SCANNER_ASSET_ROOT}/rules/trivy/${digestId(
        ruleBundleDigest
      )}/secret.yaml`,
      '--show-suppressed',
      '--timeout',
      `${plan.profile.limits.wallClockTimeoutSeconds}s`,
      '--parallel',
      '1',
      '--quiet',
      '--no-progress',
      '--offline-scan',
      '--skip-db-update',
      '--skip-java-db-update',
      '--skip-check-update',
      '--skip-vex-repo-update',
      '--disable-telemetry',
      '--skip-version-check',
      scannerInputPath
    ];
  }
  const wrapperAssetRoot = scannerWrapperAssetRoot(
    scanner,
    plan.scannerSet.scanners.SYFT.wrapper.digest
  );
  return [
    `dir:${scannerInputPath}`,
    '--config',
    `${wrapperAssetRoot}/config.yaml`,
    '--output',
    `cyclonedx-json@1.6=${outputPath}`
  ];
}

function expectedScannerEnvironment(
  scanner: SastScannerKind,
  plan: SastScanPlan
): Readonly<Record<string, string>> {
  const common = {
    HOME: '/nonexistent',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    NO_COLOR: '1',
    TMPDIR: `${SAST_SCANNER_OUTPUT_ROOT}/tmp`,
    TZ: 'UTC',
    XDG_CONFIG_HOME: '/nonexistent'
  };
  return scanner === 'SYFT'
    ? {
        ...common,
        SYFT_CHECK_FOR_APP_UPDATE: 'false',
        SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES: 'false',
        SYFT_GOLANG_SEARCH_REMOTE_LICENSES: 'false',
        SYFT_GOLANG_USE_PACKAGES_LIB: 'false',
        SYFT_JAVA_USE_NETWORK: 'false',
        SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY: 'false',
        SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES: 'false',
        SYFT_LICENSE_CONTENT: 'none',
        SYFT_LOG_QUIET: 'true',
        SYFT_FILE_METADATA_SELECTION: 'none',
        SYFT_PACKAGE_SEARCH_INDEXED_ARCHIVES: 'false',
        SYFT_PACKAGE_SEARCH_UNINDEXED_ARCHIVES: 'false',
        SYFT_PARALLELISM: '1',
        SYFT_PYTHON_SEARCH_REMOTE_LICENSES: 'false',
        SYFT_FILE_CONTENT_SKIP_FILES_ABOVE_SIZE:
          String(plan.profile.limits.maxSingleFileBytes)
      }
    : common;
}

function digestId(digest: `sha256:${string}`): string {
  return digest.slice('sha256:'.length);
}

function scannerWrapperAssetRoot(
  scanner: SastScannerKind,
  wrapperDigest: `sha256:${string}`
): string {
  return `${SAST_SCANNER_ASSET_ROOT}/wrappers/${scanner.toLowerCase()}/${digestId(
    wrapperDigest
  )}`;
}

function sameArray(
  left: readonly string[],
  right: readonly string[]
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function hasOnlyKeys(value: unknown, allowedKeys: readonly string[]): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const allowed = new Set(allowedKeys);
  return Object.keys(value).every((key) => allowed.has(key));
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
}
