export const PRODUCTION_SAST_RUNTIME_FEATURE_ID = '006-production-sast-runtime-design';

export const SAST_SCANNER_KINDS = ['OPENGREP', 'TRIVY', 'SYFT'] as const;
export type SastScannerKind = (typeof SAST_SCANNER_KINDS)[number];

export const SAST_CAPABILITIES = [
  'SAST',
  'DEPENDENCY_VULNERABILITY',
  'SECRET_DETECTION',
  'IAC_MISCONFIGURATION',
  'SBOM'
] as const;
export type SastCapability = (typeof SAST_CAPABILITIES)[number];

export const SAST_SCAN_LANES = ['FAST', 'DEEP'] as const;
export type SastScanLane = (typeof SAST_SCAN_LANES)[number];

export const SAST_PROFILE_IDS = ['JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1'] as const;
export type SastProfileId = (typeof SAST_PROFILE_IDS)[number];

export const SAST_RUNTIME_STAGES = [
  'QUEUED',
  'PLANNING',
  'PROVISIONING',
  'FETCHING',
  'PREFLIGHT',
  'SCANNING',
  'INGESTING',
  'NORMALIZING',
  'CORRELATING',
  'EVIDENCE_BUILDING',
  'POLICY_PENDING',
  'CLEANUP_PENDING',
  'CLEANUP_FAILED',
  'COMPLETED',
  'FAILED',
  'CANCELED'
] as const;
export type SastRuntimeStage = (typeof SAST_RUNTIME_STAGES)[number];

export const SCANNER_EXECUTION_STATUSES = [
  'PENDING',
  'RUNNING',
  'SUCCEEDED',
  'FAILED',
  'TIMED_OUT',
  'QUARANTINED',
  'SKIPPED_BY_POLICY',
  'KILLED'
] as const;
export type ScannerExecutionStatus = (typeof SCANNER_EXECUTION_STATUSES)[number];

export const SAST_ARTIFACT_INGRESS_MEDIA_TYPE = 'application/octet-stream';
export const SAST_ARTIFACT_ENVELOPE_HEADER = 'x-aegis-sast-artifact-envelope';
export const SAST_ARTIFACT_IDEMPOTENCY_HEADER = 'idempotency-key';
export const SAST_MAX_ARTIFACT_ENVELOPE_BYTES = 8192;

export const SAST_ARTIFACT_SCHEMAS = [
  'OPENGREP_SARIF',
  'TRIVY_JSON',
  'CYCLONEDX_JSON'
] as const;
export type SastArtifactSchema = (typeof SAST_ARTIFACT_SCHEMAS)[number];

export const SAST_ARTIFACT_SCHEMA_VERSIONS = {
  OPENGREP_SARIF: '2.1.0',
  TRIVY_JSON: '2',
  CYCLONEDX_JSON: '1.6'
} as const satisfies Record<SastArtifactSchema, string>;

export const SAST_ARTIFACT_INGESTION_STATES = [
  'RECEIVING',
  'PENDING_VALIDATION',
  'ACCEPTED',
  'REJECTED',
  'QUARANTINED'
] as const;
export type SastArtifactIngestionState =
  (typeof SAST_ARTIFACT_INGESTION_STATES)[number];

export const SAST_COVERAGE_STATES = ['PENDING', 'COMPLETE', 'PARTIAL', 'FAILED'] as const;
export type SastCoverageState = (typeof SAST_COVERAGE_STATES)[number];

export const RULE_BUNDLE_STATES = [
  'DRAFT',
  'VALIDATED',
  'CANARY',
  'ACTIVE',
  'SUSPENDED',
  'ROLLED_BACK',
  'RETIRED'
] as const;
export type RuleBundleState = (typeof RULE_BUNDLE_STATES)[number];

export const SAST_FAILURE_CLASSES = [
  'RETRYABLE_INFRASTRUCTURE',
  'NON_RETRYABLE_INPUT',
  'SCANNER_DEFECT',
  'SECURITY_VIOLATION',
  'CAPACITY_REJECTED'
] as const;
export type SastFailureClass = (typeof SAST_FAILURE_CLASSES)[number];

export const SAST_FORBIDDEN_CAPABILITIES = [
  'CUSTOMER_CODE_EXECUTION',
  'PACKAGE_INSTALL',
  'CUSTOMER_REPOSITORY_BUILD',
  'DYNAMIC_TEST_EXECUTION',
  'DIRECT_SOURCE_UPLOAD',
  'SCM_WRITE',
  'INTEGRATION_ADMIN',
  'AI_FULL_REPOSITORY_ACCESS',
  'AUTO_FIX_PULL_REQUEST'
] as const;
export type SastForbiddenCapability = (typeof SAST_FORBIDDEN_CAPABILITIES)[number];

export const SAST_SCANNER_RESPONSIBILITIES = {
  OPENGREP: {
    authoritativeCapabilities: ['SAST'],
    outputSchema: 'OPENGREP_SARIF',
    mayCreateFindings: true
  },
  TRIVY: {
    authoritativeCapabilities: [
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION'
    ],
    outputSchema: 'TRIVY_JSON',
    mayCreateFindings: true
  },
  SYFT: {
    authoritativeCapabilities: ['SBOM'],
    outputSchema: 'CYCLONEDX_JSON',
    mayCreateFindings: false
  }
} as const satisfies Record<
  SastScannerKind,
  {
    authoritativeCapabilities: readonly SastCapability[];
    outputSchema: string;
    mayCreateFindings: boolean;
  }
>;

export interface SastResourceLimits {
  cpuMillicores: number;
  memoryMiB: number;
  ephemeralDiskMiB: number;
  processLimit: number;
  fileDescriptorLimit: number;
  maxRepositoryBytes: number;
  maxSelectedBytes: number;
  maxFileCount: number;
  maxSingleFileBytes: number;
  maxPathDepth: number;
  maxFindings: number;
  maxArtifactBytes: number;
  maxArtifactRecords: number;
  maxStdoutStderrBytes: number;
  wallClockTimeoutSeconds: number;
}

export interface SastPathPolicy {
  pathNormalizationRequired: true;
  rejectAbsolutePaths: true;
  rejectParentTraversal: true;
  rejectCaseFoldCollisions: true;
  symlinkPolicy: 'REJECT_OUTSIDE_ROOT';
  submodulePolicy: 'DISABLED_BY_DEFAULT';
  lfsPolicy: 'POINTER_METADATA_ONLY_BY_DEFAULT';
  archivePolicy: 'DO_NOT_EXPAND';
  generatedCodePolicy: 'INDEX_BUT_SUPPRESS_BY_DEFAULT';
  vendorCodePolicy: 'DEPENDENCY_ONLY_BY_DEFAULT';
  fixturePolicy: 'SCAN_WITH_NON_BLOCKING_DEFAULT';
}

export interface SastScanProfile {
  readonly id: SastProfileId;
  readonly lane: SastScanLane;
  readonly language: 'JAVA' | 'COMMON';
  readonly scope: 'CHANGED_FILES_WITH_CONTEXT' | 'FULL_REPOSITORY';
  readonly requiredScanners: readonly SastScannerKind[];
  readonly optionalScanners: readonly SastScannerKind[];
  readonly requiredCapabilities: readonly SastCapability[];
  readonly sourceExtensions: readonly string[];
  readonly manifestNames: readonly string[];
  readonly aiAdvisoryEligible: boolean;
  readonly customerBuildAllowed: false;
  readonly packageInstallAllowed: false;
  readonly dynamicExecutionAllowed: false;
  readonly networkEnrichmentAllowed: false;
  readonly limits: Readonly<SastResourceLimits>;
  readonly pathPolicy: Readonly<SastPathPolicy>;
}

const DEFAULT_PATH_POLICY: Readonly<SastPathPolicy> = Object.freeze({
  pathNormalizationRequired: true,
  rejectAbsolutePaths: true,
  rejectParentTraversal: true,
  rejectCaseFoldCollisions: true,
  symlinkPolicy: 'REJECT_OUTSIDE_ROOT',
  submodulePolicy: 'DISABLED_BY_DEFAULT',
  lfsPolicy: 'POINTER_METADATA_ONLY_BY_DEFAULT',
  archivePolicy: 'DO_NOT_EXPAND',
  generatedCodePolicy: 'INDEX_BUT_SUPPRESS_BY_DEFAULT',
  vendorCodePolicy: 'DEPENDENCY_ONLY_BY_DEFAULT',
  fixturePolicy: 'SCAN_WITH_NON_BLOCKING_DEFAULT'
});

export const SAST_SCAN_PROFILES: Readonly<Record<SastProfileId, SastScanProfile>> = Object.freeze({
  JAVA_FAST_V1: freezeSastProfile({
    id: 'JAVA_FAST_V1',
    lane: 'FAST',
    language: 'JAVA',
    scope: 'CHANGED_FILES_WITH_CONTEXT',
    requiredScanners: ['OPENGREP', 'TRIVY'],
    optionalScanners: ['SYFT'],
    requiredCapabilities: ['SAST', 'DEPENDENCY_VULNERABILITY', 'SECRET_DETECTION'],
    sourceExtensions: ['.java'],
    manifestNames: [
      'pom.xml',
      'build.gradle',
      'build.gradle.kts',
      'settings.gradle',
      'settings.gradle.kts',
      'gradle.lockfile'
    ],
    aiAdvisoryEligible: true,
    customerBuildAllowed: false,
    packageInstallAllowed: false,
    dynamicExecutionAllowed: false,
    networkEnrichmentAllowed: false,
    limits: {
      cpuMillicores: 2000,
      memoryMiB: 4096,
      ephemeralDiskMiB: 10240,
      processLimit: 256,
      fileDescriptorLimit: 1024,
      maxRepositoryBytes: 1073741824,
      maxSelectedBytes: 268435456,
      maxFileCount: 25000,
      maxSingleFileBytes: 2097152,
      maxPathDepth: 64,
      maxFindings: 5000,
      maxArtifactBytes: 67108864,
      maxArtifactRecords: 25000,
      maxStdoutStderrBytes: 1048576,
      wallClockTimeoutSeconds: 900
    },
    pathPolicy: DEFAULT_PATH_POLICY
  }),
  JAVA_DEEP_V1: freezeSastProfile({
    id: 'JAVA_DEEP_V1',
    lane: 'DEEP',
    language: 'JAVA',
    scope: 'FULL_REPOSITORY',
    requiredScanners: ['OPENGREP', 'TRIVY', 'SYFT'],
    optionalScanners: [],
    requiredCapabilities: [
      'SAST',
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION',
      'SBOM'
    ],
    sourceExtensions: ['.java'],
    manifestNames: [
      'pom.xml',
      'build.gradle',
      'build.gradle.kts',
      'settings.gradle',
      'settings.gradle.kts',
      'gradle.lockfile'
    ],
    aiAdvisoryEligible: true,
    customerBuildAllowed: false,
    packageInstallAllowed: false,
    dynamicExecutionAllowed: false,
    networkEnrichmentAllowed: false,
    limits: {
      cpuMillicores: 4000,
      memoryMiB: 8192,
      ephemeralDiskMiB: 30720,
      processLimit: 512,
      fileDescriptorLimit: 2048,
      maxRepositoryBytes: 2147483648,
      maxSelectedBytes: 2147483648,
      maxFileCount: 250000,
      maxSingleFileBytes: 5242880,
      maxPathDepth: 64,
      maxFindings: 25000,
      maxArtifactBytes: 268435456,
      maxArtifactRecords: 250000,
      maxStdoutStderrBytes: 1048576,
      wallClockTimeoutSeconds: 3600
    },
    pathPolicy: DEFAULT_PATH_POLICY
  }),
  COMMON_DEEP_V1: freezeSastProfile({
    id: 'COMMON_DEEP_V1',
    lane: 'DEEP',
    language: 'COMMON',
    scope: 'FULL_REPOSITORY',
    requiredScanners: ['TRIVY', 'SYFT'],
    optionalScanners: ['OPENGREP'],
    requiredCapabilities: [
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION',
      'SBOM'
    ],
    sourceExtensions: [],
    manifestNames: [
      'package-lock.json',
      'pnpm-lock.yaml',
      'yarn.lock',
      'requirements.txt',
      'poetry.lock',
      'Pipfile.lock',
      'go.sum',
      'Cargo.lock',
      'Dockerfile'
    ],
    aiAdvisoryEligible: false,
    customerBuildAllowed: false,
    packageInstallAllowed: false,
    dynamicExecutionAllowed: false,
    networkEnrichmentAllowed: false,
    limits: {
      cpuMillicores: 4000,
      memoryMiB: 8192,
      ephemeralDiskMiB: 30720,
      processLimit: 512,
      fileDescriptorLimit: 2048,
      maxRepositoryBytes: 2147483648,
      maxSelectedBytes: 2147483648,
      maxFileCount: 250000,
      maxSingleFileBytes: 5242880,
      maxPathDepth: 64,
      maxFindings: 25000,
      maxArtifactBytes: 268435456,
      maxArtifactRecords: 250000,
      maxStdoutStderrBytes: 1048576,
      wallClockTimeoutSeconds: 3600
    },
    pathPolicy: DEFAULT_PATH_POLICY
  })
});

export const SAST_APPROVED_PROFILE_DIGESTS: Readonly<
  Record<SastProfileId, `sha256:${string}`>
> = Object.freeze({
  JAVA_FAST_V1: 'sha256:19743211685c76ac7c63cb8c829823c45bf458da3aee5dac4f5eaba2b44bbe74',
  JAVA_DEEP_V1: 'sha256:df79726b0d32cf7b1c5987f73a3b1f510b29ba57c67567083c94ad77f7a4b321',
  COMMON_DEEP_V1: 'sha256:2751b8dcd7b4ca7a44fba24a940800c557a03279efc47ba6cf67d6c1151cc8e9'
});

export interface RuleBundleDescriptor {
  bundleId: string;
  version: string;
  state: RuleBundleState;
  digest: `sha256:${string}`;
  signatureRef: string;
  provenanceRef: string;
  compatibilityRef: string;
  rolloutPolicyRef: string;
  killSwitchRef: string;
  scanner: 'OPENGREP' | 'TRIVY';
  source: 'PLATFORM_MANAGED';
  immutable: true;
  customerExecutableConfigAllowed: false;
}

export interface SignedSastArtifactDescriptor {
  digest: `sha256:${string}`;
  signatureRef: string;
  provenanceRef: string;
}

export interface ScannerRuntimeDescriptor extends SignedSastArtifactDescriptor {
  scanner: SastScannerKind;
  version: string;
  sbomRef: string;
  wrapper: SignedSastArtifactDescriptor;
}

export interface VulnerabilityDatabaseDescriptor extends SignedSastArtifactDescriptor {
  databaseVersion: string;
  publishedAt: string;
}

export interface ScannerSetDescriptor {
  scannerSetVersion: string;
  scannerSetDigest: `sha256:${string}`;
  signatureRef: string;
  provenanceRef: string;
  scanners: Record<SastScannerKind, ScannerRuntimeDescriptor>;
  ruleBundles: RuleBundleDescriptor[];
  vulnerabilityDatabase: VulnerabilityDatabaseDescriptor;
  schemaBundle: SignedSastArtifactDescriptor;
  normalizerBundle: SignedSastArtifactDescriptor;
  sbomSchema: 'CYCLONEDX_JSON';
  rollbackRef: string;
}

export interface SastRepositoryState {
  repositoryBindingId: string;
  fixedCommitSha: string;
  targetRef: string;
  inventoryDigest: `sha256:${string}`;
  attestationRef: string;
  shallowFetchPreferred: true;
  submodulesEnabled: false;
  lfsObjectsFetched: false;
}

export interface SastScanPlan {
  tenantId: string;
  scanRequestId: string;
  canonicalScanKey: `sha256:${string}`;
  profile: SastScanProfile;
  profileDigest: `sha256:${string}`;
  policyVersion: string;
  repositoryState: SastRepositoryState;
  scannerSet: ScannerSetDescriptor;
  isolationClass: 'HARDENED' | 'RESTRICTED';
  resultIngressRef: string;
  evidenceOutputRef: string;
  auditSinkRef: string;
  forbiddenCapabilities: SastForbiddenCapability[];
  createdAt: string;
}

export interface ScannerArtifactEnvelope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  scannerRunId: string;
  workloadIdentityRef: string;
  scanner: SastScannerKind;
  scannerVersion: string;
  scannerImageDigest: `sha256:${string}`;
  wrapperDigest: `sha256:${string}`;
  ruleBundleDigest?: `sha256:${string}`;
  vulnerabilityDatabaseDigest?: `sha256:${string}`;
  scannerSetDigest: `sha256:${string}`;
  schemaBundleDigest: `sha256:${string}`;
  normalizerBundleDigest: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  preflightAttestationRef: string;
  preflightInventoryDigest: `sha256:${string}`;
  scannerWorkspaceInventoryDigest: `sha256:${string}`;
  inputCommitSha: string;
  artifactSchema: SastArtifactSchema;
  artifactSchemaVersion: string;
  artifactRef: string;
  contentDigest: `sha256:${string}`;
  byteSize: number;
  recordCount: number;
  truncated: boolean;
  exitCode: number;
  executionStatus: ScannerExecutionStatus;
  producedAt: string;
}

export interface SastArtifactIngressReceipt {
  ingestionId: string;
  scannerRunId: string;
  state: Extract<SastArtifactIngestionState, 'PENDING_VALIDATION'>;
  replayed: boolean;
  receivedAt: string;
}

export interface ExpectedScannerArtifactBinding {
  attemptId: string;
  scannerRunId: string;
  scanner: SastScannerKind;
  artifactRef: string;
  workloadIdentityRef: string;
  preflightAttestationRef: string;
  preflightInventoryDigest: `sha256:${string}`;
}

export interface FindingFingerprintInput {
  repositoryBindingId: string;
  capability: Exclude<SastCapability, 'SBOM'>;
  ruleSemanticId: string;
  normalizedPath: string;
  symbolAnchor: string;
  sinkKind: string;
  structuralHash: string;
}

export const SAST_MAX_COORDINATE_VALUE = 2147483647;

export const SAST_UNKNOWN_LOCATION_REASONS = [
  'SCANNER_LOCATION_OMITTED',
  'LOCATION_NOT_MAPPABLE'
] as const;
export type SastUnknownLocationReason = (typeof SAST_UNKNOWN_LOCATION_REASONS)[number];

export interface SastFileCoordinateMetadata {
  normalizedPath: string;
  lineCount: number;
  maxColumnByLine: readonly number[];
}

export interface SastFileFindingLocation {
  kind: 'FILE';
  normalizedPath: string;
  lineStart: number;
  lineEnd?: number;
  columnStart?: number;
  columnEnd?: number;
  symbol?: string;
}

export interface SastUnknownFindingLocation {
  kind: 'UNKNOWN';
  reasonCode: SastUnknownLocationReason;
  symbol?: string;
}

export type SastFindingLocation = SastFileFindingLocation | SastUnknownFindingLocation;

export interface SastFindingProvenance {
  scanner: Exclude<SastScannerKind, 'SYFT'>;
  scannerVersion: string;
  scannerImageDigest: `sha256:${string}`;
  ruleId: string;
  ruleRevision: string;
  ruleBundleDigest: `sha256:${string}`;
  artifactDigest: `sha256:${string}`;
}

export interface NormalizedSastFinding {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  commitSha: string;
  lane: SastScanLane;
  capability: Exclude<SastCapability, 'SBOM'>;
  stableFingerprint: `sha256:${string}`;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cweIds: string[];
  cveIds: string[];
  location: SastFindingLocation;
  provenance: SastFindingProvenance;
  evidencePackIds: string[];
  status: 'OPEN' | 'WAIVED' | 'SUPPRESSED' | 'FIXED';
}

export interface ScannerCoverageRecord {
  scanner: SastScannerKind;
  required: boolean;
  capabilities: SastCapability[];
  status: ScannerExecutionStatus;
  artifactAccepted: boolean;
  reasonCode?: string;
  scannerVersion: string;
  outputDigest?: `sha256:${string}`;
}

export interface SastCoverageDecision {
  state: SastCoverageState;
  missingRequiredScanners: SastScannerKind[];
  failedRequiredScanners: SastScannerKind[];
  missingRequiredCapabilities: SastCapability[];
  duplicateScanners: SastScannerKind[];
  externalPublicationAllowed: boolean;
  aiAdvisoryAllowed: boolean;
  reasonCodes: string[];
}

export interface SastEvidencePolicy {
  maxTotalBytes: number;
  maxFragmentCount: number;
  maxFragmentBytes: number;
  contextLinesBefore: number;
  contextLinesAfter: number;
  maxRetentionSeconds: number;
  secretRedactionRequired: true;
  fullFileAllowed: false;
  repositoryArchiveAllowed: false;
  reconstructionRiskCheckRequired: true;
  aiSafeClassificationRequired: true;
  dashboardSafeClassificationRequired: true;
}

export interface SastEvidenceFragment {
  normalizedPath: string;
  startLine: number;
  endLine: number;
  sourceFileLineCount: number;
  redactedContent: string;
  byteSize: number;
  contentDigest: `sha256:${string}`;
  secretRedactionApplied: true;
  redactionDecisionRef: string;
  isFullFile: false;
}

export interface SastEvidencePack {
  evidencePackId: string;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  findingFingerprint: `sha256:${string}`;
  policyVersion: string;
  fragments: SastEvidenceFragment[];
  totalBytes: number;
  truncated: boolean;
  suppressedFragmentCount: number;
  reconstructionRiskChecked: true;
  reconstructionRiskDecisionRef: string;
  classificationDecisionRef: string;
  deletionScheduleRef: string;
  dashboardSafe: boolean;
  aiSafe: boolean;
  createdAt: string;
  expiresAt: string;
}

export const DEFAULT_SAST_EVIDENCE_POLICY: SastEvidencePolicy = {
  maxTotalBytes: 32768,
  maxFragmentCount: 5,
  maxFragmentBytes: 8192,
  contextLinesBefore: 5,
  contextLinesAfter: 5,
  maxRetentionSeconds: 604800,
  secretRedactionRequired: true,
  fullFileAllowed: false,
  repositoryArchiveAllowed: false,
  reconstructionRiskCheckRequired: true,
  aiSafeClassificationRequired: true,
  dashboardSafeClassificationRequired: true
};

export interface SastZeroToleranceCounts {
  crossTenantLeakCount: number;
  secretLeakCount: number;
  sandboxEscapeCount: number;
  staleExternalPublicationCount: number;
  unauthorizedEgressCount: number;
  missingDestructionEvidenceCount: number;
  evidencePolicyViolationCount: number;
  unsignedArtifactExecutionCount: number;
}

export interface SastCommonQualityRates {
  falsePositiveIncrease: number;
  scannerFailureRate: number;
}

export interface SastVerificationPassRates {
  normalizationDeterminismPassRate: number;
  artifactBindingPassRate: number;
  fingerprintFixturePassRate: number;
  coverageDecisionFixturePassRate: number;
  retentionExpiryPassRate: number;
}

export interface RuleBundlePromotionEvidence
  extends SastZeroToleranceCounts,
    SastCommonQualityRates,
    SastVerificationPassRates {
  bundle: RuleBundleDescriptor;
  signedArtifactVerified: boolean;
  provenanceVerified: boolean;
  goldenCorpusPassRate: number;
  mustDetectRecall: number;
  criticalHighPrecision: number;
  priorMustDetectRegressionRecall: number;
  maliciousCorpusPassRate: number;
  parserRejectRate: number;
  p95LatencyIncrease: number;
  affectedProfilePositiveCaseCount: number;
  affectedProfileNegativeCaseCount: number;
  observedChangedRulePositiveCaseCount: number;
  observedChangedRuleNegativeCaseCount: number;
  criticalHighRuleChanged: boolean;
  observedChangedCriticalHighRulePositiveCaseCount: number;
  observedChangedCriticalHighRuleNegativeCaseCount: number;
  performanceRunsPerProfileSizeBucket: number;
  securityApprovalRef: string;
  platformApprovalRef: string;
  rollbackRef: string;
}

export interface RuleBundleCanaryEvidence
  extends SastZeroToleranceCounts,
    SastCommonQualityRates {
  bundle: RuleBundleDescriptor;
  eligibleCompletedScans: number;
  observationHours: number;
  finalStep: boolean;
  p95LatencyIncrease: number;
  unexplainedCriticalHighVolumeChange: number;
  telemetryComplete: boolean;
  securityApprovalRef: string;
  platformApprovalRef: string;
  rollbackRef: string;
}

export const SAST_KILL_SWITCH_SCOPES = [
  'SCANNER_VERSION',
  'RULE_BUNDLE',
  'SEMANTIC_RULE',
  'TENANT',
  'REPOSITORY_BINDING',
  'CAPABILITY',
  'PROFILE',
  'EXTERNAL_PUBLICATION',
  'GLOBAL'
] as const;
export type SastKillSwitchScope = (typeof SAST_KILL_SWITCH_SCOPES)[number];

export interface SastKillSwitchDecision {
  killSwitchId: string;
  scope: SastKillSwitchScope;
  target: string;
  active: boolean;
  reasonCode: string;
  incidentRef: string;
  actorRef: string;
  activatedAt: string;
  reviewBy: string;
  signatureRef: string;
  rollbackRef: string;
}

export interface TenantSastRulePolicy {
  tenantId: string;
  policyId: string;
  version: string;
  enabledSemanticRuleIds: string[];
  disabledSemanticRuleIds: string[];
  pathPatternDialect: 'GITIGNORE_SUBSET_V1';
  excludedPathPatterns: string[];
  mandatoryRuleWaiverRefs: string[];
  customerExecutableConfigAllowed: false;
  approvedByRef: string;
  createdAt: string;
}

export interface SastQualityMeasurements
  extends SastZeroToleranceCounts,
    SastCommonQualityRates,
    SastVerificationPassRates {
  eligibleCompletedScans: number;
  observationHours: number;
  performanceRunsPerProfileSizeBucket: number;
  goldenCorpusPassRate: number;
  criticalHighPrecision: number;
  mustDetectRecall: number;
  priorMustDetectRegressionRecall: number;
  maliciousCorpusPassRate: number;
  parserRejectRate: number;
  fastLaneP95Milliseconds: number;
  deepLaneP95Milliseconds: number;
}

export interface SastCleanupEvidence {
  attemptId: string;
  credentialRevokedAndWiped: true;
  scannerProcessesTerminated: true;
  writableVolumesDestroyed: true;
  microVmTerminated: true;
  resultIngressClosed: true;
  cleanupEvidenceRef: string;
  finalAuditEventRef: string;
  completedAt: string;
}

export interface SastFailureDecision {
  failureClass: SastFailureClass;
  retryAllowed: boolean;
  maxAttempts: number;
  quarantineRequired: boolean;
  externalPublicationAllowed: false;
  hardenedIsolationRequired: boolean;
  reasonCode: string;
}

export function isSignedSastArtifactDescriptorValid(
  artifact: SignedSastArtifactDescriptor
): boolean {
  return (
    isSha256Digest(artifact.digest) &&
    isNonBlank(artifact.signatureRef) &&
    isNonBlank(artifact.provenanceRef)
  );
}

export function isRuleBundleDescriptorValid(bundle: RuleBundleDescriptor): boolean {
  return (
    isNonBlank(bundle.bundleId) &&
    isNonBlank(bundle.version) &&
    RULE_BUNDLE_STATES.includes(bundle.state) &&
    (bundle.scanner === 'OPENGREP' || bundle.scanner === 'TRIVY') &&
    bundle.source === 'PLATFORM_MANAGED' &&
    bundle.immutable === true &&
    bundle.customerExecutableConfigAllowed === false &&
    isSha256Digest(bundle.digest) &&
    isNonBlank(bundle.signatureRef) &&
    isNonBlank(bundle.provenanceRef) &&
    isNonBlank(bundle.compatibilityRef) &&
    isNonBlank(bundle.rolloutPolicyRef) &&
    isNonBlank(bundle.killSwitchRef)
  );
}

export function isScannerSetDescriptorValid(scannerSet: ScannerSetDescriptor): boolean {
  const scannerDescriptors = SAST_SCANNER_KINDS.map((scanner) => scannerSet.scanners[scanner]);
  const ruleBundleIds = scannerSet.ruleBundles.map((bundle) => bundle.bundleId);
  const ruleBundleDigests = scannerSet.ruleBundles.map((bundle) => bundle.digest);
  const executableRuleStates: RuleBundleState[] = ['CANARY', 'ACTIVE'];

  return (
    isNonBlank(scannerSet.scannerSetVersion) &&
    isSha256Digest(scannerSet.scannerSetDigest) &&
    isNonBlank(scannerSet.signatureRef) &&
    isNonBlank(scannerSet.provenanceRef) &&
    scannerDescriptors.every(
      (descriptor, index) =>
        descriptor !== undefined &&
        descriptor.scanner === SAST_SCANNER_KINDS[index] &&
        isNonBlank(descriptor.version) &&
        isNonBlank(descriptor.sbomRef) &&
        isSignedSastArtifactDescriptorValid(descriptor) &&
        isSignedSastArtifactDescriptorValid(descriptor.wrapper)
    ) &&
    scannerSet.ruleBundles.length >= 2 &&
    hasUniqueValues(ruleBundleIds) &&
    hasUniqueValues(ruleBundleDigests) &&
    scannerSet.ruleBundles.every(
      (bundle) =>
        isRuleBundleDescriptorValid(bundle) && executableRuleStates.includes(bundle.state)
    ) &&
    scannerSet.ruleBundles.some((bundle) => bundle.scanner === 'OPENGREP') &&
    scannerSet.ruleBundles.some((bundle) => bundle.scanner === 'TRIVY') &&
    isSignedSastArtifactDescriptorValid(scannerSet.vulnerabilityDatabase) &&
    isNonBlank(scannerSet.vulnerabilityDatabase.databaseVersion) &&
    isIsoTimestamp(scannerSet.vulnerabilityDatabase.publishedAt) &&
    isSignedSastArtifactDescriptorValid(scannerSet.schemaBundle) &&
    isSignedSastArtifactDescriptorValid(scannerSet.normalizerBundle) &&
    scannerSet.sbomSchema === 'CYCLONEDX_JSON' &&
    isNonBlank(scannerSet.rollbackRef)
  );
}

export function isSastScanProfileValid(profile: SastScanProfile): boolean {
  if (
    !profile ||
    !SAST_PROFILE_IDS.includes(profile.id) ||
    !hasSameImmutableData(profile, SAST_SCAN_PROFILES[profile.id])
  ) {
    return false;
  }

  const uniqueRequiredScanners = new Set(profile.requiredScanners);
  const scannerOverlap = profile.optionalScanners.some((scanner) => uniqueRequiredScanners.has(scanner));
  const requiredCapabilitiesCovered = profile.requiredCapabilities.every((capability) =>
    profile.requiredScanners.some((scanner) =>
      (SAST_SCANNER_RESPONSIBILITIES[scanner]
        .authoritativeCapabilities as readonly SastCapability[]).includes(capability)
    )
  );
  const everyRequiredScannerContributes = profile.requiredScanners.every((scanner) =>
    profile.requiredCapabilities.some((capability) =>
      (SAST_SCANNER_RESPONSIBILITIES[scanner]
        .authoritativeCapabilities as readonly SastCapability[]).includes(capability)
    )
  );
  const limits = profile.limits;
  const pathPolicy = profile.pathPolicy;
  const laneAndScopeMatch =
    (profile.lane === 'FAST' && profile.scope === 'CHANGED_FILES_WITH_CONTEXT') ||
    (profile.lane === 'DEEP' && profile.scope === 'FULL_REPOSITORY');
  const languageAndIdMatch =
    (profile.language === 'JAVA' && profile.id.startsWith('JAVA_')) ||
    (profile.language === 'COMMON' && profile.id.startsWith('COMMON_'));

  return (
    SAST_PROFILE_IDS.includes(profile.id) &&
    SAST_SCAN_LANES.includes(profile.lane) &&
    profile.requiredScanners.length > 0 &&
    uniqueRequiredScanners.size === profile.requiredScanners.length &&
    hasUniqueValues(profile.optionalScanners) &&
    hasUniqueValues(profile.requiredCapabilities) &&
    hasUniqueValues(profile.sourceExtensions) &&
    hasUniqueValues(profile.manifestNames) &&
    !scannerOverlap &&
    profile.requiredCapabilities.length > 0 &&
    requiredCapabilitiesCovered &&
    everyRequiredScannerContributes &&
    laneAndScopeMatch &&
    languageAndIdMatch &&
    (profile.language !== 'JAVA' || profile.sourceExtensions.includes('.java')) &&
    (profile.language !== 'COMMON' ||
      (profile.sourceExtensions.length === 0 && profile.aiAdvisoryEligible === false)) &&
    profile.sourceExtensions.every(isSafeSourceExtension) &&
    profile.manifestNames.every(isSafeManifestName) &&
    profile.customerBuildAllowed === false &&
    profile.packageInstallAllowed === false &&
    profile.dynamicExecutionAllowed === false &&
    profile.networkEnrichmentAllowed === false &&
    Object.values(limits).every(isSafePositiveInteger) &&
    limits.maxSelectedBytes <= limits.maxRepositoryBytes &&
    limits.maxPathDepth <= 64 &&
    limits.maxFindings <= 25000 &&
    limits.maxArtifactBytes <= 268435456 &&
    limits.maxArtifactRecords <= 250000 &&
    limits.maxStdoutStderrBytes <= 1048576 &&
    limits.wallClockTimeoutSeconds <= (profile.lane === 'FAST' ? 900 : 3600) &&
    pathPolicy.pathNormalizationRequired === true &&
    pathPolicy.rejectAbsolutePaths === true &&
    pathPolicy.rejectParentTraversal === true &&
    pathPolicy.rejectCaseFoldCollisions === true &&
    pathPolicy.symlinkPolicy === 'REJECT_OUTSIDE_ROOT' &&
    pathPolicy.submodulePolicy === 'DISABLED_BY_DEFAULT' &&
    pathPolicy.lfsPolicy === 'POINTER_METADATA_ONLY_BY_DEFAULT' &&
    pathPolicy.archivePolicy === 'DO_NOT_EXPAND' &&
    pathPolicy.generatedCodePolicy === 'INDEX_BUT_SUPPRESS_BY_DEFAULT' &&
    pathPolicy.vendorCodePolicy === 'DEPENDENCY_ONLY_BY_DEFAULT' &&
    pathPolicy.fixturePolicy === 'SCAN_WITH_NON_BLOCKING_DEFAULT'
  );
}

export function isSastScanPlanValid(plan: SastScanPlan): boolean {
  if (
    !plan ||
    typeof plan !== 'object' ||
    !plan.profile ||
    !plan.repositoryState ||
    !plan.scannerSet ||
    !Array.isArray(plan.forbiddenCapabilities)
  ) {
    return false;
  }

  try {
    return (
      isNonBlank(plan.tenantId) &&
      isNonBlank(plan.scanRequestId) &&
      isSha256Digest(plan.canonicalScanKey) &&
      isSastScanProfileValid(plan.profile) &&
      isSha256Digest(plan.profileDigest) &&
      plan.profileDigest === SAST_APPROVED_PROFILE_DIGESTS[plan.profile.id] &&
      isNonBlank(plan.policyVersion) &&
      isNonBlank(plan.repositoryState.repositoryBindingId) &&
      isGitCommitSha(plan.repositoryState.fixedCommitSha) &&
      isNonBlank(plan.repositoryState.targetRef) &&
      isSha256Digest(plan.repositoryState.inventoryDigest) &&
      isNonBlank(plan.repositoryState.attestationRef) &&
      plan.repositoryState.shallowFetchPreferred === true &&
      plan.repositoryState.submodulesEnabled === false &&
      plan.repositoryState.lfsObjectsFetched === false &&
      isScannerSetDescriptorValid(plan.scannerSet) &&
      (plan.isolationClass === 'HARDENED' || plan.isolationClass === 'RESTRICTED') &&
      isNonBlank(plan.resultIngressRef) &&
      isNonBlank(plan.evidenceOutputRef) &&
      isNonBlank(plan.auditSinkRef) &&
      isIsoTimestamp(plan.createdAt) &&
      doesSastPlanRespectForbiddenCapabilities(plan)
    );
  } catch {
    return false;
  }
}

export function doesSastPlanRespectForbiddenCapabilities(plan: SastScanPlan): boolean {
  return (
    hasUniqueValues(plan.forbiddenCapabilities) &&
    plan.forbiddenCapabilities.length === SAST_FORBIDDEN_CAPABILITIES.length &&
    SAST_FORBIDDEN_CAPABILITIES.every((capability) =>
      plan.forbiddenCapabilities.includes(capability)
    )
  );
}

export function isScannerArtifactEnvelopeBoundToPlan(
  envelope: ScannerArtifactEnvelope,
  plan: SastScanPlan,
  expectedBinding: ExpectedScannerArtifactBinding
): boolean {
  if (
    !envelope ||
    !isScannerArtifactEnvelopeShapeValid(envelope) ||
    !plan ||
    !expectedBinding ||
    !SAST_SCANNER_KINDS.includes(envelope.scanner as SastScannerKind) ||
    !isNonBlank(expectedBinding.attemptId) ||
    !isNonBlank(expectedBinding.scannerRunId) ||
    !SAST_SCANNER_KINDS.includes(expectedBinding.scanner) ||
    !isNonBlank(expectedBinding.artifactRef) ||
    !isNonBlank(expectedBinding.workloadIdentityRef) ||
    !isNonBlank(expectedBinding.preflightAttestationRef) ||
    !isSha256Digest(expectedBinding.preflightInventoryDigest) ||
    !isSastScanPlanValid(plan)
  ) {
    return false;
  }

  const scanner = plan.scannerSet.scanners[envelope.scanner];
  const expectedSchema = SAST_SCANNER_RESPONSIBILITIES[envelope.scanner].outputSchema;
  const expectedRuleBundle = plan.scannerSet.ruleBundles.find(
    (bundle) => bundle.scanner === envelope.scanner
  );
  const scannerSelectedByProfile =
    plan.profile.requiredScanners.includes(envelope.scanner) ||
    plan.profile.optionalScanners.includes(envelope.scanner);

  return (
    envelope.tenantId === plan.tenantId &&
    envelope.repositoryBindingId === plan.repositoryState.repositoryBindingId &&
    envelope.scanRequestId === plan.scanRequestId &&
    envelope.attemptId === expectedBinding.attemptId &&
    envelope.scannerRunId === expectedBinding.scannerRunId &&
    envelope.scanner === expectedBinding.scanner &&
    envelope.artifactRef === expectedBinding.artifactRef &&
    envelope.artifactRef ===
      `${plan.resultIngressRef}/${envelope.scanner.toLowerCase()}` &&
    envelope.workloadIdentityRef === expectedBinding.workloadIdentityRef &&
    envelope.preflightAttestationRef === expectedBinding.preflightAttestationRef &&
    envelope.preflightInventoryDigest === expectedBinding.preflightInventoryDigest &&
    envelope.scannerWorkspaceInventoryDigest === expectedBinding.preflightInventoryDigest &&
    scannerSelectedByProfile &&
    envelope.scannerVersion === scanner.version &&
    envelope.scannerImageDigest === scanner.digest &&
    envelope.wrapperDigest === scanner.wrapper.digest &&
    envelope.scannerSetDigest === plan.scannerSet.scannerSetDigest &&
    envelope.schemaBundleDigest === plan.scannerSet.schemaBundle.digest &&
    envelope.normalizerBundleDigest === plan.scannerSet.normalizerBundle.digest &&
    envelope.profileId === plan.profile.id &&
    envelope.profileDigest === plan.profileDigest &&
    envelope.inputCommitSha === plan.repositoryState.fixedCommitSha &&
    envelope.artifactSchema === expectedSchema &&
    envelope.artifactSchemaVersion ===
      SAST_ARTIFACT_SCHEMA_VERSIONS[expectedSchema] &&
    isNonBlank(envelope.artifactRef) &&
    isSha256Digest(envelope.contentDigest) &&
    Number.isSafeInteger(envelope.byteSize) &&
    envelope.byteSize > 0 &&
    envelope.byteSize <= plan.profile.limits.maxArtifactBytes &&
    Number.isSafeInteger(envelope.recordCount) &&
    envelope.recordCount >= 0 &&
    envelope.recordCount <=
      (envelope.artifactSchema === 'CYCLONEDX_JSON'
        ? plan.profile.limits.maxArtifactRecords
        : Math.min(
            plan.profile.limits.maxArtifactRecords,
            plan.profile.limits.maxFindings
          )) &&
    Number.isSafeInteger(envelope.exitCode) &&
    SCANNER_EXECUTION_STATUSES.includes(envelope.executionStatus) &&
    isIsoTimestamp(envelope.producedAt) &&
    (envelope.scanner === 'SYFT'
      ? envelope.ruleBundleDigest === undefined &&
        envelope.vulnerabilityDatabaseDigest === undefined
      : envelope.ruleBundleDigest === expectedRuleBundle?.digest &&
        (envelope.scanner === 'TRIVY'
          ? envelope.vulnerabilityDatabaseDigest ===
            plan.scannerSet.vulnerabilityDatabase.digest
          : envelope.vulnerabilityDatabaseDigest === undefined))
  );
}

export function isScannerArtifactEnvelopeShapeValid(
  value: unknown
): value is ScannerArtifactEnvelope {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const envelope = value as Record<string, unknown>;
  const requiredKeys = [
    'tenantId',
    'repositoryBindingId',
    'scanRequestId',
    'attemptId',
    'scannerRunId',
    'workloadIdentityRef',
    'scanner',
    'scannerVersion',
    'scannerImageDigest',
    'wrapperDigest',
    'scannerSetDigest',
    'schemaBundleDigest',
    'normalizerBundleDigest',
    'profileId',
    'profileDigest',
    'preflightAttestationRef',
    'preflightInventoryDigest',
    'scannerWorkspaceInventoryDigest',
    'inputCommitSha',
    'artifactSchema',
    'artifactSchemaVersion',
    'artifactRef',
    'contentDigest',
    'byteSize',
    'recordCount',
    'truncated',
    'exitCode',
    'executionStatus',
    'producedAt'
  ] as const;
  const optionalKeys = [
    'ruleBundleDigest',
    'vulnerabilityDatabaseDigest'
  ] as const;
  const actualKeys = Object.keys(envelope);
  if (
    requiredKeys.some((key) => !Object.hasOwn(envelope, key)) ||
    actualKeys.some(
      (key) =>
        !(requiredKeys as readonly string[]).includes(key) &&
        !(optionalKeys as readonly string[]).includes(key)
    )
  ) {
    return false;
  }

  return (
    isBoundedIngressText(envelope.tenantId, 256) &&
    isBoundedIngressText(envelope.repositoryBindingId, 256) &&
    isBoundedIngressText(envelope.scanRequestId, 256) &&
    isBoundedIngressText(envelope.attemptId, 256) &&
    isBoundedIngressText(envelope.scannerRunId, 256) &&
    isBoundedIngressText(envelope.workloadIdentityRef, 512) &&
    SAST_SCANNER_KINDS.includes(envelope.scanner as SastScannerKind) &&
    isBoundedIngressText(envelope.scannerVersion, 255) &&
    isSha256Digest(envelope.scannerImageDigest as string) &&
    isSha256Digest(envelope.wrapperDigest as string) &&
    (envelope.ruleBundleDigest === undefined ||
      isSha256Digest(envelope.ruleBundleDigest as string)) &&
    (envelope.vulnerabilityDatabaseDigest === undefined ||
      isSha256Digest(envelope.vulnerabilityDatabaseDigest as string)) &&
    isSha256Digest(envelope.scannerSetDigest as string) &&
    isSha256Digest(envelope.schemaBundleDigest as string) &&
    isSha256Digest(envelope.normalizerBundleDigest as string) &&
    SAST_PROFILE_IDS.includes(envelope.profileId as SastProfileId) &&
    isSha256Digest(envelope.profileDigest as string) &&
    isBoundedIngressText(envelope.preflightAttestationRef, 8192) &&
    isSha256Digest(envelope.preflightInventoryDigest as string) &&
    isSha256Digest(envelope.scannerWorkspaceInventoryDigest as string) &&
    typeof envelope.inputCommitSha === 'string' &&
    isGitCommitSha(envelope.inputCommitSha) &&
    SAST_ARTIFACT_SCHEMAS.includes(
      envelope.artifactSchema as SastArtifactSchema
    ) &&
    isBoundedIngressText(envelope.artifactSchemaVersion, 255) &&
    isBoundedIngressText(envelope.artifactRef, 2048) &&
    isSha256Digest(envelope.contentDigest as string) &&
    typeof envelope.byteSize === 'number' &&
    Number.isSafeInteger(envelope.byteSize) &&
    envelope.byteSize > 0 &&
    envelope.byteSize <= 268435456 &&
    typeof envelope.recordCount === 'number' &&
    Number.isSafeInteger(envelope.recordCount) &&
    envelope.recordCount >= 0 &&
    envelope.recordCount <= 250000 &&
    typeof envelope.truncated === 'boolean' &&
    typeof envelope.exitCode === 'number' &&
    Number.isSafeInteger(envelope.exitCode) &&
    envelope.exitCode >= -1 &&
    envelope.exitCode <= 255 &&
    SCANNER_EXECUTION_STATUSES.includes(
      envelope.executionStatus as ScannerExecutionStatus
    ) &&
    typeof envelope.producedAt === 'string' &&
    isIsoTimestamp(envelope.producedAt)
  );
}

export function canonicalizeScannerArtifactEnvelope(
  envelope: ScannerArtifactEnvelope
): string {
  const canonicalEnvelope = {
    tenantId: envelope.tenantId,
    repositoryBindingId: envelope.repositoryBindingId,
    scanRequestId: envelope.scanRequestId,
    attemptId: envelope.attemptId,
    scannerRunId: envelope.scannerRunId,
    workloadIdentityRef: envelope.workloadIdentityRef,
    scanner: envelope.scanner,
    scannerVersion: envelope.scannerVersion,
    scannerImageDigest: envelope.scannerImageDigest,
    wrapperDigest: envelope.wrapperDigest,
    ...(envelope.ruleBundleDigest === undefined
      ? {}
      : { ruleBundleDigest: envelope.ruleBundleDigest }),
    ...(envelope.vulnerabilityDatabaseDigest === undefined
      ? {}
      : {
          vulnerabilityDatabaseDigest:
            envelope.vulnerabilityDatabaseDigest
        }),
    scannerSetDigest: envelope.scannerSetDigest,
    schemaBundleDigest: envelope.schemaBundleDigest,
    normalizerBundleDigest: envelope.normalizerBundleDigest,
    profileId: envelope.profileId,
    profileDigest: envelope.profileDigest,
    preflightAttestationRef: envelope.preflightAttestationRef,
    preflightInventoryDigest: envelope.preflightInventoryDigest,
    scannerWorkspaceInventoryDigest:
      envelope.scannerWorkspaceInventoryDigest,
    inputCommitSha: envelope.inputCommitSha,
    artifactSchema: envelope.artifactSchema,
    artifactSchemaVersion: envelope.artifactSchemaVersion,
    artifactRef: envelope.artifactRef,
    contentDigest: envelope.contentDigest,
    byteSize: envelope.byteSize,
    recordCount: envelope.recordCount,
    truncated: envelope.truncated,
    exitCode: envelope.exitCode,
    executionStatus: envelope.executionStatus,
    producedAt: envelope.producedAt
  };

  return JSON.stringify(canonicalEnvelope);
}

export function buildSastArtifactIngressIdempotencyKey(
  envelope: Pick<ScannerArtifactEnvelope, 'scannerRunId' | 'contentDigest'>
): string {
  return `sast-ingress-v1:${envelope.scannerRunId}:${envelope.contentDigest}`;
}

export function isScannerArtifactEligibleForNormalization(
  envelope: ScannerArtifactEnvelope,
  plan: SastScanPlan,
  expectedBinding: ExpectedScannerArtifactBinding
): boolean {
  return (
    isScannerArtifactEnvelopeBoundToPlan(envelope, plan, expectedBinding) &&
    envelope.executionStatus === 'SUCCEEDED' &&
    envelope.exitCode === 0 &&
    envelope.truncated === false &&
    envelope.byteSize > 0
  );
}

export function buildFindingFingerprintPreimage(input: FindingFingerprintInput): string {
  const fields = [
    input.repositoryBindingId,
    input.capability,
    input.ruleSemanticId,
    input.normalizedPath,
    input.symbolAnchor,
    input.sinkKind,
    input.structuralHash
  ];

  return `sast-fingerprint-v1\0${fields.map(encodeFingerprintField).join('')}`;
}

export function isSastFindingLocationValid(
  location: SastFindingLocation,
  fileMetadata?: SastFileCoordinateMetadata
): boolean {
  if (!location || typeof location !== 'object') return false;

  if (location.kind === 'UNKNOWN') {
    const unknown = location as SastUnknownFindingLocation & Record<string, unknown>;
    return (
      SAST_UNKNOWN_LOCATION_REASONS.includes(unknown.reasonCode) &&
      isOptionalBoundedText(unknown.symbol, 512) &&
      !('normalizedPath' in unknown) &&
      !('lineStart' in unknown) &&
      !('lineEnd' in unknown) &&
      !('columnStart' in unknown) &&
      !('columnEnd' in unknown)
    );
  }

  if (
    location.kind !== 'FILE' ||
    fileMetadata === undefined ||
    fileMetadata === null ||
    !Array.isArray(fileMetadata.maxColumnByLine) ||
    typeof location.normalizedPath !== 'string' ||
    typeof fileMetadata.normalizedPath !== 'string'
  ) {
    return false;
  }

  const lineEnd = location.lineEnd ?? location.lineStart;
  const metadataValid =
    isSafeNormalizedRelativePath(fileMetadata.normalizedPath) &&
    Number.isSafeInteger(fileMetadata.lineCount) &&
    fileMetadata.lineCount > 0 &&
    fileMetadata.lineCount <= SAST_MAX_COORDINATE_VALUE &&
    fileMetadata.maxColumnByLine.length === fileMetadata.lineCount &&
    fileMetadata.maxColumnByLine.every(isSafeCoordinateValue);
  if (!metadataValid || location.normalizedPath !== fileMetadata.normalizedPath) return false;

  const linesValid =
    isSafeCoordinateValue(location.lineStart) &&
    isSafeCoordinateValue(lineEnd) &&
    lineEnd >= location.lineStart &&
    lineEnd <= fileMetadata.lineCount;
  if (!linesValid) return false;

  const columnStartValid =
    location.columnStart === undefined ||
    (isSafeCoordinateValue(location.columnStart) &&
      location.columnStart <= fileMetadata.maxColumnByLine[location.lineStart - 1]);
  const columnEndValid =
    location.columnEnd === undefined ||
    (location.columnStart !== undefined &&
      isSafeCoordinateValue(location.columnEnd) &&
      location.columnEnd <= fileMetadata.maxColumnByLine[lineEnd - 1] &&
      (lineEnd !== location.lineStart || location.columnEnd >= location.columnStart));

  return (
    isSafeNormalizedRelativePath(location.normalizedPath) &&
    isOptionalBoundedText(location.symbol, 512) &&
    columnStartValid &&
    columnEndValid
  );
}

export function evaluateSastCoverage(input: {
  profile: SastScanProfile;
  records: ScannerCoverageRecord[];
  stale: boolean;
  securityBlocked: boolean;
}): SastCoverageDecision {
  const recordsByScanner = new Map<SastScannerKind, ScannerCoverageRecord>();
  const duplicateScanners = new Set<SastScannerKind>();
  for (const record of input.records) {
    if (recordsByScanner.has(record.scanner)) duplicateScanners.add(record.scanner);
    recordsByScanner.set(record.scanner, record);
  }

  const missingRequiredScanners = input.profile.requiredScanners.filter(
    (scanner) => !recordsByScanner.has(scanner)
  );
  const failedRequiredScanners = input.profile.requiredScanners.filter((scanner) => {
    const record = recordsByScanner.get(scanner);
    return (
      record !== undefined &&
      (record.status !== 'SUCCEEDED' ||
        record.required !== true ||
        record.artifactAccepted !== true ||
        !isNonBlank(record.scannerVersion) ||
        record.outputDigest === undefined ||
        !isSha256Digest(record.outputDigest))
    );
  });
  const satisfiedCapabilities = new Set<SastCapability>();
  for (const scanner of input.profile.requiredScanners) {
    const record = recordsByScanner.get(scanner);
    if (
      record?.status === 'SUCCEEDED' &&
      record.required === true &&
      record.artifactAccepted === true &&
      record.outputDigest !== undefined &&
      isSha256Digest(record.outputDigest)
    ) {
      const authoritativeCapabilities = SAST_SCANNER_RESPONSIBILITIES[scanner]
        .authoritativeCapabilities as readonly SastCapability[];
      for (const capability of record.capabilities) {
        if (authoritativeCapabilities.includes(capability)) satisfiedCapabilities.add(capability);
      }
    }
  }
  const missingRequiredCapabilities = input.profile.requiredCapabilities.filter(
    (capability) => !satisfiedCapabilities.has(capability)
  );
  const hasCapabilityContractFailure = input.records.some((record) => {
    const authoritativeCapabilities = SAST_SCANNER_RESPONSIBILITIES[record.scanner]
      .authoritativeCapabilities as readonly SastCapability[];
    return (
      !hasUniqueValues(record.capabilities) ||
      record.capabilities.some((capability) => !authoritativeCapabilities.includes(capability))
    );
  });
  const hasArtifactIntegrityFailure = input.profile.requiredScanners.some((scanner) => {
    const record = recordsByScanner.get(scanner);
    return record?.status === 'SUCCEEDED' && record.artifactAccepted !== true;
  });
  const hasSecurityFailure =
    input.securityBlocked ||
    duplicateScanners.size > 0 ||
    hasCapabilityContractFailure ||
    hasArtifactIntegrityFailure ||
    input.records.some((record) => record.status === 'QUARANTINED' || record.status === 'KILLED');
  const hasPendingRequiredScanner = failedRequiredScanners.some((scanner) => {
    const status = recordsByScanner.get(scanner)?.status;
    return status === 'PENDING' || status === 'RUNNING';
  });

  let state: SastCoverageState;
  if (hasSecurityFailure) {
    state = 'FAILED';
  } else if (missingRequiredScanners.length > 0) {
    state = 'PARTIAL';
  } else if (hasPendingRequiredScanner) {
    state = 'PENDING';
  } else if (failedRequiredScanners.length > 0 || missingRequiredCapabilities.length > 0) {
    state = 'PARTIAL';
  } else {
    state = 'COMPLETE';
  }

  const reasonCodes: string[] = [];
  if (missingRequiredScanners.length > 0) reasonCodes.push('REQUIRED_SCANNER_MISSING');
  if (failedRequiredScanners.length > 0) reasonCodes.push('REQUIRED_SCANNER_INCOMPLETE');
  if (missingRequiredCapabilities.length > 0) reasonCodes.push('REQUIRED_CAPABILITY_MISSING');
  if (duplicateScanners.size > 0) reasonCodes.push('DUPLICATE_SCANNER_RECORD');
  if (hasArtifactIntegrityFailure) reasonCodes.push('ARTIFACT_NOT_ACCEPTED');
  if (hasCapabilityContractFailure) reasonCodes.push('SCANNER_CAPABILITY_MISMATCH');
  if (hasSecurityFailure) reasonCodes.push('SECURITY_BLOCKED');
  if (input.stale) reasonCodes.push('STALE_SCAN');

  const externalPublicationAllowed = state === 'COMPLETE' && !input.stale && !hasSecurityFailure;

  return {
    state,
    missingRequiredScanners,
    failedRequiredScanners,
    missingRequiredCapabilities,
    duplicateScanners: [...duplicateScanners],
    externalPublicationAllowed,
    aiAdvisoryAllowed: externalPublicationAllowed && input.profile.aiAdvisoryEligible,
    reasonCodes
  };
}

export function isSastEvidencePolicySafe(policy: SastEvidencePolicy): boolean {
  return (
    policy.maxTotalBytes > 0 &&
    policy.maxTotalBytes <= 32768 &&
    policy.maxFragmentCount > 0 &&
    policy.maxFragmentCount <= 5 &&
    policy.maxFragmentBytes > 0 &&
    policy.maxFragmentBytes <= 8192 &&
    policy.contextLinesBefore >= 0 &&
    policy.contextLinesBefore <= 5 &&
    policy.contextLinesAfter >= 0 &&
    policy.contextLinesAfter <= 5 &&
    policy.maxRetentionSeconds > 0 &&
    policy.maxRetentionSeconds <= 604800 &&
    policy.secretRedactionRequired === true &&
    policy.fullFileAllowed === false &&
    policy.repositoryArchiveAllowed === false &&
    policy.reconstructionRiskCheckRequired === true &&
    policy.aiSafeClassificationRequired === true &&
    policy.dashboardSafeClassificationRequired === true
  );
}

export function isSastEvidencePackSafe(
  pack: SastEvidencePack,
  policy: SastEvidencePolicy
): boolean {
  const createdAt = Date.parse(pack.createdAt);
  const expiresAt = Date.parse(pack.expiresAt);
  const fragmentBytes = pack.fragments.reduce((total, fragment) => total + fragment.byteSize, 0);

  return (
    isSastEvidencePolicySafe(policy) &&
    isNonBlank(pack.evidencePackId) &&
    isNonBlank(pack.tenantId) &&
    isNonBlank(pack.repositoryBindingId) &&
    isNonBlank(pack.scanRequestId) &&
    isSha256Digest(pack.findingFingerprint) &&
    isNonBlank(pack.policyVersion) &&
    pack.fragments.length > 0 &&
    pack.fragments.length <= policy.maxFragmentCount &&
    hasUniqueValues(pack.fragments.map((fragment) => fragment.contentDigest)) &&
    pack.fragments.every(
      (fragment) =>
        isSafeNormalizedRelativePath(fragment.normalizedPath) &&
        Number.isSafeInteger(fragment.startLine) &&
        Number.isSafeInteger(fragment.endLine) &&
        Number.isSafeInteger(fragment.sourceFileLineCount) &&
        fragment.startLine > 0 &&
        fragment.endLine >= fragment.startLine &&
        fragment.sourceFileLineCount >= fragment.endLine &&
        !(fragment.startLine === 1 && fragment.endLine === fragment.sourceFileLineCount) &&
        Number.isSafeInteger(fragment.byteSize) &&
        fragment.byteSize > 0 &&
        fragment.byteSize <= policy.maxFragmentBytes &&
        new TextEncoder().encode(fragment.redactedContent).byteLength === fragment.byteSize &&
        isSha256Digest(fragment.contentDigest) &&
        fragment.secretRedactionApplied === true &&
        isNonBlank(fragment.redactionDecisionRef) &&
        fragment.isFullFile === false
    ) &&
    Number.isSafeInteger(pack.totalBytes) &&
    pack.totalBytes === fragmentBytes &&
    pack.totalBytes <= policy.maxTotalBytes &&
    Number.isSafeInteger(pack.suppressedFragmentCount) &&
    pack.suppressedFragmentCount >= 0 &&
    pack.reconstructionRiskChecked === true &&
    isNonBlank(pack.reconstructionRiskDecisionRef) &&
    isNonBlank(pack.classificationDecisionRef) &&
    isNonBlank(pack.deletionScheduleRef) &&
    typeof pack.dashboardSafe === 'boolean' &&
    typeof pack.aiSafe === 'boolean' &&
    Number.isFinite(createdAt) &&
    Number.isFinite(expiresAt) &&
    expiresAt > createdAt &&
    expiresAt - createdAt <= policy.maxRetentionSeconds * 1000
  );
}

export function isRuleBundlePromotionReady(evidence: RuleBundlePromotionEvidence): boolean {
  const changedCriticalHighRuleSampleReady =
    !evidence.criticalHighRuleChanged ||
    (isSafeIntegerAtLeast(evidence.observedChangedCriticalHighRulePositiveCaseCount, 20) &&
      isSafeIntegerAtLeast(evidence.observedChangedCriticalHighRuleNegativeCaseCount, 20));

  return (
    isRuleBundleDescriptorValid(evidence.bundle) &&
    evidence.bundle.state === 'VALIDATED' &&
    evidence.signedArtifactVerified &&
    evidence.provenanceVerified &&
    evidence.goldenCorpusPassRate === 1 &&
    isRate(evidence.mustDetectRecall) &&
    evidence.mustDetectRecall >= 0.95 &&
    isRate(evidence.criticalHighPrecision) &&
    evidence.criticalHighPrecision >= 0.9 &&
    evidence.priorMustDetectRegressionRecall === 1 &&
    evidence.maliciousCorpusPassRate === 1 &&
    evidence.parserRejectRate === 1 &&
    isRelativeDelta(evidence.falsePositiveIncrease) &&
    evidence.falsePositiveIncrease <= 0.02 &&
    isRate(evidence.scannerFailureRate) &&
    evidence.scannerFailureRate <= 0.02 &&
    isRelativeDelta(evidence.p95LatencyIncrease) &&
    evidence.p95LatencyIncrease <= 0.2 &&
    isSafeIntegerAtLeast(evidence.affectedProfilePositiveCaseCount, 200) &&
    isSafeIntegerAtLeast(evidence.affectedProfileNegativeCaseCount, 200) &&
    isSafeIntegerAtLeast(evidence.observedChangedRulePositiveCaseCount, 10) &&
    isSafeIntegerAtLeast(evidence.observedChangedRuleNegativeCaseCount, 10) &&
    changedCriticalHighRuleSampleReady &&
    isSafeIntegerAtLeast(evidence.performanceRunsPerProfileSizeBucket, 30) &&
    evidence.normalizationDeterminismPassRate === 1 &&
    evidence.artifactBindingPassRate === 1 &&
    evidence.fingerprintFixturePassRate === 1 &&
    evidence.coverageDecisionFixturePassRate === 1 &&
    evidence.retentionExpiryPassRate === 1 &&
    evidence.crossTenantLeakCount === 0 &&
    evidence.secretLeakCount === 0 &&
    evidence.sandboxEscapeCount === 0 &&
    evidence.staleExternalPublicationCount === 0 &&
    evidence.unauthorizedEgressCount === 0 &&
    evidence.missingDestructionEvidenceCount === 0 &&
    evidence.evidencePolicyViolationCount === 0 &&
    evidence.unsignedArtifactExecutionCount === 0 &&
    isNonBlank(evidence.securityApprovalRef) &&
    isNonBlank(evidence.platformApprovalRef) &&
    evidence.securityApprovalRef !== evidence.platformApprovalRef &&
    isNonBlank(evidence.rollbackRef)
  );
}

export function isRuleBundleCanaryHealthy(evidence: RuleBundleCanaryEvidence): boolean {
  const minimumScans = evidence.finalStep ? 1000 : 200;
  const minimumHours = evidence.finalStep ? 48 : 24;

  return (
    isRuleBundleDescriptorValid(evidence.bundle) &&
    evidence.bundle.state === 'CANARY' &&
    isSafeIntegerAtLeast(evidence.eligibleCompletedScans, minimumScans) &&
    Number.isFinite(evidence.observationHours) &&
    evidence.observationHours >= minimumHours &&
    isRelativeDelta(evidence.falsePositiveIncrease) &&
    evidence.falsePositiveIncrease <= 0.02 &&
    isRate(evidence.scannerFailureRate) &&
    evidence.scannerFailureRate <= 0.02 &&
    isRelativeDelta(evidence.p95LatencyIncrease) &&
    evidence.p95LatencyIncrease <= 0.2 &&
    Number.isFinite(evidence.unexplainedCriticalHighVolumeChange) &&
    Math.abs(evidence.unexplainedCriticalHighVolumeChange) <= 0.2 &&
    evidence.telemetryComplete === true &&
    evidence.crossTenantLeakCount === 0 &&
    evidence.secretLeakCount === 0 &&
    evidence.sandboxEscapeCount === 0 &&
    evidence.staleExternalPublicationCount === 0 &&
    evidence.unauthorizedEgressCount === 0 &&
    evidence.missingDestructionEvidenceCount === 0 &&
    evidence.evidencePolicyViolationCount === 0 &&
    evidence.unsignedArtifactExecutionCount === 0 &&
    isNonBlank(evidence.securityApprovalRef) &&
    isNonBlank(evidence.platformApprovalRef) &&
    evidence.securityApprovalRef !== evidence.platformApprovalRef &&
    isNonBlank(evidence.rollbackRef)
  );
}

export function isRuleBundleActivationReady(evidence: RuleBundleCanaryEvidence): boolean {
  return evidence.finalStep === true && isRuleBundleCanaryHealthy(evidence);
}

export function isSastKillSwitchDecisionValid(decision: SastKillSwitchDecision): boolean {
  const activatedAt = Date.parse(decision.activatedAt);
  const reviewBy = Date.parse(decision.reviewBy);

  return (
    isNonBlank(decision.killSwitchId) &&
    SAST_KILL_SWITCH_SCOPES.includes(decision.scope) &&
    isNonBlank(decision.target) &&
    typeof decision.active === 'boolean' &&
    isNonBlank(decision.reasonCode) &&
    isNonBlank(decision.incidentRef) &&
    isNonBlank(decision.actorRef) &&
    Number.isFinite(activatedAt) &&
    Number.isFinite(reviewBy) &&
    reviewBy > activatedAt &&
    isNonBlank(decision.signatureRef) &&
    isNonBlank(decision.rollbackRef)
  );
}

export function isTenantSastRulePolicyValid(policy: TenantSastRulePolicy): boolean {
  const enabled = new Set(policy.enabledSemanticRuleIds);
  const hasRuleConflict = policy.disabledSemanticRuleIds.some((ruleId) => enabled.has(ruleId));

  return (
    isNonBlank(policy.tenantId) &&
    isNonBlank(policy.policyId) &&
    isNonBlank(policy.version) &&
    hasUniqueValues(policy.enabledSemanticRuleIds) &&
    hasUniqueValues(policy.disabledSemanticRuleIds) &&
    !hasRuleConflict &&
    policy.enabledSemanticRuleIds.every(isNonBlank) &&
    policy.disabledSemanticRuleIds.every(isNonBlank) &&
    policy.pathPatternDialect === 'GITIGNORE_SUBSET_V1' &&
    hasUniqueValues(policy.excludedPathPatterns) &&
    policy.excludedPathPatterns.every(isSafeDeclarativePathPattern) &&
    hasUniqueValues(policy.mandatoryRuleWaiverRefs) &&
    policy.mandatoryRuleWaiverRefs.every(isNonBlank) &&
    policy.customerExecutableConfigAllowed === false &&
    isNonBlank(policy.approvedByRef) &&
    isIsoTimestamp(policy.createdAt)
  );
}

export function areSastProductionQualityGatesSatisfied(
  measurements: SastQualityMeasurements
): boolean {
  return (
    isSafeIntegerAtLeast(measurements.eligibleCompletedScans, 1000) &&
    Number.isFinite(measurements.observationHours) &&
    measurements.observationHours >= 48 &&
    isSafeIntegerAtLeast(measurements.performanceRunsPerProfileSizeBucket, 30) &&
    measurements.goldenCorpusPassRate === 1 &&
    isRate(measurements.criticalHighPrecision) &&
    measurements.criticalHighPrecision >= 0.9 &&
    isRate(measurements.mustDetectRecall) &&
    measurements.mustDetectRecall >= 0.95 &&
    measurements.priorMustDetectRegressionRecall === 1 &&
    measurements.maliciousCorpusPassRate === 1 &&
    measurements.parserRejectRate === 1 &&
    isSafePositiveInteger(measurements.fastLaneP95Milliseconds) &&
    measurements.fastLaneP95Milliseconds <= 600000 &&
    isSafePositiveInteger(measurements.deepLaneP95Milliseconds) &&
    measurements.deepLaneP95Milliseconds <= 2700000 &&
    isRelativeDelta(measurements.falsePositiveIncrease) &&
    measurements.falsePositiveIncrease <= 0.02 &&
    isRate(measurements.scannerFailureRate) &&
    measurements.scannerFailureRate <= 0.02 &&
    measurements.normalizationDeterminismPassRate === 1 &&
    measurements.artifactBindingPassRate === 1 &&
    measurements.fingerprintFixturePassRate === 1 &&
    measurements.coverageDecisionFixturePassRate === 1 &&
    measurements.retentionExpiryPassRate === 1 &&
    measurements.crossTenantLeakCount === 0 &&
    measurements.secretLeakCount === 0 &&
    measurements.sandboxEscapeCount === 0 &&
    measurements.staleExternalPublicationCount === 0 &&
    measurements.unauthorizedEgressCount === 0 &&
    measurements.missingDestructionEvidenceCount === 0 &&
    measurements.evidencePolicyViolationCount === 0 &&
    measurements.unsignedArtifactExecutionCount === 0
  );
}

export function canSastRuntimeTransitionToCompleted(
  currentStage: SastRuntimeStage,
  expectedAttemptId: string,
  evidence: SastCleanupEvidence
): boolean {
  return (
    currentStage === 'CLEANUP_PENDING' &&
    isNonBlank(expectedAttemptId) &&
    evidence.attemptId === expectedAttemptId &&
    evidence.credentialRevokedAndWiped === true &&
    evidence.scannerProcessesTerminated === true &&
    evidence.writableVolumesDestroyed === true &&
    evidence.microVmTerminated === true &&
    evidence.resultIngressClosed === true &&
    isNonBlank(evidence.cleanupEvidenceRef) &&
    isNonBlank(evidence.finalAuditEventRef) &&
    isIsoTimestamp(evidence.completedAt)
  );
}

export function decideSastFailure(input: {
  failureClass: SastFailureClass;
  attempt: number;
  reasonCode: string;
}): SastFailureDecision {
  const retryable = input.failureClass === 'RETRYABLE_INFRASTRUCTURE';
  const securityViolation = input.failureClass === 'SECURITY_VIOLATION';

  return {
    failureClass: input.failureClass,
    retryAllowed: retryable && input.attempt === 1 && isNonBlank(input.reasonCode),
    maxAttempts: retryable ? 2 : 1,
    quarantineRequired: securityViolation || input.failureClass === 'SCANNER_DEFECT',
    externalPublicationAllowed: false,
    hardenedIsolationRequired: securityViolation,
    reasonCode: input.reasonCode
  };
}

function isSha256Digest(value: string): value is `sha256:${string}` {
  return /^sha256:[a-f0-9]{64}$/u.test(value);
}

function isNonBlank(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isBoundedIngressText(
  value: unknown,
  maximumUtf8Bytes: number
): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.trim() &&
    value === value.normalize('NFC') &&
    !hasControlCharacters(value) &&
    new TextEncoder().encode(value).byteLength <= maximumUtf8Bytes
  );
}

function hasUniqueValues<T>(values: readonly T[]): boolean {
  return new Set(values).size === values.length;
}

function hasSameImmutableData(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) {
    return true;
  }
  if (
    left === null ||
    right === null ||
    typeof left !== 'object' ||
    typeof right !== 'object'
  ) {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((value, index) => hasSameImmutableData(value, right[index]))
    );
  }

  const leftRecord = left as Record<string, unknown>;
  const rightRecord = right as Record<string, unknown>;
  const leftKeys = Object.keys(leftRecord).sort();
  const rightKeys = Object.keys(rightRecord).sort();

  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) =>
        key === rightKeys[index] && hasSameImmutableData(leftRecord[key], rightRecord[key])
    )
  );
}

function freezeSastProfile(profile: SastScanProfile): SastScanProfile {
  Object.freeze(profile.requiredScanners);
  Object.freeze(profile.optionalScanners);
  Object.freeze(profile.requiredCapabilities);
  Object.freeze(profile.sourceExtensions);
  Object.freeze(profile.manifestNames);
  Object.freeze(profile.limits);
  Object.freeze(profile.pathPolicy);
  return Object.freeze(profile);
}

function isSafePositiveInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function isSafeIntegerAtLeast(value: number, minimum: number): boolean {
  return Number.isSafeInteger(value) && value >= minimum;
}

function isSafeCoordinateValue(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && value <= SAST_MAX_COORDINATE_VALUE;
}

function isOptionalBoundedText(value: string | undefined, maximumUtf8Bytes: number): boolean {
  return (
    value === undefined ||
    (typeof value === 'string' &&
      value === value.normalize('NFC') &&
      !hasControlCharacters(value) &&
      new TextEncoder().encode(value).byteLength <= maximumUtf8Bytes)
  );
}

function encodeFingerprintField(value: string): string {
  const normalized = value.normalize('NFC');
  const utf8ByteLength = new TextEncoder().encode(normalized).byteLength;
  return `${utf8ByteLength}:${normalized}`;
}

function isRate(value: number): boolean {
  return Number.isFinite(value) && value >= 0 && value <= 1;
}

function isRelativeDelta(value: number): boolean {
  return Number.isFinite(value) && value >= -1;
}

function isIsoTimestamp(value: string): boolean {
  const timestamp = Date.parse(value);
  return (
    Number.isFinite(timestamp) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value)
  );
}

function isGitCommitSha(value: string): boolean {
  return /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/iu.test(value);
}

function isSafeSourceExtension(value: string): boolean {
  return /^\.[a-z0-9][a-z0-9._+-]{0,31}$/iu.test(value);
}

function isSafeManifestName(value: string): boolean {
  return (
    isNonBlank(value) &&
    value.length <= 255 &&
    !value.includes('/') &&
    !value.includes('\\') &&
    value !== '.' &&
    value !== '..' &&
    !hasControlCharacters(value)
  );
}

function isSafeNormalizedRelativePath(value: string): boolean {
  return (
    isNonBlank(value) &&
    value === value.normalize('NFC') &&
    value.length <= 1024 &&
    !value.startsWith('/') &&
    !/^[a-z]:[\\/]/iu.test(value) &&
    !value.startsWith('\\\\') &&
    !value.split(/[\\/]/u).includes('..') &&
    !hasControlCharacters(value)
  );
}

function isSafeDeclarativePathPattern(value: string): boolean {
  return (
    isNonBlank(value) &&
    value.length <= 1024 &&
    value === value.normalize('NFC') &&
    !value.startsWith('/') &&
    !/^[a-z]:[\\/]/iu.test(value) &&
    !value.startsWith('\\\\') &&
    !value.split(/[\\/]/u).includes('..') &&
    !hasControlCharacters(value)
  );
}

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}
