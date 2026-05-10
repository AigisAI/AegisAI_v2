export const PRODUCTION_SCAN_ARCHITECTURE_FEATURE_ID = '002-production-scan-architecture';

export const SCAN_LANES = ['FAST', 'DEEP'] as const;
export type ScanLane = (typeof SCAN_LANES)[number];

export const ISOLATION_CLASSES = ['STANDARD', 'HARDENED', 'RESTRICTED'] as const;
export type IsolationClass = (typeof ISOLATION_CLASSES)[number];

export const SCM_PROVIDERS = ['GITHUB', 'GITLAB'] as const;
export type ScmProvider = (typeof SCM_PROVIDERS)[number];

export const SCM_PRINCIPALS = ['REPO_READ', 'COMMENT_WRITE', 'INTEGRATION_ADMIN'] as const;
export type ScmPrincipal = (typeof SCM_PRINCIPALS)[number];

export const SCANNER_KINDS = ['OPENGREP', 'TRIVY', 'SYFT', 'MOCK'] as const;
export type ScannerKind = (typeof SCANNER_KINDS)[number];

export const FINDING_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];

export const FINDING_STATUSES = ['OPEN', 'ACCEPTED', 'REJECTED', 'WAIVED', 'SUPPRESSED', 'FIXED'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const DATA_CLASSIFICATIONS = [
  'LONG_LIVED_CONTROL',
  'SHORT_LIVED_EVIDENCE',
  'FORBIDDEN_LONG_TERM_STORAGE'
] as const;
export type DataClassification = (typeof DATA_CLASSIFICATIONS)[number];

export const POLICY_ACTIONS = ['DASHBOARD_ONLY', 'COMMENT', 'WARN', 'TICKET', 'BLOCK'] as const;
export type PolicyAction = (typeof POLICY_ACTIONS)[number];

export interface Tenant {
  id: string;
  slug: string;
  name: string;
  status: 'ACTIVE' | 'SUSPENDED';
}

export interface ScmIntegration {
  id: string;
  tenantId: string;
  provider: ScmProvider;
  integrationType: 'GITHUB_APP' | 'GITLAB_CLOUD_INTEGRATION';
  externalInstallationId: string;
  repoReadPrincipalId: string;
  commentWritePrincipalId?: string;
  integrationAdminPrincipalId?: string;
  status: 'ACTIVE' | 'REVOKED' | 'SUSPENDED';
}

export interface RepositoryBinding {
  id: string;
  tenantId: string;
  scmIntegrationId: string;
  providerRepoId: string;
  fullName: string;
  defaultBranch: string;
  isPrivate: boolean;
}

export interface CanonicalScanKeyInput {
  tenantId: string;
  repositoryBindingId: string;
  lane: ScanLane;
  targetRef: string;
  commitSha: string;
  policyVersion: string;
  scannerSetVersion: string;
}

export type CanonicalScanKey = string;

export interface ScanRequest {
  id: string;
  tenantId: string;
  repositoryBindingId: string;
  lane: ScanLane;
  targetRef: string;
  commitSha: string;
  policyVersion: string;
  scannerSetVersion: string;
  canonicalKey: CanonicalScanKey;
  isolationClass: IsolationClass;
  status: 'QUEUED' | 'PLANNING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELED';
}

export interface ScannerRun {
  id: string;
  tenantId: string;
  scanRequestId: string;
  scanner: ScannerKind;
  scannerVersion: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'TIMED_OUT' | 'SKIPPED';
  rawArtifactObjectKey?: string;
}

export interface NormalizedFinding {
  id: string;
  tenantId: string;
  scanRequestId: string;
  scannerRunId: string;
  title: string;
  severity: FindingSeverity;
  scannerProvenance: ScannerKind;
  filePath: string;
  lineStart: number;
  lineEnd?: number;
  status: FindingStatus;
  policyDecisionId?: string;
}

export interface EvidencePack {
  id: string;
  tenantId: string;
  scanRequestId: string;
  classification: Extract<DataClassification, 'SHORT_LIVED_EVIDENCE'>;
  objectKey: string;
  expiresAt: string;
  byteSize: number;
  redacted: boolean;
}

export interface EvidenceAccessRequest {
  evidencePackId: string;
  tenantId: string;
  scanRequestId: string;
  objectKey: string;
  expiresAt: string;
  accessMode: 'METADATA_ONLY';
  redacted: true;
  requestedAt: string;
}

export interface PolicyDecision {
  id: string;
  tenantId: string;
  scanRequestId: string;
  findingId?: string;
  enforcementAction: PolicyAction;
  commentAllowed: boolean;
  dashboardVisible: boolean;
  ticketRequested: boolean;
  blockRequested: boolean;
  reasonCodes: string[];
  requiredCoverage: ScannerKind[];
  waiverApplied: boolean;
  staleSuppressed: boolean;
  aiAdvisoryVisible: boolean;
}

export interface PolicyEvaluationInput {
  tenantId: string;
  scanRequestId: string;
  finding: NormalizedFinding;
  scanLane: ScanLane;
  scannerCoverage: ScannerKind[];
  aiAdvisory?: {
    visible: boolean;
    suggestedAction?: PolicyAction;
    summary?: string;
  };
}

export interface CommentDispatchPlanRequest {
  tenantId: string;
  repositoryBindingId: string;
  targetRef: string;
  commitSha: string;
  policyDecision: PolicyDecision;
  finding: NormalizedFinding;
}

export interface CommentDispatchPlan {
  id: string;
  idempotencyKey: string;
  tenantId: string;
  repositoryBindingId: string;
  provider: ScmProvider;
  providerRepoId: string;
  commentWritePrincipalId: string;
  policyDecisionId: string;
  findingId: string;
  targetRef: string;
  commitSha: string;
  dispatchAllowed: true;
}

export interface CommentDispatchEnqueueRequest {
  tenantId: string;
  planId: string;
}

export interface CommentDispatchOutboxItem {
  id: string;
  tenantId: string;
  planId: string;
  idempotencyKey: string;
  repositoryBindingId: string;
  provider: ScmProvider;
  providerRepoId: string;
  commentWritePrincipalId: string;
  policyDecisionId: string;
  findingId: string;
  targetRef: string;
  commitSha: string;
  status: 'PENDING' | 'PUBLISHED' | 'FAILED' | 'CANCELED';
  enqueuedAt: string;
}

export interface Waiver {
  id: string;
  tenantId: string;
  owner: string;
  reason: string;
  scope: string;
  expiresAt: string;
  lastReviewedAt?: string;
}

export interface WaiverCreateInput {
  tenantId: string;
  owner: string;
  reason: string;
  scope: string;
  expiresAt: string;
}

export interface WaiverUpdateInput {
  tenantId: string;
  owner?: string;
  reason?: string;
  scope?: string;
  expiresAt?: string;
  lastReviewedAt?: string;
}

export interface Suppression {
  id: string;
  tenantId: string;
  scanRequestId: string;
  findingId?: string;
  reason: 'STALE_RESULT' | 'DUPLICATE' | 'POLICY';
}

export interface SuppressionCreateInput {
  tenantId: string;
  scanRequestId: string;
  findingId?: string;
  reason: Suppression['reason'];
}

export interface AuditEvent {
  id: string;
  tenantId: string;
  eventType: string;
  actor: string;
  targetType: string;
  targetId: string;
  occurredAt: string;
}

export interface CommentDispatchAuditEvent extends AuditEvent {
  eventType: 'comment_dispatch.planned';
  actor: 'comment-dispatcher';
  targetType: 'comment_dispatch_plan';
  metadata: {
    repositoryBindingId: string;
    provider: ScmProvider;
    providerRepoId: string;
    policyDecisionId: string;
    findingId: string;
    targetRef: string;
    commitSha: string;
    commentWritePrincipalId: string;
  };
}

export interface TokenBrokerIssueRequest {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  principal: Extract<ScmPrincipal, 'REPO_READ'>;
  commitSha: string;
  ttlSeconds: number;
  auditReason: string;
}

export interface AiAdvisoryRequest {
  tenantId: string;
  scanRequestId: string;
  findingId: string;
  normalizedFinding: NormalizedFinding;
  evidence: EvidencePack;
  modelVersion: string;
}

export interface AiAdvisoryResult {
  id: string;
  tenantId: string;
  scanRequestId: string;
  findingId: string;
  modelVersion: string;
  advisoryOnly: true;
  redactedEvidenceOnly: true;
  detectorSignals: string[];
  plannerSteps: string[];
  confidence: number;
  createdAt: string;
}

export interface IsolationEscalationInput {
  tenantAgeDays: number;
  repositorySizeMb: number;
  hasParserFaultHistory: boolean;
  hasAbuseSignal: boolean;
  hasSuspiciousPathLayout: boolean;
  hasRepeatedTimeout: boolean;
  manuallyEscalated: boolean;
}

export interface EvidencePackMetadataInput {
  id: string;
  tenantId: string;
  scanRequestId: string;
  byteSize: number;
  expiresAt: string;
  redacted: boolean;
}

export function buildCanonicalScanKey(input: CanonicalScanKeyInput): CanonicalScanKey {
  return [
    input.tenantId,
    input.repositoryBindingId,
    input.lane,
    input.targetRef,
    input.commitSha,
    input.policyVersion,
    input.scannerSetVersion
  ].join(':');
}

export function buildCommentDispatchIdempotencyKey(input: CommentDispatchPlanRequest): string {
  return [
    input.tenantId,
    input.repositoryBindingId,
    input.policyDecision.id,
    input.finding.id,
    input.targetRef,
    input.commitSha
  ].join(':');
}

export function shouldEscalateIsolation(input: IsolationEscalationInput): boolean {
  return (
    input.tenantAgeDays < 14 ||
    input.repositorySizeMb > 1024 ||
    input.hasParserFaultHistory ||
    input.hasAbuseSignal ||
    input.hasSuspiciousPathLayout ||
    input.hasRepeatedTimeout ||
    input.manuallyEscalated
  );
}

export function createEvidencePackMetadata(input: EvidencePackMetadataInput): EvidencePack {
  return {
    id: input.id,
    tenantId: input.tenantId,
    scanRequestId: input.scanRequestId,
    classification: 'SHORT_LIVED_EVIDENCE',
    objectKey: `${input.tenantId}/${input.scanRequestId}/evidence/${input.id}.json`,
    expiresAt: input.expiresAt,
    byteSize: input.byteSize,
    redacted: input.redacted
  };
}
