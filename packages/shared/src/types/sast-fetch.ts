import type { SastPathPolicy, SastResourceLimits } from './sast-runtime';

export const SAST_REPOSITORY_ENTRY_KINDS = [
  'FILE',
  'SYMLINK',
  'SUBMODULE'
] as const;
export type SastRepositoryEntryKind = (typeof SAST_REPOSITORY_ENTRY_KINDS)[number];

export const SAST_REPOSITORY_ENTRY_CLASSIFICATIONS = [
  'SOURCE',
  'MANIFEST',
  'GENERATED',
  'VENDOR',
  'FIXTURE',
  'HIDDEN_SYSTEM',
  'LFS_POINTER',
  'ARCHIVE',
  'OTHER'
] as const;
export type SastRepositoryEntryClassification =
  (typeof SAST_REPOSITORY_ENTRY_CLASSIFICATIONS)[number];

export const SAST_PREFLIGHT_DECISIONS = [
  'ACCEPT',
  'REJECT',
  'RESTRICTED_ESCALATION'
] as const;
export type SastPreflightDecision = (typeof SAST_PREFLIGHT_DECISIONS)[number];

export const SAST_PREFLIGHT_SELECTION_MODES = [
  'ALL_SCANNABLE',
  'PATH_ALLOWLIST'
] as const;
export type SastPreflightSelectionMode =
  (typeof SAST_PREFLIGHT_SELECTION_MODES)[number];

export interface SastRepositoryPreflightSelection {
  mode: SastPreflightSelectionMode;
  paths: readonly string[];
}

export const SAST_PREFLIGHT_REASON_CODES = [
  'PATH_INVALID_UTF8',
  'PATH_NUL_OR_CONTROL',
  'PATH_ABSOLUTE',
  'PATH_DRIVE_OR_UNC',
  'PATH_PARENT_TRAVERSAL',
  'PATH_LENGTH_LIMIT_EXCEEDED',
  'PATH_CASE_COLLISION',
  'PATH_UNICODE_COLLISION',
  'PATH_DUPLICATE',
  'SYMLINK_INVALID_UTF8',
  'SYMLINK_OUTSIDE_ROOT',
  'SYMLINK_CYCLE',
  'PATH_DEPTH_LIMIT_EXCEEDED',
  'REPOSITORY_BYTES_LIMIT_EXCEEDED',
  'SELECTED_BYTES_LIMIT_EXCEEDED',
  'FILE_COUNT_LIMIT_EXCEEDED',
  'SINGLE_FILE_BYTES_LIMIT_EXCEEDED',
  'SYMLINK_PRESENT',
  'SUBMODULE_PRESENT',
  'LFS_POINTER_PRESENT',
  'ARCHIVE_PRESENT'
] as const;
export type SastPreflightReasonCode = (typeof SAST_PREFLIGHT_REASON_CODES)[number];

export interface SastRepositoryTreeEntry {
  path: string;
  pathEncodingValid: boolean;
  kind: SastRepositoryEntryKind;
  byteSize: number;
  gitObjectId: `sha1:${string}` | `sha256:${string}`;
  executable: boolean;
  symlinkTarget?: string;
  symlinkTargetEncodingValid?: boolean;
  lfsPointer: boolean;
}

export interface SastRepositoryPreflightInput {
  attemptId: string;
  fixedCommitSha: string;
  pathPolicyVersion: string;
  pathPolicy: Readonly<SastPathPolicy>;
  limits: Pick<
    SastResourceLimits,
    | 'maxRepositoryBytes'
    | 'maxSelectedBytes'
    | 'maxFileCount'
    | 'maxSingleFileBytes'
    | 'maxPathDepth'
  >;
  sourceExtensions: readonly string[];
  manifestNames: readonly string[];
  selection: Readonly<SastRepositoryPreflightSelection>;
  entries: readonly SastRepositoryTreeEntry[];
}

export interface SastRepositoryPreflightCounts {
  fileCount: number;
  directoryCount: number;
  symlinkCount: number;
  submoduleCount: number;
  lfsPointerCount: number;
  archiveCount: number;
  generatedCount: number;
  vendorCount: number;
  fixtureCount: number;
  hiddenSystemCount: number;
}

export interface SastRepositoryPreflightResult {
  attemptId: string;
  fixedCommitSha: string;
  pathPolicyVersion: string;
  inventoryDigest: `sha256:${string}`;
  attestationRef: string;
  decision: SastPreflightDecision;
  reasonCodes: SastPreflightReasonCode[];
  repositoryBytes: number;
  selectedBytes: number;
  maxSingleFileBytes: number;
  maxPathDepth: number;
  counts: SastRepositoryPreflightCounts;
  rejectedPaths: string[];
}

export interface SastRepositoryFetchMetadata {
  attemptId: string;
  fixedCommitSha: string;
  remoteHost: string;
  objectCount: number;
  fetchedBytes: number;
  shallow: true;
  detachedHead: true;
  submodulesFetched: false;
  lfsObjectsFetched: false;
  archivesExpanded: false;
  gitMetadataRemoved: true;
  credentialWiped: true;
}

export type SastCredentialLeaseStatus = 'RESERVED' | 'ISSUED' | 'WIPED' | 'REVOKED';

export interface SastCredentialLeaseMetadata {
  credentialId: string;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  workloadIdentityRef: string;
  commitSha: string;
  credentialFingerprint?: `sha256:${string}`;
  status: SastCredentialLeaseStatus;
  issuedAt: string;
  expiresAt: string;
  wipedAt?: string;
  revokedAt?: string;
}
