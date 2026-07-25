import type {
  SastArtifactValidationReasonCode
} from './sast-artifact-validation';
import {
  SAST_ARTIFACT_VALIDATION_REASON_CODES
} from './sast-artifact-validation';
import type { SastFailureClass } from './sast-runtime';
import { SAST_FAILURE_CLASSES } from './sast-runtime';

export const SAST_ARTIFACT_DISPOSITION_VERSION =
  'sast-artifact-disposition-v1' as const;

export const SAST_ARTIFACT_MAX_RETENTION_SECONDS = 7 * 24 * 60 * 60;

export const SAST_ARTIFACT_STORAGE_RECEIPT_REFERENCE_PREFIX =
  'storage-receipt://' as const;

export const SAST_ARTIFACT_DISPOSITIONS = [
  'ACCEPTED',
  'REJECTED',
  'QUARANTINED'
] as const;
export type SastArtifactDisposition =
  (typeof SAST_ARTIFACT_DISPOSITIONS)[number];

export const SAST_ARTIFACT_STORAGE_ACTIONS = [
  'RETAIN_ACCEPTED',
  'DELETE_REJECTED',
  'MOVE_REENCRYPT_QUARANTINE'
] as const;
export type SastArtifactStorageAction =
  (typeof SAST_ARTIFACT_STORAGE_ACTIONS)[number];

/**
 * Order is part of the v1 digest contract. Producers must de-duplicate and
 * emit reasons in this priority order, never in discovery order.
 */
export const SAST_ARTIFACT_DISPOSITION_REASON_CODES = [
  'ARTIFACT_RETENTION_EXPIRED',
  'ARTIFACT_SOURCE_OBJECT_MISSING',
  'ARTIFACT_DURABLE_METADATA_INVALID',
  'ARTIFACT_DURABLE_BINDING_MISMATCH',
  'ARTIFACT_SCANNER_RUN_NOT_SUCCESSFUL',
  'ARTIFACT_VALIDATION_FAILED',
  'ARTIFACT_ACCEPTANCE_DENIED',
  'ARTIFACT_VALIDATION_ACCEPTED'
] as const;
export type SastArtifactDispositionReasonCode =
  (typeof SAST_ARTIFACT_DISPOSITION_REASON_CODES)[number];

export interface SastArtifactDispositionScope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  scannerRunId: string;
}

export interface SastArtifactDispositionIntent {
  version: typeof SAST_ARTIFACT_DISPOSITION_VERSION;
  ingestionId: string;
  scope: Readonly<SastArtifactDispositionScope>;
  disposition: SastArtifactDisposition;
  storageAction: SastArtifactStorageAction;
  failureClass?: SastFailureClass;
  reasonCodes: readonly SastArtifactDispositionReasonCode[];
  validationReasonCodes: readonly SastArtifactValidationReasonCode[];
  validationResultDigest: `sha256:${string}`;
  normalizationEligible: boolean;
  retentionExpiresAt?: string;
  acceptanceControlRef?: string;
  createdAt: string;
  intentDigest: `sha256:${string}`;
}

export type SastArtifactDispositionIntentCore = Omit<
  SastArtifactDispositionIntent,
  'intentDigest'
>;

export interface SastArtifactDispositionDecision {
  version: typeof SAST_ARTIFACT_DISPOSITION_VERSION;
  ingestionId: string;
  disposition: SastArtifactDisposition;
  storageAction: SastArtifactStorageAction;
  failureClass?: SastFailureClass;
  reasonCodes: readonly SastArtifactDispositionReasonCode[];
  validationReasonCodes: readonly SastArtifactValidationReasonCode[];
  validationResultDigest: `sha256:${string}`;
  normalizationEligible: boolean;
  retentionExpiresAt?: string;
  acceptanceControlRef?: string;
  intentDigest: `sha256:${string}`;
  storageOperationId: string;
  storageReceiptRef: string;
  storageReceiptDigest: `sha256:${string}`;
  encryptionContextDigest?: `sha256:${string}`;
  decidedAt: string;
  decisionDigest: `sha256:${string}`;
}

export type SastArtifactDispositionDecisionCore = Omit<
  SastArtifactDispositionDecision,
  'decisionDigest'
>;

export function canonicalizeSastArtifactDispositionIntent(
  intent: Readonly<SastArtifactDispositionIntentCore>
): string {
  return JSON.stringify({
    version: intent.version,
    ingestionId: intent.ingestionId,
    scope: {
      tenantId: intent.scope.tenantId,
      repositoryBindingId: intent.scope.repositoryBindingId,
      scanRequestId: intent.scope.scanRequestId,
      attemptId: intent.scope.attemptId,
      scannerRunId: intent.scope.scannerRunId
    },
    disposition: intent.disposition,
    storageAction: intent.storageAction,
    ...(intent.failureClass
      ? { failureClass: intent.failureClass }
      : {}),
    reasonCodes: [...intent.reasonCodes],
    validationReasonCodes: [...intent.validationReasonCodes],
    validationResultDigest: intent.validationResultDigest,
    normalizationEligible: intent.normalizationEligible,
    ...(intent.retentionExpiresAt
      ? { retentionExpiresAt: intent.retentionExpiresAt }
      : {}),
    ...(intent.acceptanceControlRef
      ? { acceptanceControlRef: intent.acceptanceControlRef }
      : {}),
    createdAt: intent.createdAt
  });
}

export function canonicalizeSastArtifactDispositionDecision(
  decision: Readonly<SastArtifactDispositionDecisionCore>
): string {
  return JSON.stringify({
    version: decision.version,
    ingestionId: decision.ingestionId,
    disposition: decision.disposition,
    storageAction: decision.storageAction,
    ...(decision.failureClass
      ? { failureClass: decision.failureClass }
      : {}),
    reasonCodes: [...decision.reasonCodes],
    validationReasonCodes: [...decision.validationReasonCodes],
    validationResultDigest: decision.validationResultDigest,
    normalizationEligible: decision.normalizationEligible,
    ...(decision.retentionExpiresAt
      ? { retentionExpiresAt: decision.retentionExpiresAt }
      : {}),
    ...(decision.acceptanceControlRef
      ? { acceptanceControlRef: decision.acceptanceControlRef }
      : {}),
    intentDigest: decision.intentDigest,
    storageOperationId: decision.storageOperationId,
    storageReceiptRef: decision.storageReceiptRef,
    storageReceiptDigest: decision.storageReceiptDigest,
    ...(decision.encryptionContextDigest
      ? { encryptionContextDigest: decision.encryptionContextDigest }
      : {}),
    decidedAt: decision.decidedAt
  });
}

export function isSastArtifactDispositionIntentShapeValid(
  value: unknown
): value is SastArtifactDispositionIntent {
  if (!isRecord(value)) return false;

  const allowedKeys = [
    'version',
    'ingestionId',
    'scope',
    'disposition',
    'storageAction',
    'failureClass',
    'reasonCodes',
    'validationReasonCodes',
    'validationResultDigest',
    'normalizationEligible',
    'retentionExpiresAt',
    'acceptanceControlRef',
    'createdAt',
    'intentDigest'
  ];
  if (!hasOnlyAllowedKeys(value, allowedKeys)) return false;

  return (
    value.version === SAST_ARTIFACT_DISPOSITION_VERSION &&
    isBoundedReference(value.ingestionId) &&
    isScopeValid(value.scope) &&
    SAST_ARTIFACT_DISPOSITIONS.includes(
      value.disposition as SastArtifactDisposition
    ) &&
    SAST_ARTIFACT_STORAGE_ACTIONS.includes(
      value.storageAction as SastArtifactStorageAction
    ) &&
    isOptionalFailureClass(value.failureClass) &&
    isOrderedDispositionReasons(value.reasonCodes) &&
    isOrderedValidationReasons(value.validationReasonCodes) &&
    isSha256Digest(value.validationResultDigest) &&
    typeof value.normalizationEligible === 'boolean' &&
    isOptionalIsoTimestamp(value.retentionExpiresAt) &&
    isOptionalBoundedReference(value.acceptanceControlRef) &&
    isIsoTimestamp(value.createdAt) &&
    isSha256Digest(value.intentDigest) &&
    isDispositionInvariantValid(value)
  );
}

export function isSastArtifactDispositionDecisionShapeValid(
  value: unknown
): value is SastArtifactDispositionDecision {
  if (!isRecord(value)) return false;

  const allowedKeys = [
    'version',
    'ingestionId',
    'disposition',
    'storageAction',
    'failureClass',
    'reasonCodes',
    'validationReasonCodes',
    'validationResultDigest',
    'normalizationEligible',
    'retentionExpiresAt',
    'acceptanceControlRef',
    'intentDigest',
    'storageOperationId',
    'storageReceiptRef',
    'storageReceiptDigest',
    'encryptionContextDigest',
    'decidedAt',
    'decisionDigest'
  ];
  if (!hasOnlyAllowedKeys(value, allowedKeys)) return false;

  return (
    value.version === SAST_ARTIFACT_DISPOSITION_VERSION &&
    isBoundedReference(value.ingestionId) &&
    SAST_ARTIFACT_DISPOSITIONS.includes(
      value.disposition as SastArtifactDisposition
    ) &&
    SAST_ARTIFACT_STORAGE_ACTIONS.includes(
      value.storageAction as SastArtifactStorageAction
    ) &&
    isOptionalFailureClass(value.failureClass) &&
    isOrderedDispositionReasons(value.reasonCodes) &&
    isOrderedValidationReasons(value.validationReasonCodes) &&
    isSha256Digest(value.validationResultDigest) &&
    typeof value.normalizationEligible === 'boolean' &&
    isOptionalIsoTimestamp(value.retentionExpiresAt) &&
    isOptionalBoundedReference(value.acceptanceControlRef) &&
    isSha256Digest(value.intentDigest) &&
    isStorageOperationId(value.storageOperationId) &&
    isSastArtifactStorageReceiptReferenceValid(
      value.storageReceiptRef
    ) &&
    isSha256Digest(value.storageReceiptDigest) &&
    (value.encryptionContextDigest === undefined ||
      isSha256Digest(value.encryptionContextDigest)) &&
    isIsoTimestamp(value.decidedAt) &&
    isSha256Digest(value.decisionDigest) &&
    (Array.isArray(value.reasonCodes) &&
      (value.reasonCodes.includes('ARTIFACT_SOURCE_OBJECT_MISSING') ||
      value.storageOperationId ===
        `${SAST_ARTIFACT_DISPOSITION_VERSION}:${value.intentDigest.slice(
          'sha256:'.length
        )}`)) &&
    isDispositionInvariantValid(value) &&
    (value.disposition === 'QUARANTINED'
      ? value.encryptionContextDigest !== undefined
      : value.encryptionContextDigest === undefined)
  );
}

function isDispositionInvariantValid(
  value: Record<string, unknown>
): boolean {
  if (
    !Array.isArray(value.reasonCodes) ||
    !Array.isArray(value.validationReasonCodes)
  ) {
    return false;
  }
  const hasAcceptanceDenial = value.reasonCodes.includes(
    'ARTIFACT_ACCEPTANCE_DENIED'
  );
  const hasValidationFailure = value.reasonCodes.includes(
    'ARTIFACT_VALIDATION_FAILED'
  );
  if (
    hasValidationFailure !== (value.validationReasonCodes.length > 0)
  ) {
    return false;
  }

  if (value.disposition === 'ACCEPTED') {
    return (
      value.storageAction === 'RETAIN_ACCEPTED' &&
      value.failureClass === undefined &&
      value.normalizationEligible === true &&
      value.reasonCodes.length === 1 &&
      value.reasonCodes[0] === 'ARTIFACT_VALIDATION_ACCEPTED' &&
      Array.isArray(value.validationReasonCodes) &&
      value.validationReasonCodes.length === 0 &&
      isRetentionActiveAtDecisionBoundary(value) &&
      typeof value.acceptanceControlRef === 'string'
    );
  }

  if (value.disposition === 'REJECTED') {
    return (
      value.storageAction === 'DELETE_REJECTED' &&
      (value.failureClass === 'NON_RETRYABLE_INPUT' ||
        value.failureClass === 'SECURITY_VIOLATION') &&
      value.normalizationEligible === false &&
      value.retentionExpiresAt === undefined &&
      hasAcceptanceDenial ===
        (typeof value.acceptanceControlRef === 'string') &&
      !value.reasonCodes.includes('ARTIFACT_VALIDATION_ACCEPTED') &&
      (value.reasonCodes.includes('ARTIFACT_RETENTION_EXPIRED') ||
        value.reasonCodes.includes('ARTIFACT_SOURCE_OBJECT_MISSING'))
    );
  }

  return (
    value.disposition === 'QUARANTINED' &&
    value.storageAction === 'MOVE_REENCRYPT_QUARANTINE' &&
    value.failureClass === 'SECURITY_VIOLATION' &&
    value.normalizationEligible === false &&
    value.reasonCodes.length > 0 &&
    isRetentionActiveAtDecisionBoundary(value) &&
    hasAcceptanceDenial ===
      (typeof value.acceptanceControlRef === 'string') &&
    !value.reasonCodes.includes('ARTIFACT_VALIDATION_ACCEPTED') &&
    !value.reasonCodes.includes('ARTIFACT_RETENTION_EXPIRED') &&
    !value.reasonCodes.includes('ARTIFACT_SOURCE_OBJECT_MISSING')
  );
}

function isRetentionActiveAtDecisionBoundary(
  value: Record<string, unknown>
): boolean {
  const boundary =
    typeof value.createdAt === 'string'
      ? value.createdAt
      : value.decidedAt;
  return (
    typeof value.retentionExpiresAt === 'string' &&
    typeof boundary === 'string' &&
    Number.isFinite(Date.parse(value.retentionExpiresAt)) &&
    Number.isFinite(Date.parse(boundary)) &&
    Date.parse(value.retentionExpiresAt) > Date.parse(boundary)
  );
}

function isScopeValid(value: unknown): value is SastArtifactDispositionScope {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'attemptId',
      'scannerRunId'
    ]) &&
    Object.values(value).every(isBoundedReference)
  );
}

function isOrderedDispositionReasons(value: unknown): boolean {
  return isStrictOrderedMembers(
    value,
    SAST_ARTIFACT_DISPOSITION_REASON_CODES
  );
}

function isOrderedValidationReasons(value: unknown): boolean {
  return isStrictOrderedMembers(
    value,
    SAST_ARTIFACT_VALIDATION_REASON_CODES
  );
}

function isStrictOrderedMembers(
  value: unknown,
  allowed: readonly string[]
): value is string[] {
  return (
    Array.isArray(value) &&
    value.every(
      (item, index) =>
        typeof item === 'string' &&
        allowed.includes(item) &&
        (index === 0 ||
          allowed.indexOf(value[index - 1] as string) <
            allowed.indexOf(item))
    )
  );
}

function isOptionalFailureClass(value: unknown): boolean {
  return (
    value === undefined ||
    SAST_FAILURE_CLASSES.includes(value as SastFailureClass)
  );
}

function isOptionalIsoTimestamp(value: unknown): boolean {
  return value === undefined || isIsoTimestamp(value);
}

function isOptionalBoundedReference(value: unknown): boolean {
  return value === undefined || isBoundedReference(value);
}

function isBoundedReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value === value.trim() &&
    value === value.normalize('NFC') &&
    value.length > 0 &&
    !hasControlCharacters(value) &&
    new TextEncoder().encode(value).byteLength <= 2048
  );
}

function isIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isSha256Digest(value: unknown): value is `sha256:${string}` {
  return (
    typeof value === 'string' &&
    /^sha256:[a-f0-9]{64}$/u.test(value)
  );
}

function isStorageOperationId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^sast-artifact-disposition-v1:[a-f0-9]{64}$/u.test(value)
  );
}

export function isSastArtifactStorageReceiptReferenceValid(
  value: unknown
): value is string {
  if (
    !isBoundedReference(value) ||
    !value.startsWith(
      SAST_ARTIFACT_STORAGE_RECEIPT_REFERENCE_PREFIX
    )
  ) {
    return false;
  }
  const opaqueReference = value.slice(
    SAST_ARTIFACT_STORAGE_RECEIPT_REFERENCE_PREFIX.length
  );
  return (
    opaqueReference.length > 0 &&
    /^[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+$/u.test(opaqueReference)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return (
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f)
    );
  });
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[]
): boolean {
  const actual = Object.keys(value);
  return (
    actual.length === expected.length &&
    actual.every((key) => expected.includes(key))
  );
}

function hasOnlyAllowedKeys(
  value: Record<string, unknown>,
  allowed: readonly string[]
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}
