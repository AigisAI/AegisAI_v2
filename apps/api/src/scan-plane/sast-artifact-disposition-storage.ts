import type {
  SastArtifactDispositionScope,
  SastArtifactStorageAction
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export const SAST_ARTIFACT_QUARANTINE_CONTEXT_VERSION =
  'sast-artifact-quarantine-context-v1' as const;
export const SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX =
  'restricted/sast-artifact-quarantine/' as const;

export interface SastArtifactQuarantineEncryptionContext {
  version: typeof SAST_ARTIFACT_QUARANTINE_CONTEXT_VERSION;
  purpose: 'SAST_ARTIFACT_FORENSIC_QUARANTINE';
  ingestionId: string;
  scope: Readonly<SastArtifactDispositionScope>;
  validationResultDigest: `sha256:${string}`;
  intentDigest: `sha256:${string}`;
}

export function canonicalizeSastArtifactQuarantineEncryptionContext(
  context: Readonly<SastArtifactQuarantineEncryptionContext>
): string {
  return JSON.stringify({
    version: context.version,
    purpose: context.purpose,
    ingestionId: context.ingestionId,
    scope: {
      tenantId: context.scope.tenantId,
      repositoryBindingId: context.scope.repositoryBindingId,
      scanRequestId: context.scope.scanRequestId,
      attemptId: context.scope.attemptId,
      scannerRunId: context.scope.scannerRunId
    },
    validationResultDigest: context.validationResultDigest,
    intentDigest: context.intentDigest
  });
}

export interface ApplySastArtifactStorageDispositionInput {
  operationId: string;
  ingestionId: string;
  scope: Readonly<SastArtifactDispositionScope>;
  action: SastArtifactStorageAction;
  sourceObjectKey: string;
  expectedContentDigest: `sha256:${string}`;
  expectedByteSize: number;
  retentionExpiresAt?: string;
  quarantineEncryptionContext?: Readonly<SastArtifactQuarantineEncryptionContext>;
}

export interface SastArtifactStorageDispositionReceipt {
  operationId: string;
  storageReceiptRef: string;
  storageReceiptDigest: `sha256:${string}`;
  finalObjectKey?: string;
  encryptionContextDigest?: `sha256:${string}`;
  completedAt: string;
}

export abstract class SastArtifactDispositionStorage {
  /**
   * Implementations must use server-side retain/delete/re-encrypt operations.
   * The Scan Plane is deliberately not given an object read capability.
   * operationId is the durable idempotency key.
   */
  abstract apply(
    input: Readonly<ApplySastArtifactStorageDispositionInput>
  ): Promise<SastArtifactStorageDispositionReceipt>;
}

export class SastArtifactDispositionStorageUnavailableError extends Error {
  constructor() {
    super('No production SAST artifact disposition storage adapter is installed.');
    this.name = 'SastArtifactDispositionStorageUnavailableError';
  }
}

export class SastArtifactSourceObjectMissingError extends Error {
  constructor(
    readonly receipt: Readonly<SastArtifactStorageDispositionReceipt>
  ) {
    super('The source artifact object is absent.');
    this.name = 'SastArtifactSourceObjectMissingError';
  }
}

@Injectable()
export class UnavailableSastArtifactDispositionStorage
  extends SastArtifactDispositionStorage
{
  apply(): Promise<SastArtifactStorageDispositionReceipt> {
    return Promise.reject(
      new SastArtifactDispositionStorageUnavailableError()
    );
  }
}
