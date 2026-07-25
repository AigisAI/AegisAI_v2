import type {
  ScannerArtifactEnvelope,
  SastArtifactDispositionDecision,
  SastArtifactDispositionIntent,
  SastArtifactDispositionScope,
  SastArtifactValidationResult,
  SastScanPlan,
  SastScannerKind
} from '@aegisai/shared';

export interface SastArtifactDispositionCandidate {
  ingestionId: string;
  scope: Readonly<SastArtifactDispositionScope>;
  workloadIdentityRef: string;
  identityValidated: boolean;
  envelope: unknown;
  envelopeDigest: string;
  declaredContentDigest: string;
  observedContentDigest: string | null;
  declaredByteSize: number;
  observedByteSize: number | null;
  objectKey: string;
  validationMetadata: unknown;
  receivedAt: string;
  scanner: SastScannerKind | string;
  scannerVersion: string;
  scannerImageDigest: string | null;
  wrapperDigest: string | null;
  ruleBundleDigest: string | null;
  vulnerabilityDatabaseDigest: string | null;
  scannerSetDigest: string | null;
  schemaBundleDigest: string | null;
  normalizerBundleDigest: string | null;
  profileId: string | null;
  profileDigest: string | null;
  scannerWorkspaceInventoryDigest: string | null;
  scannerArtifactSchema: string | null;
  scannerArtifactSchemaVersion: string | null;
  scannerExitCode: number | null;
  scannerTimedOut: boolean | null;
  scannerOutputLimitExceeded: boolean | null;
  scannerArtifactByteSize: number | null;
  scannerRunStatus: string;
  scannerRunCompletedAt: string;
  scannerRawArtifactObjectKey: string | null;
  scannerArtifactRef: string | null;
  preflightAttestationRef: string | null;
  preflightInventoryDigest: string | null;
  immutablePlan: unknown;
  persistedIntent: unknown;
  persistedIntentDigest: string | null;
  persistedOperationId: string | null;
  leaseToken: string;
  leaseExpiresAt: string;
}

export interface ClaimSastArtifactDispositionInput {
  workerId: string;
  leaseToken: string;
  claimedAt: string;
  leaseExpiresAt: string;
}

export interface SaveSastArtifactDispositionIntentInput {
  ingestionId: string;
  leaseToken: string;
  expectedIntentDigest: string | null;
  intent: Readonly<SastArtifactDispositionIntent>;
  operationId: string;
  savedAt: string;
}

export interface FinalizeSastArtifactDispositionInput {
  decisionId: string;
  auditEventId: string;
  ingestionId: string;
  scope: Readonly<SastArtifactDispositionScope>;
  leaseToken: string;
  operationId: string;
  decision: Readonly<SastArtifactDispositionDecision>;
  fencedAt: string;
  finalObjectKey?: string;
}

export interface ReleaseSastArtifactDispositionInput {
  ingestionId: string;
  leaseToken: string;
  errorCode: string;
  releasedAt: string;
  retryAt: string;
}

export class SastArtifactDispositionFenceError extends Error {
  constructor() {
    super('The artifact disposition lease is no longer valid.');
    this.name = 'SastArtifactDispositionFenceError';
  }
}

export abstract class SastArtifactDispositionStore {
  abstract claimNext(
    input: Readonly<ClaimSastArtifactDispositionInput>
  ): Promise<SastArtifactDispositionCandidate | null>;

  abstract saveIntent(
    input: Readonly<SaveSastArtifactDispositionIntentInput>
  ): Promise<void>;

  abstract finalize(
    input: Readonly<FinalizeSastArtifactDispositionInput>
  ): Promise<void>;

  abstract release(
    input: Readonly<ReleaseSastArtifactDispositionInput>
  ): Promise<void>;
}

export type DurableSastArtifactEnvelope = ScannerArtifactEnvelope;
export type DurableSastArtifactValidationResult =
  SastArtifactValidationResult;
export type DurableSastScanPlan = SastScanPlan;
