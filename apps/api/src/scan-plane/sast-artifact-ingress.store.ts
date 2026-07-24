import type {
  SastArtifactIngestionState,
  SastScannerKind,
  SastScanPlan
} from '@aegisai/shared';

export interface SastArtifactIngressExpectedBinding {
  plan: Readonly<SastScanPlan>;
  attemptId: string;
  scannerRunId: string;
  workloadIdentityRef: string;
  preflightAttestationRef: string;
  preflightInventoryDigest: `sha256:${string}`;
  scanner: SastScannerKind;
  artifactRef: string;
  attemptStage: string;
  attemptDeadlineAt: string;
  scannerRunStatus: string;
}

export interface ReserveSastArtifactIngressInput {
  ingestionId: string;
  envelopeDigest: `sha256:${string}`;
  idempotencyKey: string;
  expected: Readonly<SastArtifactIngressExpectedBinding>;
  declaredContentDigest: `sha256:${string}`;
  declaredByteSize: number;
  now: string;
}

export interface SastArtifactIngressReservation {
  kind: 'RESERVED' | 'REPLAY';
  ingestionId: string;
  state: SastArtifactIngestionState;
  receivedAt?: string;
}

export interface CompleteSastArtifactIngressInput {
  ingestionId: string;
  objectKey: string;
  observedContentDigest: `sha256:${string}`;
  observedByteSize: number;
  receivedAt: string;
}

export interface RejectSastArtifactIngressInput {
  ingestionId: string;
  reasonCode: string;
  observedContentDigest?: `sha256:${string}`;
  observedByteSize?: number;
  rejectedAt: string;
}

export interface AbortSastArtifactIngressInput {
  ingestionId: string;
  reasonCode: string;
  occurredAt: string;
}

export interface SastArtifactIngressRejectionAudit {
  expected: Readonly<SastArtifactIngressExpectedBinding>;
  certificateFingerprint: `sha256:${string}`;
  reasonCode: string;
  workloadIdentityValidated: boolean;
  occurredAt: string;
}

export class SastArtifactIngressReplayConflictError extends Error {
  constructor() {
    super('A scanner run already has a different artifact submission.');
    this.name = 'SastArtifactIngressReplayConflictError';
  }
}

export class SastArtifactIngressStateConflictError extends Error {
  constructor() {
    super('The artifact ingress lifecycle does not permit this transition.');
    this.name = 'SastArtifactIngressStateConflictError';
  }
}

export class SastArtifactIngressReservationRetryError extends Error {
  constructor() {
    super('Artifact ingress reservation must be retried.');
    this.name = 'SastArtifactIngressReservationRetryError';
  }
}

export abstract class SastArtifactIngressStore {
  abstract loadExpectedBinding(
    scanRequestId: string,
    scannerRunId: string
  ): Promise<SastArtifactIngressExpectedBinding | null>;

  abstract reserve(
    input: Readonly<ReserveSastArtifactIngressInput>
  ): Promise<SastArtifactIngressReservation>;

  abstract complete(
    input: Readonly<CompleteSastArtifactIngressInput>
  ): Promise<void>;

  abstract reject(
    input: Readonly<RejectSastArtifactIngressInput>
  ): Promise<void>;

  abstract abort(
    input: Readonly<AbortSastArtifactIngressInput>
  ): Promise<void>;

  abstract recordRejectedRequest(
    input: Readonly<SastArtifactIngressRejectionAudit>
  ): Promise<void>;
}
