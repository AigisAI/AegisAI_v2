import type {
  SastArtifactDispositionScope,
  SastProfileId,
  SastScanPlan,
  SastScannerKind
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export interface SastArtifactAcceptanceGateInput {
  scope: Readonly<SastArtifactDispositionScope>;
  plan: Readonly<SastScanPlan>;
  scanner: SastScannerKind;
  scannerVersion: string;
  scannerImageDigest: `sha256:${string}`;
  validationResultDigest: `sha256:${string}`;
  scannerSetDigest: `sha256:${string}`;
  ruleBundleDigest?: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  evaluatedAt: string;
}

export interface SastArtifactAcceptanceGateDecision {
  outcome: 'ALLOW' | 'DENY';
  controlRef: string;
  evaluatedAt: string;
  reasonCode?: string;
}

export abstract class SastArtifactAcceptanceGate {
  abstract evaluate(
    input: Readonly<SastArtifactAcceptanceGateInput>
  ): Promise<SastArtifactAcceptanceGateDecision>;
}

/**
 * Independent Data/Security Plane authority that decides whether a validated
 * object may become accepted. Runtime safety gates compose around this port;
 * they never replace its fail-closed production default.
 */
export abstract class SastArtifactAcceptanceAuthority {
  abstract evaluate(
    input: Readonly<SastArtifactAcceptanceGateInput>
  ): Promise<SastArtifactAcceptanceGateDecision>;
}

export class SastArtifactAcceptanceGateUnavailableError extends Error {
  constructor() {
    super('No production SAST artifact acceptance gate is installed.');
    this.name = 'SastArtifactAcceptanceGateUnavailableError';
  }
}

@Injectable()
export class UnavailableSastArtifactAcceptanceGate
  extends SastArtifactAcceptanceAuthority
{
  evaluate(): Promise<SastArtifactAcceptanceGateDecision> {
    return Promise.reject(
      new SastArtifactAcceptanceGateUnavailableError()
    );
  }
}
