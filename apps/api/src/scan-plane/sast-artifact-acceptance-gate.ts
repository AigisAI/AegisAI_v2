import type {
  SastArtifactDispositionScope,
  SastProfileId,
  SastScannerKind
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export interface SastArtifactAcceptanceGateInput {
  scope: Readonly<SastArtifactDispositionScope>;
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
  /**
   * T049 will provide the authoritative kill-switch implementation. Until then
   * an explicit adapter must be installed; absence is intentionally fail closed.
   */
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
  extends SastArtifactAcceptanceGate
{
  evaluate(): Promise<SastArtifactAcceptanceGateDecision> {
    return Promise.reject(
      new SastArtifactAcceptanceGateUnavailableError()
    );
  }
}
