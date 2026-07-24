import type {
  SastScannerInvocation,
  SastScannerProcessObservation,
  SastScannerRepositoryManifest,
  SastScannerWrapperExecutionRequest,
  SastSignedSandboxCleanupObservation
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import { retryableInfrastructureFailure } from './scanner-runtime.errors';

export interface ScannerSandboxRuntimeOperation {
  request: Readonly<SastScannerWrapperExecutionRequest>;
  invocation: Readonly<SastScannerInvocation>;
  attemptDeadlineAt: string;
  signal: AbortSignal;
}

export interface ScannerSandboxCleanupOperation {
  request: Readonly<SastScannerWrapperExecutionRequest>;
  cleanupDeadlineAt: string;
  signal: AbortSignal;
}

export abstract class ScannerSandboxRuntimeProvider {
  abstract readRepositoryManifest(
    operation: ScannerSandboxRuntimeOperation
  ): Promise<SastScannerRepositoryManifest>;

  abstract executeScanner(
    operation: ScannerSandboxRuntimeOperation
  ): Promise<SastScannerProcessObservation>;

  abstract cleanup(
    operation: ScannerSandboxCleanupOperation
  ): Promise<SastSignedSandboxCleanupObservation>;
}

@Injectable()
export class UnavailableScannerSandboxRuntimeProvider
  extends ScannerSandboxRuntimeProvider
{
  readRepositoryManifest(): Promise<SastScannerRepositoryManifest> {
    return Promise.reject(this.unavailable());
  }

  executeScanner(): Promise<SastScannerProcessObservation> {
    return Promise.reject(this.unavailable());
  }

  cleanup(): Promise<SastSignedSandboxCleanupObservation> {
    return Promise.reject(this.unavailable());
  }

  private unavailable(): Error {
    return retryableInfrastructureFailure(
      'SCANNER_SANDBOX_PROVIDER_UNAVAILABLE',
      'No live microVM scanner sandbox provider is installed.'
    );
  }
}
