import type {
  SastFailureClass,
  SastScannerExecutionRecord,
  SastScannerInvocation,
  SastScannerRuntimeAuditSignal,
  SastScannerWrapperExecutionRequest,
  SastSignedSandboxCleanupObservation
} from '@aegisai/shared';

export type PersistedSastAttemptStage =
  | 'VALIDATING'
  | 'SCANNING'
  | 'CLEANUP_PENDING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CLEANUP_FAILED';

export interface FinishSastAttemptInput {
  request: Readonly<SastScannerWrapperExecutionRequest>;
  stage: Extract<
    PersistedSastAttemptStage,
    'COMPLETED' | 'FAILED' | 'CLEANUP_FAILED'
  >;
  failureClass?: SastFailureClass;
  reasonCode?: string;
  retryEligible: boolean;
  cleanup?: Readonly<SastSignedSandboxCleanupObservation>;
  finalAuditEventId: string;
  completedAt: string;
}

export abstract class SastScannerRuntimeStore {
  abstract beginAttempt(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    startedAt: string
  ): Promise<void>;

  abstract markStage(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    stage: Extract<
      PersistedSastAttemptStage,
      'SCANNING' | 'CLEANUP_PENDING'
    >
  ): Promise<void>;

  abstract beginScannerRun(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    scannerRunId: string,
    invocation: Readonly<SastScannerInvocation>,
    startedAt: string
  ): Promise<void>;

  abstract recordScannerRun(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    record: Readonly<SastScannerExecutionRecord>
  ): Promise<void>;

  abstract failScannerRun(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    scannerRunId: string,
    invocation: Readonly<SastScannerInvocation>,
    reasonCode: string,
    completedAt: string
  ): Promise<void>;

  abstract recordAuditSignal(
    signal: Readonly<SastScannerRuntimeAuditSignal>
  ): Promise<void>;

  abstract isCredentialHandoffTerminal(
    request: Readonly<SastScannerWrapperExecutionRequest>
  ): Promise<boolean>;

  abstract failOverdueAttempts(referenceTime: string): Promise<number>;

  abstract finishAttempt(input: FinishSastAttemptInput): Promise<void>;
}
