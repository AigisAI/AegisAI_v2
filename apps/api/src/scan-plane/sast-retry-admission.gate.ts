import type {
  SastScannerWrapperExecutionRequest
} from '@aegisai/shared';

export type SastRetryAdmissionVerification =
  | {
      outcome: 'AUTHORIZED';
      startedAt: string;
    }
  | {
      outcome: 'REJECTED';
    };

export abstract class SastRetryAdmissionGate {
  abstract authorize(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    decidedAt: string
  ): Promise<SastRetryAdmissionVerification>;
}

export class UnavailableSastRetryAdmissionGate
  extends SastRetryAdmissionGate {
  async authorize(): Promise<SastRetryAdmissionVerification> {
    return { outcome: 'REJECTED' };
  }
}
