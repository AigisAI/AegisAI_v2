import type {
  SastScannerWrapperExecutionRequest
} from '@aegisai/shared';

export type SastRetryAdmissionVerification =
  | 'AUTHORIZED'
  | 'REJECTED';

export abstract class SastRetryAdmissionGate {
  abstract authorize(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    decidedAt: string
  ): Promise<SastRetryAdmissionVerification>;
}

export class UnavailableSastRetryAdmissionGate
  extends SastRetryAdmissionGate {
  async authorize(): Promise<SastRetryAdmissionVerification> {
    return 'REJECTED';
  }
}
