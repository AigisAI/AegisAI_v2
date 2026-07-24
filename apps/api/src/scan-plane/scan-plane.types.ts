import type {
  EvidencePack,
  NormalizedFinding,
  ScannerRun,
  ScannerKind
} from '@aegisai/shared';

export interface RunMockScanPlaneInput {
  tenantId: string;
  scanRequestId: string;
  scannerSetVersion: string;
}

export interface MockScanPlaneRunResult {
  scannerRuns: ScannerRun[];
  findings: NormalizedFinding[];
  evidencePacks: EvidencePack[];
}

export interface ScannerRunView {
  id: string;
  tenantId: string;
  scanRequestId: string;
  scanner: ScannerKind;
  scannerVersion: string;
  status:
    | ScannerRun['status']
    | 'QUARANTINED'
    | 'KILLED';
  required: boolean | null;
  scannerImageDigest: string | null;
  wrapperDigest: string | null;
  ruleBundleDigest: string | null;
  databaseDigest: string | null;
  scannerSetDigest: string | null;
  profileId: string | null;
  profileDigest: string | null;
  exitCode: number | null;
  terminationSignal: string | null;
  timedOut: boolean | null;
  outputLimitExceeded: boolean | null;
  durationMilliseconds: number | null;
  startedAt: string | null;
  completedAt: string | null;
}

export type DeterministicScannerKind = Exclude<ScannerKind, "MOCK">;
