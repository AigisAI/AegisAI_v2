import type {
  EvidencePack,
  NormalizedFinding,
  ScannerRun,
  ScannerKind
} from "../../../../packages/shared/src";

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

export type DeterministicScannerKind = Exclude<ScannerKind, "MOCK">;
