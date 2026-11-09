import type {
  EvidencePack,
  NormalizedFinding,
  RepositoryManifest,
  ScanPlanningMetadata,
  ScannerRun,
  ScannerKind
} from "@aegisai/shared";

export interface RunMockScanPlaneInput {
  tenantId: string;
  scanRequestId: string;
  scannerSetVersion: string;
  repositoryManifest?: RepositoryManifest;
}

export interface MockScanPlaneRunResult {
  scannerRuns: ScannerRun[];
  findings: NormalizedFinding[];
  evidencePacks: EvidencePack[];
  planning?: ScanPlanningMetadata;
}

export type DeterministicScannerKind = Exclude<ScannerKind, "MOCK">;
