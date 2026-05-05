import type {
  EvidencePack,
  IsolationClass,
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

export interface RunSandboxScannersInput {
  tenantId: string;
  scanRequestId: string;
  scannerSetVersion: string;
  workspaceRef: string;
  isolationClass: IsolationClass;
  timeoutSeconds: number;
}

export interface ScannerSandboxPolicy {
  isolationClass: IsolationClass;
  networkEgress: false;
  readOnlyWorkspace: true;
  packageInstallAllowed: false;
  buildAllowed: false;
  customerCodeExecutionAllowed: false;
}

export interface ScannerAdapterInvocation {
  scanner: DeterministicScannerKind;
  command: string;
  args: string[];
  sandbox: ScannerSandboxPolicy;
}

export interface SandboxScannerExecutionResult {
  scannerRuns: ScannerRun[];
  evidencePacks: EvidencePack[];
  adapterInvocations: ScannerAdapterInvocation[];
}
