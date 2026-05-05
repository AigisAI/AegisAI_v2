import { Injectable } from "@nestjs/common";
import { createEvidencePackMetadata } from "../../../../packages/shared/src";

import type {
  DeterministicScannerKind,
  MockScanPlaneRunResult,
  RunMockScanPlaneInput,
  RunSandboxScannersInput,
  SandboxScannerExecutionResult
} from "./scan-plane.types";
import type { EvidencePack, NormalizedFinding, ScannerRun } from "../../../../packages/shared/src";
import { ScannerSandboxAdapterService } from "./scanner-sandbox-adapter.service";

@Injectable()
export class ScanPlaneService {
  private readonly scannerRuns: ScannerRun[] = [];
  private readonly findings: NormalizedFinding[] = [];
  private readonly evidencePacks: EvidencePack[] = [];

  private scannerRunSequence = 0;
  private findingSequence = 0;
  private evidenceSequence = 0;

  constructor(private readonly scannerSandboxAdapter: ScannerSandboxAdapterService) {}

  runMockPipeline(input: RunMockScanPlaneInput): MockScanPlaneRunResult {
    const scanners: DeterministicScannerKind[] = ["OPENGREP", "TRIVY", "SYFT"];
    const scannerRuns = scanners.map((scanner) => this.createScannerRun(input, scanner));
    const opengrepRun = scannerRuns[0];
    const finding = this.createFinding(input, opengrepRun.id);
    const evidence = createEvidencePackMetadata({
      id: `evidence_${++this.evidenceSequence}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      byteSize: 512,
      expiresAt: "2026-04-19T00:00:00.000Z",
      redacted: true
    });

    this.scannerRuns.push(...scannerRuns);
    this.findings.push(finding);
    this.evidencePacks.push(evidence);

    return {
      scannerRuns,
      findings: [finding],
      evidencePacks: [evidence]
    };
  }

  runSandboxScanners(input: RunSandboxScannersInput): SandboxScannerExecutionResult {
    const adapterInvocations = this.scannerSandboxAdapter.buildInvocations(input);
    const scannerRuns = adapterInvocations.map((invocation) => ({
      id: `scanner_run_${++this.scannerRunSequence}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      scanner: invocation.scanner,
      scannerVersion: this.scannerSandboxAdapter.scannerVersion(
        invocation.scanner,
        input.scannerSetVersion
      ),
      status: "COMPLETED" as const,
      rawArtifactObjectKey: `${input.tenantId}/${input.scanRequestId}/raw/${invocation.scanner.toLowerCase()}.json`
    }));
    const evidence = createEvidencePackMetadata({
      id: `evidence_${++this.evidenceSequence}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      byteSize: 1024,
      expiresAt: "2026-04-19T00:00:00.000Z",
      redacted: true
    });

    this.scannerRuns.push(...scannerRuns);
    this.evidencePacks.push(evidence);

    return {
      scannerRuns,
      evidencePacks: [evidence],
      adapterInvocations
    };
  }

  listScannerRuns(tenantId: string, scanRequestId: string): ScannerRun[] {
    return this.scannerRuns.filter(
      (run) => run.tenantId === tenantId && run.scanRequestId === scanRequestId
    );
  }

  listFindings(tenantId: string, scanRequestId: string): NormalizedFinding[] {
    return this.findings.filter(
      (finding) => finding.tenantId === tenantId && finding.scanRequestId === scanRequestId
    );
  }

  listEvidencePacks(tenantId: string, scanRequestId: string): EvidencePack[] {
    return this.evidencePacks.filter(
      (evidence) => evidence.tenantId === tenantId && evidence.scanRequestId === scanRequestId
    );
  }

  private createScannerRun(input: RunMockScanPlaneInput, scanner: DeterministicScannerKind): ScannerRun {
    return {
      id: `scanner_run_${++this.scannerRunSequence}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      scanner,
      scannerVersion: `${scanner.toLowerCase()}-${input.scannerSetVersion}`,
      status: "COMPLETED",
      rawArtifactObjectKey: `${input.tenantId}/${input.scanRequestId}/raw/${scanner.toLowerCase()}.json`
    };
  }

  private createFinding(input: RunMockScanPlaneInput, scannerRunId: string): NormalizedFinding {
    return {
      id: `finding_${++this.findingSequence}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      scannerRunId,
      title: "Mock unsafe deserialization finding",
      severity: "HIGH",
      scannerProvenance: "OPENGREP",
      filePath: "src/main/java/App.java",
      lineStart: 42,
      lineEnd: 42,
      status: "OPEN"
    };
  }
}
