import { createHash, randomUUID } from "node:crypto";

import { BadRequestException, Injectable } from "@nestjs/common";
import { classifyRepositoryManifest, createEvidencePackMetadata, MAX_EVIDENCE_TTL_MS } from "@aegisai/shared";

import { ControlPlaneService } from "../control-plane/control-plane.service";
import type {
  DeterministicScannerKind,
  MockScanPlaneRunResult,
  RunMockScanPlaneInput
} from "./scan-plane.types";
import type { EvidencePack, NormalizedFinding, ScannerRun, ScanPlanningMetadata } from "@aegisai/shared";

@Injectable()
export class ScanPlaneService {
  private readonly scannerRuns: ScannerRun[] = [];
  private readonly findings: NormalizedFinding[] = [];
  private readonly evidencePacks: EvidencePack[] = [];
  private readonly resultsByScanKey = new Map<string, {
    manifestKey: string;
    result: MockScanPlaneRunResult;
  }>();

  constructor(private readonly controlPlane: ControlPlaneService) {}

  async runMockPipeline(input: RunMockScanPlaneInput): Promise<MockScanPlaneRunResult> {
    const scanRequest = await this.controlPlane.getScanRequest(input.tenantId, input.scanRequestId);
    if (scanRequest.scannerSetVersion !== input.scannerSetVersion) {
      throw new BadRequestException({
        errorCode: "SCANNER_SET_VERSION_MISMATCH",
        message: "Scanner set version must match the immutable scan request."
      });
    }

    let planning: ScanPlanningMetadata | undefined;
    try {
      planning = input.repositoryManifest === undefined
        ? undefined : classifyRepositoryManifest(input.repositoryManifest);
    } catch {
      throw new BadRequestException({
        errorCode: "INVALID_REPOSITORY_MANIFEST",
        message: "Repository manifest must contain bounded repository-relative paths only."
      });
    }
    const manifestKey = createHash("sha256").update(JSON.stringify(
      input.repositoryManifest === undefined ? null
        : [...new Set(input.repositoryManifest.files.map((file) => file.path))].sort()
    )).digest("hex");
    const scanKey = JSON.stringify([input.tenantId, input.scanRequestId]);
    const existingResult = this.resultsByScanKey.get(scanKey);
    if (existingResult) {
      if (existingResult.manifestKey !== manifestKey) {
        throw new BadRequestException({
          errorCode: "REPOSITORY_MANIFEST_MISMATCH",
          message: "Repository manifest must match the original scan run."
        });
      }
      return existingResult.result;
    }

    const scanners: DeterministicScannerKind[] = ["OPENGREP", "TRIVY", "SYFT"];
    const scannerRuns = scanners.map((scanner) => this.createScannerRun(input, scanner, planning));
    const opengrepRun = scannerRuns[0];
    const findings = planning?.scanProfile === "COMMON"
      ? [] : [this.createFinding(input, opengrepRun.id, planning)];
    const evidencePacks = findings.length === 0 ? [] : [createEvidencePackMetadata({
      id: `evidence_${randomUUID()}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      byteSize: 512,
      expiresAt: new Date(Date.now() + MAX_EVIDENCE_TTL_MS).toISOString(),
      redacted: true
    })];

    this.scannerRuns.push(...scannerRuns);
    this.findings.push(...findings);
    this.evidencePacks.push(...evidencePacks);

    const result = {
      scannerRuns,
      findings,
      evidencePacks,
      ...(planning ? { planning } : {})
    };
    this.resultsByScanKey.set(scanKey, { manifestKey, result });

    return result;
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

  private createScannerRun(
    input: RunMockScanPlaneInput,
    scanner: DeterministicScannerKind,
    planning?: ScanPlanningMetadata
  ): ScannerRun {
    return {
      id: `scanner_run_${randomUUID()}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      scanner,
      scannerVersion: `${scanner.toLowerCase()}-${input.scannerSetVersion}`,
      status: "COMPLETED",
      ...(planning ? { planning } : {}),
      rawArtifactObjectKey: [
        input.tenantId,
        input.scanRequestId,
        "raw",
        `${scanner.toLowerCase()}.json`
      ]
        .map((component) => encodeURIComponent(component))
        .join("/")
    };
  }

  private createFinding(
    input: RunMockScanPlaneInput,
    scannerRunId: string,
    planning?: ScanPlanningMetadata
  ): NormalizedFinding {
    return {
      id: `finding_${randomUUID()}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      scannerRunId,
      title: "Mock unsafe deserialization finding",
      severity: "HIGH",
      scannerProvenance: "OPENGREP",
      filePath: "src/main/java/App.java",
      lineStart: 42,
      lineEnd: 42,
      status: "OPEN",
      ...(planning?.scanProfile === "JAVA_DETAILED"
        ? { language: "JAVA" as const, scanProfile: "JAVA_DETAILED" as const } : {})
    };
  }
}
