import { BadRequestException, GoneException, Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { createEvidencePackMetadata, MAX_EVIDENCE_TTL_MS } from '@aegisai/shared';

import { ControlPlaneService } from '../control-plane/control-plane.service';
import type {
  DeterministicScannerKind,
  MockScanPlaneRunResult,
  RunMockScanPlaneInput,
  RunSandboxScannersInput,
  SandboxScannerExecutionResult
} from "./scan-plane.types";
import type {
  EvidenceAccessRequest,
  EvidencePack,
  NormalizedFinding,
  ScannerRun
} from '@aegisai/shared';
import { EvidenceObjectStorageService } from "./evidence-object-storage.service";
import { ScannerSandboxAdapterService } from "./scanner-sandbox-adapter.service";

@Injectable()
export class ScanPlaneService {
  private readonly scannerRuns: ScannerRun[] = [];
  private readonly findings: NormalizedFinding[] = [];
  private readonly evidencePacks: EvidencePack[] = [];
  private readonly completedPipelines = new Map<string, MockScanPlaneRunResult>();
  private readonly completedSandboxRuns = new Map<string, SandboxScannerExecutionResult>();

  constructor(
    private readonly scannerSandboxAdapter: ScannerSandboxAdapterService,
    private readonly evidenceObjectStorage: EvidenceObjectStorageService,
    private readonly controlPlaneService: ControlPlaneService
  ) {}

  runMockPipeline(input: RunMockScanPlaneInput): MockScanPlaneRunResult {
    this.assertScanScope(input);
    const pipelineKey = `mock:${input.tenantId}:${input.scanRequestId}:${input.scannerSetVersion}`;
    const completedPipeline = this.completedPipelines.get(pipelineKey);
    if (completedPipeline) {
      return completedPipeline;
    }

    const scanners: DeterministicScannerKind[] = ["OPENGREP", "TRIVY", "SYFT"];
    const scannerRuns = scanners.map((scanner) => this.createScannerRun(input, scanner));
    const opengrepRun = scannerRuns[0];
    const finding = this.createFinding(input, opengrepRun.id);
    const evidence = createEvidencePackMetadata({
      id: `evidence_${randomUUID()}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      byteSize: 512,
      expiresAt: new Date(Date.now() + MAX_EVIDENCE_TTL_MS).toISOString(),
      redacted: true
    });

    this.scannerRuns.push(...scannerRuns);
    this.findings.push(finding);
    this.evidencePacks.push(evidence);

    const result = {
      scannerRuns,
      findings: [finding],
      evidencePacks: [evidence]
    };
    this.completedPipelines.set(pipelineKey, result);

    return result;
  }

  runSandboxScanners(input: RunSandboxScannersInput): SandboxScannerExecutionResult {
    this.assertScanScope(input);
    const pipelineKey = `sandbox:${input.tenantId}:${input.scanRequestId}:${input.scannerSetVersion}`;
    const completedPipeline = this.completedSandboxRuns.get(pipelineKey);
    if (completedPipeline) {
      return completedPipeline;
    }

    const adapterInvocations = this.scannerSandboxAdapter.buildInvocations(input);
    const scannerRuns = adapterInvocations.map((invocation) => ({
      id: `scanner_run_${randomUUID()}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      scanner: invocation.scanner,
      scannerVersion: this.scannerSandboxAdapter.scannerVersion(
        invocation.scanner,
        input.scannerSetVersion
      ),
      status: "COMPLETED" as const,
      rawArtifactObjectKey: this.buildRawArtifactObjectKey(
        input.tenantId,
        input.scanRequestId,
        invocation.scanner
      )
    }));
    const evidence = createEvidencePackMetadata({
      id: `evidence_${randomUUID()}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      byteSize: 1024,
      expiresAt: new Date(Date.now() + MAX_EVIDENCE_TTL_MS).toISOString(),
      redacted: true
    });

    this.scannerRuns.push(...scannerRuns);
    this.evidencePacks.push(evidence);

    const result = {
      scannerRuns,
      evidencePacks: [evidence],
      adapterInvocations
    };
    this.completedSandboxRuns.set(pipelineKey, result);

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

  async requestEvidenceAccess(input: {
    evidencePackId: string;
    tenantId: string;
    scanRequestId: string;
  }): Promise<EvidenceAccessRequest> {
    const evidencePack = this.evidencePacks.find(
      (evidence) =>
        evidence.id === input.evidencePackId &&
        evidence.tenantId === input.tenantId &&
        evidence.scanRequestId === input.scanRequestId
    );

    if (!evidencePack) {
      throw new NotFoundException("Evidence pack was not found for tenant and scan request.");
    }

    if (new Date(evidencePack.expiresAt).getTime() <= Date.now()) {
      throw new GoneException('Evidence pack has expired.');
    }

    await this.evidenceObjectStorage.write({
      objectKey: evidencePack.objectKey,
      payload: {
        evidencePackId: evidencePack.id,
        tenantId: evidencePack.tenantId,
        scanRequestId: evidencePack.scanRequestId,
        classification: evidencePack.classification,
        expiresAt: evidencePack.expiresAt,
        byteSize: evidencePack.byteSize,
        redacted: true,
        accessMode: "METADATA_ONLY"
      }
    });

    return {
      evidencePackId: evidencePack.id,
      tenantId: evidencePack.tenantId,
      scanRequestId: evidencePack.scanRequestId,
      objectKey: evidencePack.objectKey,
      expiresAt: evidencePack.expiresAt,
      accessMode: "METADATA_ONLY",
      redacted: true,
      requestedAt: new Date().toISOString()
    };
  }

  listExpiredEvidencePacks(referenceTime: Date): EvidencePack[] {
    return this.evidencePacks.filter((evidence) => new Date(evidence.expiresAt) <= referenceTime);
  }

  removeEvidencePack(evidencePackId: string): void {
    const evidenceIndex = this.evidencePacks.findIndex((evidence) => evidence.id === evidencePackId);

    if (evidenceIndex >= 0) {
      this.evidencePacks.splice(evidenceIndex, 1);
    }
  }

  private createScannerRun(input: RunMockScanPlaneInput, scanner: DeterministicScannerKind): ScannerRun {
    return {
      id: `scanner_run_${randomUUID()}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      scanner,
      scannerVersion: `${scanner.toLowerCase()}-${input.scannerSetVersion}`,
      status: "COMPLETED",
      rawArtifactObjectKey: this.buildRawArtifactObjectKey(
        input.tenantId,
        input.scanRequestId,
        scanner
      )
    };
  }

  private createFinding(input: RunMockScanPlaneInput, scannerRunId: string): NormalizedFinding {
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
      status: "OPEN"
    };
  }

  private assertScanScope(input: RunMockScanPlaneInput): void {
    const scanRequest = this.controlPlaneService.getScanRequest(input.tenantId, input.scanRequestId);
    if (scanRequest.scannerSetVersion !== input.scannerSetVersion) {
      throw new BadRequestException('Scanner set version does not match the immutable scan request.');
    }
  }

  private buildRawArtifactObjectKey(
    tenantId: string,
    scanRequestId: string,
    scanner: DeterministicScannerKind
  ): string {
    return [
      encodeURIComponent(tenantId),
      encodeURIComponent(scanRequestId),
      'raw',
      `${scanner.toLowerCase()}.json`
    ].join('/');
  }
}
