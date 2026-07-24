import { BadRequestException, GoneException, Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  createEvidencePackMetadata,
  MAX_EVIDENCE_TTL_MS,
  type SastScannerRuntimeExecutionResult,
  type SastScannerWrapperExecutionRequest
} from '@aegisai/shared';

import { ControlPlaneService } from '../control-plane/control-plane.service';
import { isMockAnalysisFixtureEnabled } from '../client/analysis/analysis-fixture.policy';
import { PrismaService } from '../prisma/prisma.service';
import type {
  DeterministicScannerKind,
  MockScanPlaneRunResult,
  RunMockScanPlaneInput,
  ScannerRunView,
} from "./scan-plane.types";
import type {
  EvidenceAccessRequest,
  EvidencePack,
  NormalizedFinding,
  ScannerRun
} from '@aegisai/shared';
import { EvidenceObjectStorageService } from "./evidence-object-storage.service";
import { SastScannerRuntimeService } from './sast-scanner-runtime.service';

@Injectable()
export class ScanPlaneService {
  private readonly scannerRuns: ScannerRun[] = [];
  private readonly findings: NormalizedFinding[] = [];
  private readonly evidencePacks: EvidencePack[] = [];
  private readonly completedPipelines = new Map<string, MockScanPlaneRunResult>();

  constructor(
    private readonly sastScannerRuntime: SastScannerRuntimeService,
    private readonly evidenceObjectStorage: EvidenceObjectStorageService,
    private readonly controlPlaneService: ControlPlaneService,
    private readonly prisma: PrismaService
  ) {}

  async runMockPipeline(input: RunMockScanPlaneInput): Promise<MockScanPlaneRunResult> {
    if (!isMockAnalysisFixtureEnabled()) {
      throw new NotFoundException('Mock scan pipeline is a test-only fixture.');
    }
    await this.assertScanScope(input);
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

  async runSandboxScanners(
    input: SastScannerWrapperExecutionRequest
  ): Promise<SastScannerRuntimeExecutionResult> {
    return this.sastScannerRuntime.execute(input);
  }

  async listScannerRuns(
    tenantId: string,
    scanRequestId: string
  ): Promise<ScannerRunView[]> {
    if (isMockAnalysisFixtureEnabled()) {
      return this.scannerRuns
        .filter(
          (run) =>
            run.tenantId === tenantId &&
            run.scanRequestId === scanRequestId
        )
        .map((run) => ({
          id: run.id,
          tenantId: run.tenantId,
          scanRequestId: run.scanRequestId,
          scanner: run.scanner,
          scannerVersion: run.scannerVersion,
          status: run.status,
          required: true,
          scannerImageDigest: null,
          wrapperDigest: null,
          ruleBundleDigest: null,
          databaseDigest: null,
          scannerSetDigest: null,
          profileId: null,
          profileDigest: null,
          exitCode: null,
          terminationSignal: null,
          timedOut: null,
          outputLimitExceeded: null,
          durationMilliseconds: null,
          startedAt: null,
          completedAt: null
        }));
    }
    const scannerRuns = await this.prisma.scannerRun.findMany({
      where: { tenantId, scanRequestId },
      select: {
        id: true,
        tenantId: true,
        scanRequestId: true,
        scanner: true,
        scannerVersion: true,
        status: true,
        required: true,
        scannerImageDigest: true,
        wrapperDigest: true,
        ruleBundleDigest: true,
        databaseDigest: true,
        scannerSetDigest: true,
        profileId: true,
        profileDigest: true,
        exitCode: true,
        terminationSignal: true,
        timedOut: true,
        outputLimitExceeded: true,
        durationMilliseconds: true,
        startedAt: true,
        completedAt: true
      },
      orderBy: [{ startedAt: 'asc' }, { id: 'asc' }]
    });
    return scannerRuns.map((run) => ({
      ...run,
      startedAt: run.startedAt?.toISOString() ?? null,
      completedAt: run.completedAt?.toISOString() ?? null
    }));
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

  private async assertScanScope(input: RunMockScanPlaneInput): Promise<void> {
    const scanRequest = await this.controlPlaneService.getScanRequest(
      input.tenantId,
      input.scanRequestId
    );
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
