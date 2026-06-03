import { AiAdvisoryService } from "../../src/ai-plane/ai-advisory.service";

import type { AiAdvisoryRequest, AiInferenceResponse } from "../../../../packages/shared/src";

describe("AiAdvisoryService", () => {
  const request: AiAdvisoryRequest = {
    tenantId: "tenant_ai",
    scanRequestId: "scan_request_1",
    findingId: "finding_1",
    normalizedFinding: {
      id: "finding_1",
      tenantId: "tenant_ai",
      scanRequestId: "scan_request_1",
      scannerRunId: "scanner_run_1",
      title: "Unsafe deserialization",
      severity: "HIGH",
      scannerProvenance: "OPENGREP",
      filePath: "src/App.java",
      lineStart: 42,
      status: "OPEN"
    },
    evidence: {
      id: "evidence_1",
      tenantId: "tenant_ai",
      scanRequestId: "scan_request_1",
      classification: "SHORT_LIVED_EVIDENCE",
      objectKey: "tenant_ai/scan_request_1/evidence/evidence_1.json",
      expiresAt: "2026-04-19T00:00:00.000Z",
      byteSize: 512,
      redacted: true
    },
    modelVersion: "detector-planner-mock-v1"
  };

  it("creates advisory-only detector planner output from normalized findings and redacted evidence", async () => {
    const service = new AiAdvisoryService({
      get: jest.fn().mockReturnValue("false")
    } as never);

    const advisory = await service.createAdvisory(request);

    expect(advisory).toEqual(
      expect.objectContaining({
        tenantId: "tenant_ai",
        scanRequestId: "scan_request_1",
        findingId: "finding_1",
        modelVersion: "detector-planner-mock-v1",
        advisoryOnly: true,
        redactedEvidenceOnly: true,
        confidence: expect.any(Number)
      })
    );
    expect(advisory.detectorSignals).toEqual(expect.arrayContaining(["SCANNER_CONFIRMED"]));
    expect(advisory.plannerSteps).toEqual(expect.arrayContaining(["Review scanner evidence before remediation."]));
    expect(JSON.stringify(advisory)).not.toMatch(
      /enforcementAction|blockRequested|policyOverride|findingOverride|accessToken|refreshToken|tokenValue|secretValue|fullRepository|sourceArchive|rawScannerPayload/i
    );
  });

  it("rejects unredacted evidence and forbidden repository or credential payloads", async () => {
    const service = new AiAdvisoryService({
      get: jest.fn().mockReturnValue("false")
    } as never);

    await expect(
      service.createAdvisory({
        ...request,
        evidence: {
          ...request.evidence,
          redacted: false
        }
      })
    ).rejects.toThrow("AI advisory input must use redacted evidence.");

    await expect(
      service.createAdvisory({
        ...request,
        normalizedFinding: {
          ...request.normalizedFinding,
          title: "fullRepository payload was supplied"
        }
      })
    ).rejects.toThrow("AI advisory input contains forbidden sensitive content.");
  });

  it("uses runtime detector planner output when internal AI runtime is enabled", async () => {
    const runtimeResponse: AiInferenceResponse = {
      requestId: "ai_request_1",
      tenantId: "tenant_ai",
      scanRequestId: "scan_request_1",
      advisoryOnly: true,
      detectorAdvisories: [
        {
          findingId: "finding_1",
          confidence: 0.83,
          rationale: "Runtime detector advisory.",
          signals: ["SCANNER_CONFIRMED", "MODEL_TRIAGED"]
        }
      ],
      plannerAdvisories: [
        {
          findingId: "finding_1",
          action: "Review scanner evidence before remediation.",
          rationale: "Runtime planner advisory.",
          priority: "high"
        }
      ],
      modelMetadata: {
        provider: "deterministic",
        model: "detector-planner-runtime",
        version: "2026-05-26"
      },
      fallback: {
        used: true,
        reason: "provider not configured"
      },
      latencyMs: 11,
      createdAt: "2026-05-26T00:00:00.000Z"
    };
    const runtime = {
      createAdvisory: jest.fn().mockResolvedValue(runtimeResponse)
    };
    const service = new AiAdvisoryService(
      {
        get: jest.fn((key: string) => (key === "USE_INTERNAL_AI" ? "true" : undefined))
      } as never,
      runtime as never
    );

    const advisory = await service.createAdvisory({
      ...request,
      modelVersion: "detector-planner-runtime-v1"
    });

    expect(runtime.createAdvisory).toHaveBeenCalledWith(
      expect.objectContaining({
        tenantId: "tenant_ai",
        findingId: "finding_1",
        evidence: expect.objectContaining({
          redacted: true
        })
      })
    );
    expect(advisory).toEqual(
      expect.objectContaining({
        modelVersion: "2026-05-26",
        detectorSignals: ["SCANNER_CONFIRMED", "MODEL_TRIAGED"],
        plannerSteps: ["Review scanner evidence before remediation."],
        confidence: 0.83,
        advisoryOnly: true,
        redactedEvidenceOnly: true,
        detectorAdvisories: runtimeResponse.detectorAdvisories,
        plannerAdvisories: runtimeResponse.plannerAdvisories,
        modelMetadata: runtimeResponse.modelMetadata,
        fallback: runtimeResponse.fallback
      })
    );
    expect(JSON.stringify(advisory)).not.toMatch(
      /enforcementAction|blockRequested|policyOverride|findingOverride|waiverApplied|staleSuppressed/i
    );
  });

  it("persists advisory metadata without granting finding or policy authority", async () => {
    const createdAt = new Date("2026-05-26T00:00:00.000Z");
    const prisma = {
      aiAdvisoryMetadata: {
        create: jest.fn(async ({ data }) => ({
          ...data,
          createdAt,
          updatedAt: createdAt
        })),
        findFirst: jest.fn(async ({ where }) => ({
          id: where.id,
          tenantId: where.tenantId,
          scanRequestId: "scan_request_1",
          findingId: "finding_1",
          modelVersion: "detector-planner-mock-v1",
          advisoryOnly: true,
          redactedEvidenceOnly: true,
          detectorSignals: ["SCANNER_CONFIRMED", "SEVERITY_HIGH", "PROVENANCE_OPENGREP"],
          plannerSteps: [
            "Review scanner evidence before remediation.",
            "Prioritize owner review before merging affected changes.",
            "Apply remediation outside the AI advisory boundary."
          ],
          confidence: 0.74,
          detectorAdvisories: null,
          plannerAdvisories: null,
          modelMetadata: null,
          fallback: null,
          createdAt,
          updatedAt: createdAt
        }))
      }
    };
    const service = new AiAdvisoryService(
      {
        get: jest.fn().mockReturnValue("false")
      } as never,
      undefined,
      prisma as never
    );

    const advisory = await service.createAdvisory(request);

    expect(prisma.aiAdvisoryMetadata.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        id: advisory.id,
        tenantId: "tenant_ai",
        scanRequestId: "scan_request_1",
        findingId: "finding_1",
        modelVersion: "detector-planner-mock-v1",
        advisoryOnly: true,
        redactedEvidenceOnly: true,
        confidence: 0.74
      })
    });
    expect(JSON.stringify(prisma.aiAdvisoryMetadata.create.mock.calls)).not.toMatch(
      /enforcementAction|blockRequested|policyOverride|findingOverride|waiverApplied|staleSuppressed/i
    );

    const stored = await service.getAdvisory("tenant_ai", advisory.id);

    expect(prisma.aiAdvisoryMetadata.findFirst).toHaveBeenCalledWith({
      where: {
        id: advisory.id,
        tenantId: "tenant_ai"
      }
    });
    expect(stored).toEqual(
      expect.objectContaining({
        id: advisory.id,
        tenantId: "tenant_ai",
        scanRequestId: "scan_request_1",
        findingId: "finding_1",
        advisoryOnly: true,
        redactedEvidenceOnly: true,
        detectorSignals: ["SCANNER_CONFIRMED", "SEVERITY_HIGH", "PROVENANCE_OPENGREP"]
      })
    );
    expect(JSON.stringify(stored)).not.toMatch(
      /enforcementAction|blockRequested|policyOverride|findingOverride|waiverApplied|staleSuppressed/i
    );
  });
});
