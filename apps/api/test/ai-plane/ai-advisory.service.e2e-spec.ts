import { AiAdvisoryService } from "../../src/ai-plane/ai-advisory.service";

import type { AiAdvisoryRequest } from "../../../../packages/shared/src";

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

  it("creates advisory-only detector planner output from normalized findings and redacted evidence", () => {
    const service = new AiAdvisoryService();

    const advisory = service.createAdvisory(request);

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

  it("rejects unredacted evidence and forbidden repository or credential payloads", () => {
    const service = new AiAdvisoryService();

    expect(() =>
      service.createAdvisory({
        ...request,
        evidence: {
          ...request.evidence,
          redacted: false
        }
      })
    ).toThrow("AI advisory input must use redacted evidence.");

    expect(() =>
      service.createAdvisory({
        ...request,
        normalizedFinding: {
          ...request.normalizedFinding,
          title: "fullRepository payload was supplied"
        }
      })
    ).toThrow("AI advisory input contains forbidden sensitive content.");
  });
});
