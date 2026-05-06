import { PolicyEngineService } from "../../src/policy/policy-engine.service";

import type { NormalizedFinding } from "../../../../packages/shared/src";

describe("PolicyEngineService", () => {
  const highFinding: NormalizedFinding = {
    id: "finding_high",
    tenantId: "tenant_policy",
    scanRequestId: "scan_request_1",
    scannerRunId: "scanner_run_1",
    title: "Unsafe deserialization",
    severity: "HIGH",
    scannerProvenance: "OPENGREP",
    filePath: "src/App.java",
    lineStart: 42,
    status: "OPEN"
  };

  it("creates deterministic policy decisions from scanner findings and coverage", () => {
    const service = new PolicyEngineService();

    const decision = service.evaluate({
      tenantId: "tenant_policy",
      scanRequestId: "scan_request_1",
      finding: highFinding,
      scanLane: "DEEP",
      scannerCoverage: ["OPENGREP"],
      aiAdvisory: {
        visible: true,
        suggestedAction: "BLOCK"
      }
    });

    expect(decision).toEqual(
      expect.objectContaining({
        tenantId: "tenant_policy",
        scanRequestId: "scan_request_1",
        findingId: "finding_high",
        enforcementAction: "WARN",
        commentAllowed: true,
        dashboardVisible: true,
        ticketRequested: false,
        blockRequested: false,
        waiverApplied: false,
        staleSuppressed: false,
        aiAdvisoryVisible: true,
        requiredCoverage: ["OPENGREP", "TRIVY", "SYFT"]
      })
    );
    expect(decision.reasonCodes).toEqual(
      expect.arrayContaining(["SEVERITY_HIGH", "MISSING_REQUIRED_SCANNER_COVERAGE"])
    );
  });

  it("blocks critical scanner findings without using AI as the policy authority", () => {
    const service = new PolicyEngineService();

    const decision = service.evaluate({
      tenantId: "tenant_policy",
      scanRequestId: "scan_request_2",
      finding: {
        ...highFinding,
        id: "finding_critical",
        scanRequestId: "scan_request_2",
        severity: "CRITICAL"
      },
      scanLane: "FAST",
      scannerCoverage: ["OPENGREP", "TRIVY", "SYFT"],
      aiAdvisory: {
        visible: true,
        suggestedAction: "DASHBOARD_ONLY"
      }
    });

    expect(decision.enforcementAction).toBe("BLOCK");
    expect(decision.blockRequested).toBe(true);
    expect(decision.aiAdvisoryVisible).toBe(true);
    expect(decision.reasonCodes).toEqual(expect.arrayContaining(["SEVERITY_CRITICAL"]));
  });
});
