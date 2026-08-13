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

  it("creates deterministic policy decisions from scanner findings and coverage", async () => {
    const verifier = authorityVerifier(true);
    const store = policyStore();
    const service = new PolicyEngineService(
      store as never,
      verifier as never
    );

    const decision = await service.evaluate({
      tenantId: "tenant_policy",
      scanRequestId: "scan_request_1",
      finding: highFinding,
      scanLane: "DEEP",
      scannerCoverage: ["OPENGREP"],
      aiAdvisory: policyReference()
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
    expect(verifier.verifyPolicyReference).toHaveBeenCalledWith({
      tenantId: 'tenant_policy',
      normalizedFindingId: 'finding_high',
      reference: policyReference()
    });
    expect(store.create).toHaveBeenCalledTimes(1);
  });

  it("blocks critical scanner findings without using AI as the policy authority", async () => {
    const service = new PolicyEngineService(
      policyStore() as never,
      authorityVerifier(true) as never
    );

    const decision = await service.evaluate({
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
      aiAdvisory: policyReference()
    });

    expect(decision.enforcementAction).toBe("BLOCK");
    expect(decision.blockRequested).toBe(true);
    expect(decision.aiAdvisoryVisible).toBe(true);
    expect(decision.reasonCodes).toEqual(expect.arrayContaining(["SEVERITY_CRITICAL"]));
  });

  it('rejects suggested actions and unknown authority fields before policy evaluation', async () => {
    const verifier = authorityVerifier(true);
    const service = new PolicyEngineService(
      policyStore() as never,
      verifier as never
    );

    await expect(
      service.evaluate({
        tenantId: 'tenant_policy',
        scanRequestId: 'scan_request_1',
        finding: highFinding,
        scanLane: 'DEEP',
        scannerCoverage: ['OPENGREP', 'TRIVY', 'SYFT'],
        aiAdvisory: {
          ...policyReference(),
          suggestedAction: 'BLOCK',
          findingStatus: 'FIXED'
        } as never
      })
    ).rejects.toThrow('AI advisory reference is invalid or unavailable.');
    expect(verifier.verifyPolicyReference).not.toHaveBeenCalled();
  });
});

function policyReference() {
  return {
    version: 'sast-ai-advisory-policy-reference-v1' as const,
    advisoryId: `sast-ai-advisory://${'a'.repeat(64)}`,
    authorityProofId: `sast-ai-authority-proof://${'b'.repeat(64)}`,
    authorityProofDigest: `sha256:${'c'.repeat(64)}` as const,
    advisoryOnly: true as const
  };
}

function authorityVerifier(result: boolean) {
  return {
    verifyPolicyReference: jest.fn().mockResolvedValue(result)
  };
}

function policyStore() {
  let sequence = 0;
  const decisions = new Map<string, Record<string, unknown>>();
  return {
    create: jest.fn(async (input: Record<string, unknown>) => {
      const decision = {
        id: `policy_decision_${++sequence}`,
        ...input
      };
      decisions.set(String(decision.id), decision);
      return decision;
    }),
    findByTenantAndId: jest.fn(
      async (tenantId: string, id: string) => {
        const decision = decisions.get(id);
        return decision?.tenantId === tenantId ? decision : null;
      }
    )
  };
}
