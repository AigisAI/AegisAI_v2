import { Injectable, NotFoundException } from "@nestjs/common";

import type {
  PolicyDecision,
  PolicyEvaluationInput,
  ScannerKind
} from "../../../../packages/shared/src";

const REQUIRED_SCANNER_COVERAGE: ScannerKind[] = ["OPENGREP", "TRIVY", "SYFT"];

@Injectable()
export class PolicyEngineService {
  private readonly policyDecisions: PolicyDecision[] = [];
  private decisionSequence = 0;

  evaluate(input: PolicyEvaluationInput): PolicyDecision {
    const reasonCodes = this.reasonCodesFor(input);
    const enforcementAction = this.enforcementActionFor(input);
    const decision: PolicyDecision = {
      id: `policy_decision_${++this.decisionSequence}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      findingId: input.finding.id,
      enforcementAction,
      commentAllowed: enforcementAction !== "DASHBOARD_ONLY",
      dashboardVisible: true,
      ticketRequested: enforcementAction === "BLOCK",
      blockRequested: enforcementAction === "BLOCK",
      reasonCodes,
      requiredCoverage: REQUIRED_SCANNER_COVERAGE,
      waiverApplied: false,
      staleSuppressed: false,
      aiAdvisoryVisible: input.aiAdvisory?.visible === true
    };

    this.policyDecisions.push(decision);

    return decision;
  }

  getPolicyDecision(tenantId: string, policyDecisionId: string): PolicyDecision {
    const decision = this.policyDecisions.find(
      (policyDecision) =>
        policyDecision.id === policyDecisionId && policyDecision.tenantId === tenantId
    );

    if (!decision) {
      throw new NotFoundException("Policy decision was not found for tenant.");
    }

    return decision;
  }

  private enforcementActionFor(input: PolicyEvaluationInput): PolicyDecision["enforcementAction"] {
    if (input.finding.severity === "CRITICAL") {
      return "BLOCK";
    }

    if (input.finding.severity === "HIGH") {
      return "WARN";
    }

    if (input.finding.severity === "MEDIUM") {
      return "COMMENT";
    }

    return "DASHBOARD_ONLY";
  }

  private reasonCodesFor(input: PolicyEvaluationInput): string[] {
    const reasonCodes = [`SEVERITY_${input.finding.severity}`];
    const hasRequiredCoverage = REQUIRED_SCANNER_COVERAGE.every((scanner) =>
      input.scannerCoverage.includes(scanner)
    );

    if (input.scanLane === "DEEP" && !hasRequiredCoverage) {
      reasonCodes.push("MISSING_REQUIRED_SCANNER_COVERAGE");
    }

    return reasonCodes;
  }
}
