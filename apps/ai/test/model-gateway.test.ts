import assert from "node:assert/strict";
import test from "node:test";

import {
  createDeterministicFallbackProvider,
  createModelGateway,
  validateModelGatewayConfig
} from "../src/model-gateway";

import type { AiInferenceRequest, AiInferenceResponse } from "@aegisai/shared";

const inferenceRequest: AiInferenceRequest = {
  tenantId: "tenant_model_gateway",
  scanRequestId: "scan_request_1",
  canonicalScanKey: "tenant_model_gateway:repo_1:FAST:main:abc123:policy_v1:scanner_v1",
  requestId: "ai_request_1",
  reducedEvidence: {
    findingIds: ["finding_1"],
    scannerNames: ["OPENGREP"],
    evidencePackId: "evidence_1",
    summary: "Reduced scanner evidence for a SQL injection sink.",
    snippets: [
      {
        label: "sink",
        language: "ts",
        redactedText: "db.query(REDACTED)"
      }
    ],
    metadata: {
      severity: "HIGH"
    },
    redactionState: "redacted"
  },
  requestedCapabilities: ["detector", "planner"],
  runtimePolicy: {
    allowFallback: true,
    maxLatencyMs: 1000
  },
  createdAt: "2026-05-26T00:00:00.000Z"
};

test("model gateway returns deterministic fallback advisories when no provider is configured", async () => {
  const gateway = createModelGateway({
    config: {
      providerId: "deterministic",
      model: "detector-planner-fallback",
      version: "v1",
      allowFallback: true
    },
    fallbackProvider: createDeterministicFallbackProvider()
  });

  const response = await gateway.infer(inferenceRequest);

  assert.equal(response.advisoryOnly, true);
  assert.equal(response.fallback.used, true);
  assert.equal(response.modelMetadata.provider, "deterministic");
  assert.equal(response.modelMetadata.model, "detector-planner-fallback");
  assert.equal(response.detectorAdvisories[0]?.findingId, "finding_1");
  assert.equal(response.plannerAdvisories[0]?.priority, "high");
});

test("model gateway returns provider output without fallback when provider succeeds", async () => {
  const providerResponse: AiInferenceResponse = {
    requestId: inferenceRequest.requestId,
    tenantId: inferenceRequest.tenantId,
    scanRequestId: inferenceRequest.scanRequestId,
    advisoryOnly: true,
    detectorAdvisories: [
      {
        findingId: "finding_1",
        confidence: 0.91,
        rationale: "Provider confirmed scanner context.",
        signals: ["PROVIDER_CONFIRMED"]
      }
    ],
    plannerAdvisories: [
      {
        findingId: "finding_1",
        action: "Schedule owner review.",
        rationale: "High confidence advisory.",
        priority: "high"
      }
    ],
    modelMetadata: {
      provider: "configured-provider",
      model: "prod-detector-planner",
      version: "2026-05-26"
    },
    fallback: {
      used: false
    },
    latencyMs: 12,
    createdAt: "2026-05-26T00:00:01.000Z"
  };

  const gateway = createModelGateway({
    config: {
      providerId: "configured-provider",
      model: "prod-detector-planner",
      version: "2026-05-26",
      allowFallback: true
    },
    provider: {
      infer: async () => providerResponse
    },
    fallbackProvider: createDeterministicFallbackProvider()
  });

  const response = await gateway.infer(inferenceRequest);

  assert.equal(response.fallback.used, false);
  assert.equal(response.detectorAdvisories[0]?.signals[0], "PROVIDER_CONFIRMED");
});

test("model gateway uses fallback when provider fails and runtime policy allows fallback", async () => {
  const gateway = createModelGateway({
    config: {
      providerId: "configured-provider",
      model: "prod-detector-planner",
      version: "2026-05-26",
      allowFallback: true
    },
    provider: {
      infer: async () => {
        throw new Error("provider unavailable");
      }
    },
    fallbackProvider: createDeterministicFallbackProvider()
  });

  const response = await gateway.infer(inferenceRequest);

  assert.equal(response.fallback.used, true);
  assert.match(response.fallback.reason ?? "", /provider unavailable/i);
});

test("model gateway configuration guardrails reject incomplete provider metadata", () => {
  assert.throws(
    () =>
      validateModelGatewayConfig({
        providerId: "",
        model: "prod-detector-planner",
        version: "2026-05-26",
        allowFallback: true
      }),
    /provider/i
  );

  assert.throws(
    () =>
      validateModelGatewayConfig({
        providerId: "configured-provider",
        model: "",
        version: "2026-05-26",
        allowFallback: true
      }),
    /model/i
  );
});

test("model gateway responses remain advisory-only without authority fields", async () => {
  const gateway = createModelGateway({
    config: {
      providerId: "deterministic",
      model: "detector-planner-fallback",
      version: "v1",
      allowFallback: true
    },
    fallbackProvider: createDeterministicFallbackProvider()
  });

  const serialized = JSON.stringify(await gateway.infer(inferenceRequest));

  assert.doesNotMatch(
    serialized,
    /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload/i
  );
  assert.doesNotMatch(
    serialized,
    /policyOverride|findingOverride|enforcementAction|blockRequested|waiverApplied|staleSuppressed/i
  );
});
