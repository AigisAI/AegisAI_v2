import assert from "node:assert/strict";
import test from "node:test";

import { handleAiAdvisoryRequest } from "../src/advisory-runtime";

import type { AiAdvisoryRequest } from "@aegisai/shared";

const baseRequest: AiAdvisoryRequest = {
  tenantId: "tenant_ai_service",
  scanRequestId: "scan_request_1",
  findingId: "finding_1",
  normalizedFinding: {
    id: "finding_1",
    tenantId: "tenant_ai_service",
    scanRequestId: "scan_request_1",
    scannerRunId: "scanner_run_1",
    title: "SQL injection sink",
    severity: "HIGH",
    scannerProvenance: "OPENGREP",
    filePath: "src/user.controller.ts",
    lineStart: 42,
    status: "OPEN"
  },
  evidence: {
    id: "evidence_1",
    tenantId: "tenant_ai_service",
    scanRequestId: "scan_request_1",
    classification: "SHORT_LIVED_EVIDENCE",
    objectKey: "tenant_ai_service/scan_request_1/evidence/evidence_1.json",
    expiresAt: "2026-04-19T00:00:00.000Z",
    byteSize: 512,
    redacted: true
  },
  modelVersion: "detector-planner-runtime-v1"
};

function advisoryHttpRequest(body: unknown): Request {
  return new Request("http://127.0.0.1:8000/ai/advisories", {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });
}

test("POST /ai/advisories returns advisory-only detector and planner output", async () => {
  const response = await handleAiAdvisoryRequest(advisoryHttpRequest(baseRequest));
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(Object.keys(body).sort(), [
    "confidence",
    "detectorSignals",
    "modelVersion",
    "plannerSteps"
  ]);
  assert.deepEqual(body.detectorSignals, [
    "SCANNER_CONFIRMED",
    "SEVERITY_HIGH",
    "PROVENANCE_OPENGREP",
    "MODEL_SERVICE_BOUNDARY_REDUCED_INPUT"
  ]);
  assert.equal(body.modelVersion, "detector-planner-runtime-v1");
  assert.equal(typeof body.confidence, "number");
  assert.ok(body.confidence >= 0);
  assert.ok(body.confidence <= 1);
});

test("GET /health returns the AI runtime health status", async () => {
  const response = await handleAiAdvisoryRequest(new Request("http://127.0.0.1:8000/health"));
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body, {
    service: "ai-runtime",
    status: "ok"
  });
});

test("POST /ai/advisories rejects unredacted evidence", async () => {
  const response = await handleAiAdvisoryRequest(
    advisoryHttpRequest({
      ...baseRequest,
      evidence: {
        ...baseRequest.evidence,
        redacted: false
      }
    })
  );
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /redacted evidence/i);
});

test("POST /ai/advisories rejects credentials, repositories, source archives, and raw scanner payloads", async () => {
  const forbiddenInputs = [
    { accessToken: "ghs_secret" },
    { fullRepository: "entire repository contents" },
    { sourceArchive: "base64-zip" },
    { rawScannerPayload: { raw: true } }
  ];

  for (const forbiddenInput of forbiddenInputs) {
    const response = await handleAiAdvisoryRequest(
      advisoryHttpRequest({
        ...baseRequest,
        ...forbiddenInput
      })
    );

    assert.equal(response.status, 400);
  }
});

test("POST /ai/advisories never returns policy authority or finding override fields", async () => {
  const response = await handleAiAdvisoryRequest(advisoryHttpRequest(baseRequest));
  const serialized = JSON.stringify(await response.json());

  assert.doesNotMatch(
    serialized,
    /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload/i
  );
  assert.doesNotMatch(
    serialized,
    /policyOverride|findingOverride|enforcementAction|blockRequested|waiverApplied|staleSuppressed/i
  );
});
