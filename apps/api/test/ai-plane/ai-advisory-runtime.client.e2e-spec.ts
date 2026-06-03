import axios from "axios";

import { AiAdvisoryRuntimeClient } from "../../src/ai-plane/ai-advisory-runtime.client";

import type { AiAdvisoryRequest, AiInferenceResponse } from "../../../../packages/shared/src";

jest.mock("axios");

const mockedAxios = jest.mocked(axios);

describe("AiAdvisoryRuntimeClient", () => {
  const request: AiAdvisoryRequest = {
    tenantId: "tenant_runtime",
    scanRequestId: "scan_request_1",
    findingId: "finding_1",
    normalizedFinding: {
      id: "finding_1",
      tenantId: "tenant_runtime",
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
      tenantId: "tenant_runtime",
      scanRequestId: "scan_request_1",
      classification: "SHORT_LIVED_EVIDENCE",
      objectKey: "tenant_runtime/scan_request_1/evidence/evidence_1.json",
      expiresAt: "2026-04-19T00:00:00.000Z",
      byteSize: 512,
      redacted: true
    },
    modelVersion: "detector-planner-runtime-v1"
  };

  beforeEach(() => {
    mockedAxios.post.mockReset();
  });

  it("sends reduced inference requests and accepts the model gateway response shape", async () => {
    const runtimeResponse: AiInferenceResponse = {
      requestId: "ai_request_1",
      tenantId: "tenant_runtime",
      scanRequestId: "scan_request_1",
      advisoryOnly: true,
      detectorAdvisories: [
        {
          findingId: "finding_1",
          confidence: 0.91,
          rationale: "Model gateway mapped reduced evidence to a detector advisory.",
          signals: ["SCANNER_CONFIRMED", "MODEL_TRIAGED"]
        }
      ],
      plannerAdvisories: [
        {
          findingId: "finding_1",
          action: "Review scanner evidence before remediation.",
          rationale: "Planner advisory generated from reduced evidence.",
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
      latencyMs: 13,
      createdAt: "2026-05-26T00:00:00.000Z"
    };
    mockedAxios.post.mockResolvedValueOnce({
      data: runtimeResponse
    });
    const client = new AiAdvisoryRuntimeClient({
      get: jest.fn((key: string) => {
        const values: Record<string, string | number> = {
          AI_SERVER_URL: "https://ai-runtime.example",
          AI_ADVISORY_TIMEOUT_MS: 2500
        };

        return values[key];
      })
    } as never);

    const result = await client.createAdvisory(request);
    const inferenceRequest = mockedAxios.post.mock.calls[0]?.[1] as Record<string, unknown>;

    expect(mockedAxios.post).toHaveBeenCalledWith(
      "https://ai-runtime.example/ai/advisories",
      expect.objectContaining({
        tenantId: "tenant_runtime",
        scanRequestId: "scan_request_1",
        requestId: expect.any(String),
        canonicalScanKey: expect.any(String),
        reducedEvidence: expect.objectContaining({
          findingIds: ["finding_1"],
          evidencePackId: "evidence_1",
          scannerNames: ["OPENGREP"],
          redactionState: "redacted"
        }),
        requestedCapabilities: ["detector", "planner"],
        runtimePolicy: {
          allowFallback: true,
          maxLatencyMs: 2500
        }
      }),
      expect.objectContaining({
        timeout: 2500
      })
    );
    expect(inferenceRequest).not.toHaveProperty("normalizedFinding");
    expect(inferenceRequest).not.toHaveProperty("evidence");
    expect(result).toEqual(runtimeResponse);
    expect(JSON.stringify({ calls: mockedAxios.post.mock.calls, result })).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload/i
    );
  });

  it("rejects runtime responses that attempt to override findings or policy", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: {
        requestId: "ai_request_1",
        tenantId: "tenant_runtime",
        scanRequestId: "scan_request_1",
        advisoryOnly: true,
        detectorAdvisories: [],
        plannerAdvisories: [],
        modelMetadata: {
          provider: "deterministic",
          model: "detector-planner-runtime",
          version: "2026-05-26"
        },
        fallback: {
          used: false
        },
        latencyMs: 1,
        createdAt: "2026-05-26T00:00:00.000Z",
        enforcementAction: "BLOCK"
      }
    });
    const client = new AiAdvisoryRuntimeClient({
      get: jest.fn((key: string) => {
        const values: Record<string, string | number> = {
          AI_SERVER_URL: "https://ai-runtime.example",
          AI_ADVISORY_TIMEOUT_MS: 2500
        };

        return values[key];
      })
    } as never);

    await expect(client.createAdvisory(request)).rejects.toThrow(
      "AI advisory runtime response contains forbidden authority or sensitive content."
    );
  });
});
