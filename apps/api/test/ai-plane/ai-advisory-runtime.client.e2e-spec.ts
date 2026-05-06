import axios from "axios";

import { AiAdvisoryRuntimeClient } from "../../src/ai-plane/ai-advisory-runtime.client";

import type { AiAdvisoryRequest } from "../../../../packages/shared/src";

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

  it("sends only reduced AI advisory requests to the configured runtime endpoint", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: {
        detectorSignals: ["SCANNER_CONFIRMED", "MODEL_TRIAGED"],
        plannerSteps: ["Review scanner evidence before remediation."],
        confidence: 0.81,
        modelVersion: "detector-planner-runtime-v1"
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

    const result = await client.createAdvisory(request);

    expect(mockedAxios.post).toHaveBeenCalledWith(
      "https://ai-runtime.example/ai/advisories",
      request,
      expect.objectContaining({
        timeout: 2500
      })
    );
    expect(result).toEqual({
      detectorSignals: ["SCANNER_CONFIRMED", "MODEL_TRIAGED"],
      plannerSteps: ["Review scanner evidence before remediation."],
      confidence: 0.81,
      modelVersion: "detector-planner-runtime-v1"
    });
    expect(JSON.stringify(mockedAxios.post.mock.calls)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload/i
    );
  });

  it("rejects runtime responses that attempt to override findings or policy", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: {
        detectorSignals: ["SCANNER_CONFIRMED"],
        plannerSteps: ["Override policy."],
        confidence: 0.9,
        modelVersion: "detector-planner-runtime-v1",
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
