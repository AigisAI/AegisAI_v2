import type { AiAdvisoryRequest } from "@aegisai/shared";

export interface AiAdvisoryRuntimeResponse {
  detectorSignals: string[];
  plannerSteps: string[];
  confidence: number;
  modelVersion: string;
}

const FORBIDDEN_INPUT_KEYS = [
  "accessToken",
  "refreshToken",
  "tokenValue",
  "secretValue",
  "sourceArchive",
  "fullRepository",
  "rawScannerPayload",
  "policyOverride",
  "findingOverride",
  "enforcementAction",
  "blockRequested",
  "waiverApplied",
  "staleSuppressed"
];

export async function handleAiAdvisoryRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/health") {
    return jsonResponse({ status: "ok", service: "ai-runtime" }, 200);
  }

  if (url.pathname !== "/ai/advisories") {
    return jsonResponse({ error: "AI advisory route was not found." }, 404);
  }

  if (request.method !== "POST") {
    return jsonResponse({ error: "AI advisory route only accepts POST." }, 405);
  }

  try {
    const body = (await request.json()) as unknown;
    const advisoryRequest = parseReducedAdvisoryRequest(body);

    return jsonResponse(createDetectorPlannerAdvisory(advisoryRequest), 200);
  } catch (error) {
    return jsonResponse(
      {
        error: error instanceof Error ? error.message : "AI advisory request is malformed."
      },
      400
    );
  }
}

export function createDetectorPlannerAdvisory(input: AiAdvisoryRequest): AiAdvisoryRuntimeResponse {
  return {
    detectorSignals: [
      "SCANNER_CONFIRMED",
      `SEVERITY_${input.normalizedFinding.severity}`,
      `PROVENANCE_${input.normalizedFinding.scannerProvenance}`,
      "MODEL_SERVICE_BOUNDARY_REDUCED_INPUT"
    ],
    plannerSteps: plannerStepsFor(input),
    confidence: confidenceFor(input),
    modelVersion: input.modelVersion
  };
}

function parseReducedAdvisoryRequest(input: unknown): AiAdvisoryRequest {
  if (!isRecord(input)) {
    throw new Error("AI advisory request must be an object.");
  }

  const serialized = JSON.stringify(input);

  for (const forbiddenKey of FORBIDDEN_INPUT_KEYS) {
    if (new RegExp(forbiddenKey, "i").test(serialized)) {
      throw new Error("AI advisory request contains forbidden sensitive or authority content.");
    }
  }

  const evidence = input.evidence;
  const normalizedFinding = input.normalizedFinding;

  if (!isRecord(evidence) || evidence.redacted !== true) {
    throw new Error("AI advisory request must use redacted evidence.");
  }

  if (!isRecord(normalizedFinding)) {
    throw new Error("AI advisory request must include a normalized finding.");
  }

  if (
    typeof input.tenantId !== "string" ||
    typeof input.scanRequestId !== "string" ||
    typeof input.findingId !== "string" ||
    typeof input.modelVersion !== "string"
  ) {
    throw new Error("AI advisory request is missing required identifiers.");
  }

  if (
    typeof normalizedFinding.severity !== "string" ||
    typeof normalizedFinding.scannerProvenance !== "string" ||
    typeof normalizedFinding.title !== "string" ||
    typeof normalizedFinding.filePath !== "string"
  ) {
    throw new Error("AI advisory request normalized finding is incomplete.");
  }

  return input as unknown as AiAdvisoryRequest;
}

function plannerStepsFor(input: AiAdvisoryRequest): string[] {
  const steps = ["Review normalized scanner evidence before remediation planning."];

  if (input.normalizedFinding.severity === "CRITICAL" || input.normalizedFinding.severity === "HIGH") {
    steps.push("Prioritize owner review before merging affected changes.");
  }

  steps.push("Keep remediation, policy, and merge decisions outside the AI Plane.");

  return steps;
}

function confidenceFor(input: AiAdvisoryRequest): number {
  if (input.normalizedFinding.severity === "CRITICAL") {
    return 0.82;
  }

  if (input.normalizedFinding.severity === "HIGH") {
    return 0.74;
  }

  return 0.61;
}

function jsonResponse(body: Record<string, unknown> | AiAdvisoryRuntimeResponse, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return Boolean(input) && typeof input === "object" && !Array.isArray(input);
}
