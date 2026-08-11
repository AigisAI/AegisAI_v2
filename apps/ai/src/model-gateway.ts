import type {
  AiInferenceAuditEvent,
  AiInferenceRejectionReason,
  AiInferenceRequest,
  AiInferenceResponse
} from "@aegisai/shared";

export interface ModelGatewayConfig {
  providerId: string;
  model: string;
  version: string;
  allowFallback: boolean;
}

export interface ModelProviderContext {
  config: ModelGatewayConfig;
  fallbackReason?: string;
}

export interface AiModelProvider {
  infer(request: AiInferenceRequest, context?: ModelProviderContext): Promise<AiInferenceResponse>;
}

export interface ModelGatewayOptions {
  config: ModelGatewayConfig;
  provider?: AiModelProvider;
  fallbackProvider: AiModelProvider;
  auditSink?: (event: AiInferenceAuditEvent) => void | Promise<void>;
}

export interface ModelGateway {
  infer(request: AiInferenceRequest): Promise<AiInferenceResponse>;
}

export function validateModelGatewayConfig(config: ModelGatewayConfig): ModelGatewayConfig {
  if (config.providerId.trim().length === 0) {
    throw new Error("Model gateway provider id is required.");
  }

  if (config.model.trim().length === 0) {
    throw new Error("Model gateway model is required.");
  }

  if (!isRuntimeModelVersion(config.version)) {
    throw new Error("Model gateway version is required.");
  }

  return config;
}

export function createModelGateway(options: ModelGatewayOptions): ModelGateway {
  const config = validateModelGatewayConfig(options.config);

  return {
    async infer(request) {
      const startedAt = Date.now();

      try {
        validateAiInferenceRequest(request);
        if (request.modelVersion !== config.version) {
          throw new AiInferenceValidationError(
            "AI inference request model version does not match the selected gateway.",
            "FORBIDDEN_INPUT_CLASS"
          );
        }
      } catch (error) {
        emitAuditEvent(options, request, "ai_inference.rejected", {
          rejectionReason: rejectionReasonFor(error)
        });
        throw error;
      }

      emitAuditEvent(options, request, "ai_inference.requested");

      if (options.provider) {
        try {
          const response = await options.provider.infer(request, { config });
          emitAuditEvent(options, request, "ai_inference.completed", {
            latencyMs: elapsedMs(startedAt),
            provider: response.modelMetadata.provider,
            model: response.modelMetadata.model,
            fallbackUsed: response.fallback.used
          });
          return response;
        } catch (error) {
          if (!config.allowFallback || !request.runtimePolicy.allowFallback) {
            emitAuditEvent(options, request, "ai_inference.failed", {
              latencyMs: elapsedMs(startedAt),
              fallbackUsed: false
            });
            throw error;
          }

          return runFallbackProvider(
            options,
            request,
            config,
            startedAt,
            error instanceof Error ? error.message : "provider failed"
          );
        }
      }

      if (!config.allowFallback || !request.runtimePolicy.allowFallback) {
        emitAuditEvent(options, request, "ai_inference.failed", {
          latencyMs: elapsedMs(startedAt),
          fallbackUsed: false
        });
        throw new Error("Model gateway provider is not configured and fallback is disabled.");
      }

      return runFallbackProvider(options, request, config, startedAt, "provider not configured");
    }
  };
}

async function runFallbackProvider(
  options: ModelGatewayOptions,
  request: AiInferenceRequest,
  config: ModelGatewayConfig,
  startedAt: number,
  fallbackReason: string
): Promise<AiInferenceResponse> {
  try {
    const response = await options.fallbackProvider.infer(request, {
      config,
      fallbackReason
    });
    emitAuditEvent(options, request, "ai_inference.fallback_completed", {
      latencyMs: elapsedMs(startedAt),
      provider: response.modelMetadata.provider,
      model: response.modelMetadata.model,
      fallbackUsed: true
    });
    return response;
  } catch (error) {
    emitAuditEvent(options, request, "ai_inference.failed", {
      latencyMs: elapsedMs(startedAt),
      fallbackUsed: true
    });
    throw error;
  }
}

export function validateAiInferenceRequest(request: AiInferenceRequest): AiInferenceRequest {
  if (!isRecord(request as unknown) || !hasExactKeys(request as unknown as Record<string, unknown>, [
    "tenantId",
    "scanRequestId",
    "canonicalScanKey",
    "requestId",
    "modelVersion",
    "reducedEvidence",
    "requestedCapabilities",
    "runtimePolicy",
    "createdAt"
  ]) || typeof request.tenantId !== "string" || request.tenantId.trim().length === 0) {
    throw new AiInferenceValidationError("AI inference request requires tenant attribution.", "MISSING_TENANT_ATTRIBUTION");
  }

  if (typeof request.scanRequestId !== "string" || request.scanRequestId.trim().length === 0) {
    throw new AiInferenceValidationError("AI inference request requires scan attribution.", "MISSING_SCAN_ATTRIBUTION");
  }

  if (!isRuntimeModelVersion(request.modelVersion)) {
    throw new AiInferenceValidationError(
      "AI inference request requires a bounded model version.",
      "FORBIDDEN_INPUT_CLASS"
    );
  }

  if (!isRecord(request.reducedEvidence as unknown) || request.reducedEvidence.redactionState !== "reduced") {
    throw new AiInferenceValidationError(
      "AI inference request must remain inside the reduced evidence boundary.",
      "UNREDACTED_EVIDENCE"
    );
  }

  if (hasForbiddenEvidenceKey(request.reducedEvidence)) {
    throw new AiInferenceValidationError(
      "AI inference request must remain inside the reduced evidence boundary.",
      "FORBIDDEN_INPUT_CLASS"
    );
  }

  if (!isT043ReducedReferenceRequest(request)) {
    throw new AiInferenceValidationError(
      "AI inference request must use the exact T043 reduced-reference contract.",
      "FORBIDDEN_INPUT_CLASS"
    );
  }

  return request;
}

const T043_METADATA_KEYS = [
  "handoffVersion",
  "handoffDigest",
  "requestDigest",
  "repositoryBindingId",
  "attemptId",
  "occurrenceId",
  "normalizedFindingId",
  "findingFingerprint",
  "capability",
  "severity",
  "confidence",
  "scanner",
  "ruleSemanticId",
  "ruleRevision",
  "location",
  "cweIds",
  "cveIds",
  "accessDecisionId",
  "accessDecisionDigest",
  "reducedEvidenceRef",
  "redactedProjectionDigest",
  "fragmentCount",
  "payloadExpiresAt",
  "retrievalAllowed",
  "toolsAllowed",
  "policyAuthority",
  "publicationAuthority",
  "lifecycleMutationAuthority",
  "scmWriteAuthority",
  "advisoryOnly"
] as const;

function isT043ReducedReferenceRequest(
  request: AiInferenceRequest
): boolean {
  const evidence = request.reducedEvidence;
  if (
    !isRecord(evidence as unknown) ||
    !isRecord(evidence.metadata) ||
    !Array.isArray(evidence.findingIds) ||
    !Array.isArray(evidence.scannerNames) ||
    !Array.isArray(evidence.snippets) ||
    !Array.isArray(request.requestedCapabilities) ||
    !isRecord(request.runtimePolicy as unknown)
  ) {
    return false;
  }
  const metadata = evidence.metadata;
  const createdAt = Date.parse(request.createdAt);
  const expiresAt = Date.parse(String(metadata.payloadExpiresAt));
  const requestSuffix = String(metadata.requestDigest).replace(
    /^sha256:/u,
    ""
  );
  return (
    hasExactKeys(evidence as unknown as Record<string, unknown>, [
      "findingIds",
      "scannerNames",
      "evidencePackId",
      "summary",
      "snippets",
      "metadata",
      "redactionState"
    ]) &&
    hasExactKeys(metadata, T043_METADATA_KEYS) &&
    hasExactKeys(request.runtimePolicy as unknown as Record<string, unknown>, [
      "allowFallback",
      "maxLatencyMs"
    ]) &&
    isBoundedRuntimeText(request.tenantId, 512) &&
    isBoundedRuntimeText(request.scanRequestId, 512) &&
    request.canonicalScanKey === [
      request.tenantId,
      metadata.repositoryBindingId,
      request.scanRequestId,
      metadata.attemptId,
      metadata.accessDecisionDigest,
      request.modelVersion
    ].join(":") &&
    request.requestId === `sast-ai-request://${requestSuffix}` &&
    /^sast-ai-request:\/\/[a-f0-9]{64}$/u.test(request.requestId) &&
    /^sha256:[a-f0-9]{64}$/u.test(String(metadata.handoffDigest)) &&
    /^sha256:[a-f0-9]{64}$/u.test(String(metadata.requestDigest)) &&
    /^sha256:[a-f0-9]{64}$/u.test(String(metadata.findingFingerprint)) &&
    /^sha256:[a-f0-9]{64}$/u.test(String(metadata.accessDecisionDigest)) &&
    /^sha256:[a-f0-9]{64}$/u.test(String(metadata.redactedProjectionDigest)) &&
    metadata.handoffVersion === "sast-ai-advisory-handoff-v1" &&
    /^sast-evidence-access:\/\/[a-f0-9]{64}$/u.test(String(metadata.accessDecisionId)) &&
    /^sast-reduced-evidence:\/\/[a-f0-9]{64}$/u.test(String(metadata.reducedEvidenceRef)) &&
    /^sast-evidence-pack:\/\/[a-f0-9]{64}$/u.test(evidence.evidencePackId) &&
    /^finding-occurrence:\/\/[a-f0-9]{64}$/u.test(String(metadata.occurrenceId)) &&
    isBoundedRuntimeText(metadata.repositoryBindingId, 512) &&
    isBoundedRuntimeText(metadata.attemptId, 512) &&
    isBoundedRuntimeText(metadata.normalizedFindingId, 512) &&
    isBoundedRuntimeText(metadata.ruleSemanticId, 512) &&
    isBoundedRuntimeText(metadata.ruleRevision, 512) &&
    isBoundedRuntimeText(metadata.location, 1024) &&
    isCommaSeparatedIdentifiers(metadata.cweIds) &&
    isCommaSeparatedIdentifiers(metadata.cveIds) &&
    [
      "SAST",
      "DEPENDENCY_VULNERABILITY",
      "SECRET_DETECTION",
      "IAC_MISCONFIGURATION"
    ].includes(String(metadata.capability)) &&
    evidence.findingIds.length === 1 &&
    evidence.findingIds[0] === metadata.normalizedFindingId &&
    evidence.scannerNames.length === 1 &&
    evidence.scannerNames[0] === metadata.scanner &&
    evidence.snippets.length === 0 &&
    typeof evidence.summary === "string" &&
    evidence.summary.length > 0 &&
    evidence.summary.length <= 1024 &&
    (metadata.scanner === "OPENGREP" || metadata.scanner === "TRIVY") &&
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(String(metadata.severity)) &&
    ["HIGH", "MEDIUM", "LOW", "UNKNOWN"].includes(String(metadata.confidence)) &&
    Number.isInteger(metadata.fragmentCount) &&
    Number(metadata.fragmentCount) >= 1 &&
    Number(metadata.fragmentCount) <= 5 &&
    metadata.retrievalAllowed === false &&
    metadata.toolsAllowed === false &&
    metadata.policyAuthority === false &&
    metadata.publicationAuthority === false &&
    metadata.lifecycleMutationAuthority === false &&
    metadata.scmWriteAuthority === false &&
    metadata.advisoryOnly === true &&
    request.requestedCapabilities.length === 2 &&
    request.requestedCapabilities[0] === "detector" &&
    request.requestedCapabilities[1] === "planner" &&
    request.runtimePolicy.allowFallback === true &&
    Number.isFinite(request.runtimePolicy.maxLatencyMs) &&
    request.runtimePolicy.maxLatencyMs > 0 &&
    request.runtimePolicy.maxLatencyMs <= 30_000 &&
    Number.isFinite(createdAt) &&
    Number.isFinite(expiresAt) &&
    new Date(createdAt).toISOString() === request.createdAt &&
    new Date(expiresAt).toISOString() === metadata.payloadExpiresAt &&
    createdAt < expiresAt &&
    Date.now() < expiresAt &&
    expiresAt - createdAt <= 24 * 60 * 60 * 1000
  );
}

function isBoundedRuntimeText(
  value: unknown,
  maximumLength: number
): value is string {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    value.trim() === value &&
    !hasAsciiControl(value);
}

function isRuntimeModelVersion(value: unknown): value is string {
  return isBoundedRuntimeText(value, 128) &&
    /^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$/u.test(value);
}

function hasAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function isCommaSeparatedIdentifiers(value: unknown): boolean {
  if (typeof value !== "string") return false;
  if (value === "") return true;
  const identifiers = value.split(",");
  return identifiers.length <= 32 &&
    identifiers.every((identifier) =>
      /^[A-Z0-9][A-Z0-9._:-]{0,127}$/u.test(identifier)
    ) &&
    new Set(identifiers).size === identifiers.length &&
    identifiers.every((identifier, index) =>
      index === 0 || String(identifiers[index - 1]) < identifier
    );
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[]
): boolean {
  const actual = Object.keys(value).sort();
  const ordered = [...expected].sort();
  return actual.length === ordered.length &&
    actual.every((key, index) => key === ordered[index]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasForbiddenEvidenceKey(input: unknown): boolean {
  if (input === null || typeof input !== "object") {
    return false;
  }

  if (Array.isArray(input)) {
    return input.some((item) => hasForbiddenEvidenceKey(item));
  }

  return Object.entries(input as Record<string, unknown>).some(
    ([key, value]) => isForbiddenEvidenceKey(key) || hasForbiddenEvidenceKey(value)
  );
}

function isForbiddenEvidenceKey(key: string): boolean {
  return FORBIDDEN_INPUT_KEYS.some((forbiddenKey) => forbiddenKey.toLowerCase() === key.toLowerCase());
}

export function createDeterministicFallbackProvider(): AiModelProvider {
  return {
    async infer(request, context) {
      const startedAt = Date.now();
      const findingId = request.reducedEvidence.findingIds[0] ?? "finding";
      const severity = String(request.reducedEvidence.metadata.severity ?? "MEDIUM").toUpperCase();
      const priority = severity === "CRITICAL" || severity === "HIGH" ? "high" : "medium";

      return {
        requestId: request.requestId,
        tenantId: request.tenantId,
        scanRequestId: request.scanRequestId,
        advisoryOnly: true,
        detectorAdvisories: [
          {
            findingId,
            confidence: severity === "CRITICAL" || severity === "HIGH" ? 0.68 : 0.55,
            rationale: "Deterministic fallback advisory generated from reduced scanner evidence.",
            signals: [
              "FALLBACK_DETERMINISTIC",
              `EVIDENCE_${request.reducedEvidence.redactionState.toUpperCase()}`,
              `SCANNERS_${request.reducedEvidence.scannerNames.join("_")}`
            ]
          }
        ],
        plannerAdvisories: [
          {
            findingId,
            action: "Review normalized scanner evidence with the owning team.",
            rationale: "Fallback planning keeps remediation and policy decisions outside the AI Plane.",
            priority
          }
        ],
        modelMetadata: {
          provider: "deterministic",
          model: context?.config.model ?? "detector-planner-fallback",
          version: context?.config.version ?? "v1"
        },
        fallback: {
          used: true,
          reason: context?.fallbackReason
        },
        latencyMs: Math.max(0, Date.now() - startedAt),
        createdAt: new Date().toISOString()
      };
    }
  };
}

class AiInferenceValidationError extends Error {
  constructor(
    message: string,
    readonly rejectionReason: AiInferenceRejectionReason
  ) {
    super(message);
  }
}

const FORBIDDEN_INPUT_KEYS = [
  "accessToken",
  "refreshToken",
  "tokenValue",
  "secretValue",
  "scmCredential",
  "scmToken",
  "sourceArchive",
  "repositoryArchive",
  "fullRepository",
  "rawScannerPayload"
];

type AuditEventOverrides = Partial<
  Pick<AiInferenceAuditEvent, "fallbackUsed" | "latencyMs" | "model" | "provider" | "rejectionReason">
>;

function emitAuditEvent(
  options: ModelGatewayOptions,
  request: AiInferenceRequest,
  eventType: AiInferenceAuditEvent["eventType"],
  overrides: AuditEventOverrides = {}
): void {
  try {
    const result = options.auditSink?.({
      tenantId: request.tenantId,
      scanRequestId: request.scanRequestId,
      requestId: request.requestId,
      eventType,
      provider: overrides.provider ?? options.config.providerId,
      model: overrides.model ?? options.config.model,
      fallbackUsed: overrides.fallbackUsed ?? false,
      rejectionReason: overrides.rejectionReason,
      latencyMs: overrides.latencyMs,
      createdAt: new Date().toISOString()
    });

    if (isPromiseLike(result)) {
      result.catch(() => undefined);
    }
  } catch {
    return;
  }
}

function isPromiseLike(input: unknown): input is PromiseLike<void> {
  return (
    input !== null &&
    (typeof input === "object" || typeof input === "function") &&
    "then" in input &&
    typeof (input as { then?: unknown }).then === "function" &&
    "catch" in input &&
    typeof (input as { catch?: unknown }).catch === "function"
  );
}

function rejectionReasonFor(error: unknown): AiInferenceRejectionReason {
  if (error instanceof AiInferenceValidationError) {
    return error.rejectionReason;
  }

  return "MODEL_GATEWAY_UNAVAILABLE";
}

function elapsedMs(startedAt: number): number {
  return Math.max(0, Date.now() - startedAt);
}
