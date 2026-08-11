import {
  isSastAiAdvisoryHandoffShapeValid,
  type AiInferenceRequest,
  type AiInferenceResponse,
  type SastAiAdvisoryHandoff
} from '@aegisai/shared';
import { BadGatewayException, Injectable } from '@nestjs/common';
import axios from 'axios';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

import { ConfigService } from '../config/config.service';

const FORBIDDEN_RUNTIME_RESPONSE_KEYS = [
  'accessToken',
  'refreshToken',
  'tokenValue',
  'secretValue',
  'sourceArchive',
  'fullRepository',
  'rawScannerPayload',
  'policyOverride',
  'findingOverride',
  'enforcementAction',
  'blockRequested',
  'waiverApplied',
  'staleSuppressed'
];
const MAX_RUNTIME_ADVISORIES = 32;
const MAX_RUNTIME_SIGNALS = 32;
const MAX_RUNTIME_TEXT_BYTES = 2048;
const MAX_RUNTIME_METADATA_BYTES = 128;
const MAX_RUNTIME_SCAN_DEPTH = 12;
const MAX_RUNTIME_SCAN_COLLECTION = 64;
const MAX_RUNTIME_LATENCY_MILLISECONDS = 30_000;

@Injectable()
export class AiAdvisoryRuntimeClient {
  constructor(private readonly config: ConfigService) {}

  async createAdvisory(
    handoff: Readonly<SastAiAdvisoryHandoff>
  ): Promise<AiInferenceResponse> {
    if (!isSastAiAdvisoryHandoffShapeValid(handoff, digest)) {
      throw new BadGatewayException(
        'AI advisory handoff is malformed.'
      );
    }
    try {
      const timeoutMs = this.timeoutMs();
      const response = await axios.post(
        this.runtimeUrl(),
        this.toInferenceRequest(handoff, timeoutMs),
        { timeout: timeoutMs }
      );
      return this.parseRuntimeOutput(response.data, handoff);
    } catch (error) {
      if (error instanceof BadGatewayException) throw error;
      throw new BadGatewayException(
        'AI advisory runtime request failed.'
      );
    }
  }

  private toInferenceRequest(
    handoff: Readonly<SastAiAdvisoryHandoff>,
    maxLatencyMs: number
  ): AiInferenceRequest {
    const finding = handoff.normalizedFinding;
    const reference = handoff.reducedEvidenceReference;
    return {
      tenantId: handoff.tenantId,
      scanRequestId: handoff.scanRequestId,
      canonicalScanKey: [
        handoff.tenantId,
        handoff.repositoryBindingId,
        handoff.scanRequestId,
        handoff.attemptId,
        handoff.accessDecisionDigest,
        handoff.modelVersion
      ].join(':'),
      requestId: handoff.requestId,
      modelVersion: handoff.modelVersion,
      reducedEvidence: {
        findingIds: [finding.normalizedFindingId],
        scannerNames: [finding.scanner],
        evidencePackId: handoff.evidencePackId,
        summary: `${finding.title} (${finding.severity})`,
        snippets: [],
        metadata: {
          handoffVersion: handoff.version,
          handoffDigest: handoff.handoffDigest,
          requestDigest: handoff.requestDigest,
          repositoryBindingId: handoff.repositoryBindingId,
          attemptId: handoff.attemptId,
          occurrenceId: finding.occurrenceId,
          normalizedFindingId: finding.normalizedFindingId,
          findingFingerprint: finding.findingFingerprint,
          capability: finding.capability,
          severity: finding.severity,
          confidence: finding.confidence,
          scanner: finding.scanner,
          ruleSemanticId: finding.ruleSemanticId,
          ruleRevision: finding.ruleRevision,
          location: locationReference(finding.location),
          cweIds: finding.cweIds.join(','),
          cveIds: finding.cveIds.join(','),
          accessDecisionId: handoff.accessDecisionId,
          accessDecisionDigest: handoff.accessDecisionDigest,
          reducedEvidenceRef: reference.reducedEvidenceRef,
          redactedProjectionDigest:
            reference.redactedProjectionDigest,
          fragmentCount: reference.fragmentCount,
          payloadExpiresAt: handoff.payloadExpiresAt,
          retrievalAllowed: false,
          toolsAllowed: false,
          policyAuthority: false,
          publicationAuthority: false,
          lifecycleMutationAuthority: false,
          scmWriteAuthority: false,
          advisoryOnly: true
        },
        redactionState: 'reduced'
      },
      requestedCapabilities: ['detector', 'planner'],
      runtimePolicy: {
        allowFallback: true,
        maxLatencyMs
      },
      createdAt: handoff.createdAt
    };
  }

  private parseRuntimeOutput(
    input: unknown,
    handoff: Readonly<SastAiAdvisoryHandoff>
  ): AiInferenceResponse {
    if (!isRecord(input)) {
      throw new BadGatewayException(
        'AI advisory runtime response must be an object.'
      );
    }
    if (hasForbiddenRuntimeResponseKey(input)) {
      throw new BadGatewayException(
        'AI advisory runtime response contains forbidden authority or sensitive content.'
      );
    }
    const candidate = input as Partial<AiInferenceResponse>;
    const findingId =
      handoff.normalizedFinding.normalizedFindingId;
    if (
      candidate.requestId !== handoff.requestId ||
      candidate.tenantId !== handoff.tenantId ||
      candidate.scanRequestId !== handoff.scanRequestId ||
      candidate.advisoryOnly !== true ||
      !Array.isArray(candidate.detectorAdvisories) ||
      candidate.detectorAdvisories.length > MAX_RUNTIME_ADVISORIES ||
      !candidate.detectorAdvisories.every(
        (advisory) =>
          isDetectorAdvisory(advisory) &&
          advisory.findingId === findingId
      ) ||
      !Array.isArray(candidate.plannerAdvisories) ||
      candidate.plannerAdvisories.length > MAX_RUNTIME_ADVISORIES ||
      !candidate.plannerAdvisories.every(
        (advisory) =>
          isPlannerAdvisory(advisory) &&
          (advisory.findingId === undefined ||
            advisory.findingId === findingId)
      ) ||
      !isRecord(candidate.modelMetadata) ||
      !isBoundedRuntimeResponseText(
        candidate.modelMetadata.provider,
        MAX_RUNTIME_METADATA_BYTES
      ) ||
      !isBoundedRuntimeResponseText(
        candidate.modelMetadata.model,
        MAX_RUNTIME_METADATA_BYTES
      ) ||
      typeof candidate.modelMetadata.version !== 'string' ||
      candidate.modelMetadata.version !== handoff.modelVersion ||
      !isRecord(candidate.fallback) ||
      typeof candidate.fallback.used !== 'boolean' ||
      (candidate.fallback.reason !== undefined &&
        !isBoundedRuntimeResponseText(
          candidate.fallback.reason,
          MAX_RUNTIME_TEXT_BYTES
        )) ||
      typeof candidate.latencyMs !== 'number' ||
      !Number.isFinite(candidate.latencyMs) ||
      candidate.latencyMs < 0 ||
      candidate.latencyMs > MAX_RUNTIME_LATENCY_MILLISECONDS ||
      typeof candidate.createdAt !== 'string' ||
      !Number.isFinite(Date.parse(candidate.createdAt))
    ) {
      throw new BadGatewayException(
        'AI advisory runtime response is malformed.'
      );
    }
    return candidate as AiInferenceResponse;
  }

  private timeoutMs(): number {
    const configured = Number(
      this.config.get('AI_ADVISORY_TIMEOUT_MS')
    );
    return Number.isFinite(configured) &&
      configured > 0 &&
      configured <= MAX_RUNTIME_LATENCY_MILLISECONDS
      ? configured
      : 2500;
  }

  private runtimeUrl(): string {
    return `${this.config.get('AI_SERVER_URL').replace(/\/$/, '')}/ai/advisories`;
  }
}

function locationReference(
  location: Readonly<
    SastAiAdvisoryHandoff['normalizedFinding']['location']
  >
): string {
  if (location.kind === 'UNKNOWN') {
    return `UNKNOWN:${location.reasonCode}`;
  }
  const lines =
    location.lineEnd && location.lineEnd !== location.lineStart
      ? `${location.lineStart}-${location.lineEnd}`
      : String(location.lineStart);
  return `${location.normalizedPath}:${lines}`;
}

function isDetectorAdvisory(
  input: unknown
): input is AiInferenceResponse['detectorAdvisories'][number] {
  if (!isRecord(input)) return false;
  return (
    typeof input.findingId === 'string' &&
    typeof input.confidence === 'number' &&
    input.confidence >= 0 &&
    input.confidence <= 1 &&
    isBoundedRuntimeResponseText(
      input.rationale,
      MAX_RUNTIME_TEXT_BYTES
    ) &&
    Array.isArray(input.signals) &&
    input.signals.length <= MAX_RUNTIME_SIGNALS &&
    input.signals.every((signal) =>
      isBoundedRuntimeResponseText(signal, MAX_RUNTIME_TEXT_BYTES)
    )
  );
}

function isPlannerAdvisory(
  input: unknown
): input is AiInferenceResponse['plannerAdvisories'][number] {
  if (!isRecord(input)) return false;
  return (
    (input.findingId === undefined ||
      typeof input.findingId === 'string') &&
    isBoundedRuntimeResponseText(
      input.action,
      MAX_RUNTIME_TEXT_BYTES
    ) &&
    isBoundedRuntimeResponseText(
      input.rationale,
      MAX_RUNTIME_TEXT_BYTES
    ) &&
    (input.priority === 'low' ||
      input.priority === 'medium' ||
      input.priority === 'high')
  );
}

function hasForbiddenRuntimeResponseKey(
  input: unknown,
  depth = 0
): boolean {
  if (depth > MAX_RUNTIME_SCAN_DEPTH) return true;
  if (input === null || typeof input !== 'object') return false;
  if (Array.isArray(input)) {
    return input.length > MAX_RUNTIME_SCAN_COLLECTION ||
      input.some((item) =>
        hasForbiddenRuntimeResponseKey(item, depth + 1)
      );
  }
  const entries = Object.entries(input as Record<string, unknown>);
  return entries.length > MAX_RUNTIME_SCAN_COLLECTION || entries.some(
    ([key, value]) =>
      FORBIDDEN_RUNTIME_RESPONSE_KEYS.some(
        (forbidden) =>
          forbidden.toLowerCase() === key.toLowerCase()
      ) || hasForbiddenRuntimeResponseKey(value, depth + 1)
  );
}

function isBoundedRuntimeResponseText(
  value: unknown,
  maximumBytes: number
): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maximumBytes;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
