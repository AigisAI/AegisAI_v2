import {
  isSastAiAdvisoryHandoffShapeValid,
  type AiInferenceRequest,
  type AiInferenceResponse,
  type SastAiAdvisoryHandoff
} from '@aegisai/shared';
import { BadGatewayException, Injectable } from '@nestjs/common';
import axios from 'axios';
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
      const response = await axios.post(
        this.runtimeUrl(),
        this.toInferenceRequest(handoff),
        { timeout: this.config.get('AI_ADVISORY_TIMEOUT_MS') }
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
    handoff: Readonly<SastAiAdvisoryHandoff>
  ): AiInferenceRequest {
    const maxLatencyMs = Number(
      this.config.get('AI_ADVISORY_TIMEOUT_MS')
    );
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
        maxLatencyMs: Number.isFinite(maxLatencyMs)
          ? maxLatencyMs
          : 2500
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
      !candidate.detectorAdvisories.every(
        (advisory) =>
          isDetectorAdvisory(advisory) &&
          advisory.findingId === findingId
      ) ||
      !Array.isArray(candidate.plannerAdvisories) ||
      !candidate.plannerAdvisories.every(
        (advisory) =>
          isPlannerAdvisory(advisory) &&
          (advisory.findingId === undefined ||
            advisory.findingId === findingId)
      ) ||
      !isRecord(candidate.modelMetadata) ||
      typeof candidate.modelMetadata.provider !== 'string' ||
      typeof candidate.modelMetadata.model !== 'string' ||
      typeof candidate.modelMetadata.version !== 'string' ||
      candidate.modelMetadata.version !== handoff.modelVersion ||
      !isRecord(candidate.fallback) ||
      typeof candidate.fallback.used !== 'boolean' ||
      (candidate.fallback.reason !== undefined &&
        typeof candidate.fallback.reason !== 'string') ||
      typeof candidate.latencyMs !== 'number' ||
      !Number.isFinite(candidate.latencyMs) ||
      candidate.latencyMs < 0 ||
      typeof candidate.createdAt !== 'string' ||
      !Number.isFinite(Date.parse(candidate.createdAt))
    ) {
      throw new BadGatewayException(
        'AI advisory runtime response is malformed.'
      );
    }
    return candidate as AiInferenceResponse;
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
    typeof input.rationale === 'string' &&
    Array.isArray(input.signals) &&
    input.signals.every((signal) => typeof signal === 'string')
  );
}

function isPlannerAdvisory(
  input: unknown
): input is AiInferenceResponse['plannerAdvisories'][number] {
  if (!isRecord(input)) return false;
  return (
    (input.findingId === undefined ||
      typeof input.findingId === 'string') &&
    typeof input.action === 'string' &&
    typeof input.rationale === 'string' &&
    (input.priority === 'low' ||
      input.priority === 'medium' ||
      input.priority === 'high')
  );
}

function hasForbiddenRuntimeResponseKey(input: unknown): boolean {
  if (input === null || typeof input !== 'object') return false;
  if (Array.isArray(input)) {
    return input.some((item) => hasForbiddenRuntimeResponseKey(item));
  }
  return Object.entries(input as Record<string, unknown>).some(
    ([key, value]) =>
      FORBIDDEN_RUNTIME_RESPONSE_KEYS.some(
        (forbidden) =>
          forbidden.toLowerCase() === key.toLowerCase()
      ) || hasForbiddenRuntimeResponseKey(value)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
