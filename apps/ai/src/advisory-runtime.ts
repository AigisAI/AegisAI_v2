import type {
  AiInferenceRequest,
  AiInferenceResponse
} from '@aegisai/shared';

import {
  AiInferenceValidationError,
  createDeterministicFallbackProvider,
  createModelGateway
} from './model-gateway';

export async function handleAiAdvisoryRequest(
  request: Request
): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === '/health') {
    return jsonResponse({ status: 'ok', service: 'ai-runtime' }, 200);
  }
  if (url.pathname !== '/ai/advisories') {
    return jsonResponse(
      { error: 'AI advisory route was not found.' },
      404
    );
  }
  if (request.method !== 'POST') {
    return jsonResponse(
      { error: 'AI advisory route only accepts POST.' },
      405
    );
  }

  try {
    const body = (await request.json()) as unknown;
    if (!isAiInferenceRequestLike(body)) {
      throw new AiInferenceValidationError(
        'AI advisory runtime requires a T043 reduced-reference handoff.',
        'FORBIDDEN_INPUT_CLASS'
      );
    }
    const gateway = createModelGateway({
      config: {
        providerId: 'deterministic',
        model: 'detector-planner-fallback',
        version: body.modelVersion,
        allowFallback: true
      },
      fallbackProvider: createDeterministicFallbackProvider()
    });
    return jsonResponse(await gateway.infer(body), 200);
  } catch (error) {
    return jsonResponse(
      {
        error: 'AI advisory request was rejected.',
        reasonCode:
          error instanceof AiInferenceValidationError
            ? error.rejectionReason
            : 'MALFORMED_REQUEST'
      },
      400
    );
  }
}

function isAiInferenceRequestLike(
  input: unknown
): input is AiInferenceRequest {
  return (
    isRecord(input) &&
    isRecord(input.reducedEvidence) &&
    Array.isArray(input.requestedCapabilities) &&
    isRecord(input.runtimePolicy)
  );
}

function jsonResponse(
  body: Record<string, unknown> | AiInferenceResponse,
  status: number
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
