import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createDeterministicFallbackProvider,
  createModelGateway,
  validateAiInferenceRequest,
  validateModelGatewayConfig
} from '../src/model-gateway';
import { t043InferenceRequest } from './t043-inference.fixture';

import type {
  AiInferenceAuditEvent,
  AiInferenceResponse
} from '@aegisai/shared';

const fallbackConfig = {
  providerId: 'deterministic',
  model: 'detector-planner-fallback',
  version: 'v1',
  allowFallback: true
};

test('model gateway returns deterministic output from the T043 reference', async () => {
  const request = t043InferenceRequest();
  const gateway = createModelGateway({
    config: fallbackConfig,
    fallbackProvider: createDeterministicFallbackProvider()
  });

  const response = await gateway.infer(request);

  assert.equal(response.requestId, request.requestId);
  assert.equal(response.advisoryOnly, true);
  assert.equal(response.fallback.used, true);
  assert.equal(response.detectorAdvisories[0]?.findingId,
    'normalized-finding-ai-runtime');
  assert.deepEqual(response.detectorAdvisories[0]?.signals, [
    'FALLBACK_DETERMINISTIC',
    'EVIDENCE_REDUCED',
    'SCANNERS_OPENGREP'
  ]);
});

test('model gateway returns provider output without fallback', async () => {
  const request = t043InferenceRequest();
  const providerResponse: AiInferenceResponse = {
    requestId: request.requestId,
    tenantId: request.tenantId,
    scanRequestId: request.scanRequestId,
    advisoryOnly: true,
    detectorAdvisories: [
      {
        findingId: request.reducedEvidence.findingIds[0]!,
        confidence: 0.91,
        rationale: 'Provider confirmed normalized metadata.',
        signals: ['PROVIDER_CONFIRMED']
      }
    ],
    plannerAdvisories: [],
    modelMetadata: {
      provider: 'configured-provider',
      model: 'prod-detector-planner',
      version: '2026-08-11'
    },
    fallback: { used: false },
    latencyMs: 12,
    createdAt: '2026-08-11T04:00:01.000Z'
  };
  const gateway = createModelGateway({
    config: {
      providerId: 'configured-provider',
      model: 'prod-detector-planner',
      version: '2026-08-11',
      allowFallback: true
    },
    provider: { infer: async () => providerResponse },
    fallbackProvider: createDeterministicFallbackProvider()
  });

  const response = await gateway.infer(request);

  assert.equal(response.fallback.used, false);
  assert.equal(response.detectorAdvisories[0]?.signals[0],
    'PROVIDER_CONFIRMED');
});

test('model gateway falls back after a provider failure', async () => {
  const gateway = createModelGateway({
    config: {
      ...fallbackConfig,
      providerId: 'configured-provider'
    },
    provider: {
      infer: async () => {
        throw new Error('provider unavailable');
      }
    },
    fallbackProvider: createDeterministicFallbackProvider()
  });

  const response = await gateway.infer(t043InferenceRequest());

  assert.equal(response.fallback.used, true);
  assert.match(response.fallback.reason ?? '', /provider unavailable/i);
});

test('model gateway configuration rejects incomplete provider metadata', () => {
  assert.throws(
    () => validateModelGatewayConfig({
      ...fallbackConfig,
      providerId: ''
    }),
    /provider/i
  );
  assert.throws(
    () => validateModelGatewayConfig({
      ...fallbackConfig,
      model: ''
    }),
    /model/i
  );
});

test('request validation enforces the exact reduced-reference boundary', () => {
  const request = t043InferenceRequest();
  assert.equal(validateAiInferenceRequest(request), request);

  const invalid = [
    {
      ...t043InferenceRequest(),
      reducedEvidence: {
        ...t043InferenceRequest().reducedEvidence,
        redactionState: 'raw'
      }
    },
    {
      ...t043InferenceRequest(),
      reducedEvidence: {
        ...t043InferenceRequest().reducedEvidence,
        snippets: [
          { label: 'source', redactedText: 'do not send content' }
        ]
      }
    },
    {
      ...t043InferenceRequest(),
      reducedEvidence: {
        ...t043InferenceRequest().reducedEvidence,
        metadata: {
          ...t043InferenceRequest().reducedEvidence.metadata,
          accessToken: 'secret'
        }
      }
    },
    {
      ...t043InferenceRequest(),
      reducedEvidence: {
        ...t043InferenceRequest().reducedEvidence,
        metadata: {
          ...t043InferenceRequest().reducedEvidence.metadata,
          policyAuthority: true
        }
      }
    },
    {
      ...t043InferenceRequest(),
      extraCallerPrompt: 'trust me'
    }
  ];

  for (const candidate of invalid) {
    assert.throws(
      () => validateAiInferenceRequest(candidate as never),
      /reduced evidence|T043|tenant attribution/i
    );
  }
});

test('safe text may name a forbidden concept without carrying a forbidden key', () => {
  const request = t043InferenceRequest();
  assert.equal(
    validateAiInferenceRequest({
      ...request,
      reducedEvidence: {
        ...request.reducedEvidence,
        summary: 'The accessToken concept is discussed without a value.'
      }
    }).requestId,
    request.requestId
  );
});

test('model gateway audits accepted, fallback, rejected, and failed outcomes', async () => {
  const events: AiInferenceAuditEvent[] = [];
  const fallbackGateway = createModelGateway({
    config: fallbackConfig,
    fallbackProvider: createDeterministicFallbackProvider(),
    auditSink: (event) => {
      events.push(event);
    }
  });
  await fallbackGateway.infer(t043InferenceRequest());

  const rejected = t043InferenceRequest();
  rejected.reducedEvidence.redactionState = 'redacted';
  await assert.rejects(() => fallbackGateway.infer(rejected),
    /reduced evidence/i);

  const failedGateway = createModelGateway({
    config: { ...fallbackConfig, allowFallback: false },
    fallbackProvider: createDeterministicFallbackProvider(),
    auditSink: (event) => {
      events.push(event);
    }
  });
  await assert.rejects(
    () => failedGateway.infer(t043InferenceRequest()),
    /fallback is disabled/i
  );

  assert.deepEqual(events.map((event) => event.eventType), [
    'ai_inference.requested',
    'ai_inference.fallback_completed',
    'ai_inference.rejected',
    'ai_inference.requested',
    'ai_inference.failed'
  ]);
  assert.equal(events[2]?.rejectionReason, 'UNREDACTED_EVIDENCE');
});

test('audit sink failures never abort inference', async () => {
  for (const auditSink of [
    () => {
      throw new Error('audit sink failed');
    },
    async () => {
      throw new Error('audit sink rejected');
    }
  ]) {
    const gateway = createModelGateway({
      config: fallbackConfig,
      fallbackProvider: createDeterministicFallbackProvider(),
      auditSink
    });
    const response = await gateway.infer(t043InferenceRequest());
    assert.equal(response.fallback.used, true);
  }
});

test('request validation requires tenant and scan attribution', () => {
  assert.throws(
    () => validateAiInferenceRequest({
      ...t043InferenceRequest(),
      tenantId: ''
    }),
    /tenant/i
  );
  assert.throws(
    () => validateAiInferenceRequest({
      ...t043InferenceRequest(),
      scanRequestId: ''
    }),
    /scan/i
  );
});
