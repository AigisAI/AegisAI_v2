import assert from 'node:assert/strict';
import test from 'node:test';

import { handleAiAdvisoryRequest } from '../src/advisory-runtime';
import { t043InferenceRequest } from './t043-inference.fixture';

function advisoryHttpRequest(body: unknown): Request {
  return new Request('http://127.0.0.1:8000/ai/advisories', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
}

test('POST /ai/advisories accepts only the T043 reduced-reference request', async () => {
  const request = t043InferenceRequest();
  const response = await handleAiAdvisoryRequest(
    advisoryHttpRequest(request)
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.requestId, request.requestId);
  assert.equal(body.tenantId, request.tenantId);
  assert.equal(body.scanRequestId, request.scanRequestId);
  assert.equal(body.advisoryOnly, true);
  assert.equal(body.fallback.used, true);
  assert.equal(body.modelMetadata.version, request.modelVersion);
  assert.deepEqual(body.detectorAdvisories[0].signals, [
    'FALLBACK_DETERMINISTIC',
    'EVIDENCE_REDUCED',
    'SCANNERS_OPENGREP'
  ]);
});

test('GET /health returns the AI runtime health status', async () => {
  const response = await handleAiAdvisoryRequest(
    new Request('http://127.0.0.1:8000/health')
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    service: 'ai-runtime',
    status: 'ok'
  });
});

test('POST /ai/advisories rejects the legacy direct finding payload', async () => {
  const response = await handleAiAdvisoryRequest(
    advisoryHttpRequest({
      tenantId: 'tenant-ai-runtime',
      scanRequestId: 'scan-ai-runtime',
      normalizedFinding: { title: 'caller supplied' },
      evidence: { redacted: true },
      modelVersion: 'legacy-v1'
    })
  );
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /T043 reduced-reference handoff/i);
});

test('POST /ai/advisories rejects unknown fields and authority escalation', async () => {
  const cases = [
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
          toolsAllowed: true
        }
      }
    }
  ];

  for (const input of cases) {
    const response = await handleAiAdvisoryRequest(
      advisoryHttpRequest(input)
    );
    assert.equal(response.status, 400);
  }
});

test('POST /ai/advisories never returns secrets or decision authority', async () => {
  const response = await handleAiAdvisoryRequest(
    advisoryHttpRequest(t043InferenceRequest())
  );
  const serialized = JSON.stringify(await response.json());

  assert.doesNotMatch(
    serialized,
    /accessToken|refreshToken|secretValue|sourceArchive|rawScannerPayload/i
  );
  assert.doesNotMatch(
    serialized,
    /policyOverride|findingOverride|enforcementAction|blockRequested/i
  );
});
