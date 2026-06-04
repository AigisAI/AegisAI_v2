import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const manifestFiles = {
  hpa: new URL('../../deploy/kubernetes/ai-plane/horizontal-pod-autoscaler.json', import.meta.url),
  policy: new URL('../../deploy/kubernetes/ai-plane/autoscaling-policy.json', import.meta.url)
};

const forbiddenAuthorityFields =
  /enforcementAction|blockRequested|policyOverride|findingOverride|waiverApplied|staleSuppressed|createFinding|authoritativeFinding|suppressionOverride/i;

const readJson = (fileUrl) => JSON.parse(readFileSync(fileUrl, 'utf8'));

test('AI Plane runtime autoscaling manifests cover latency, queue, provider, fallback, CPU, and memory signals', () => {
  for (const [name, fileUrl] of Object.entries(manifestFiles)) {
    assert.equal(existsSync(fileUrl), true, `Expected ${name} manifest to exist at ${fileUrl.pathname}`);
  }

  const hpa = readJson(manifestFiles.hpa);
  const policy = readJson(manifestFiles.policy);
  const metricNames = hpa.spec.metrics.map((metric) => {
    if (metric.type === 'Resource') {
      return metric.resource.name;
    }

    return metric.pods.metric.name;
  });

  assert.equal(hpa.apiVersion, 'autoscaling/v2');
  assert.equal(hpa.kind, 'HorizontalPodAutoscaler');
  assert.equal(hpa.metadata.namespace, 'aegisai-ai-plane');
  assert.deepEqual(hpa.spec.scaleTargetRef, {
    apiVersion: 'apps/v1',
    kind: 'Deployment',
    name: 'aegisai-ai'
  });
  assert.equal(hpa.spec.minReplicas, 2);
  assert.equal(hpa.spec.maxReplicas, 10);
  assert.deepEqual(metricNames, [
    'cpu',
    'memory',
    'ai_request_latency_p95_ms',
    'ai_queue_depth',
    'ai_provider_error_rate',
    'ai_fallback_rate'
  ]);

  assert.equal(policy.kind, 'ConfigMap');
  assert.equal(policy.metadata.name, 'aegisai-ai-plane-autoscaling-policy');
  assert.equal(policy.metadata.namespace, 'aegisai-ai-plane');
  assert.equal(policy.data.RUNTIME_AUTOSCALING_POLICY, 'advisory-infrastructure-only');
  assert.equal(policy.data.LATENCY_P95_MS_TARGET, '750');
  assert.equal(policy.data.QUEUE_DEPTH_TARGET, '25');
  assert.equal(policy.data.PROVIDER_ERROR_RATE_TARGET, '5');
  assert.equal(policy.data.FALLBACK_RATE_TARGET, '10');
});

test('AI Plane runtime autoscaling policy cannot grant finding or policy authority', () => {
  const combinedManifestText = Object.values(manifestFiles)
    .map((fileUrl) => readFileSync(fileUrl, 'utf8'))
    .join('\n');
  const policy = readJson(manifestFiles.policy);
  const hpa = readJson(manifestFiles.hpa);

  assert.doesNotMatch(combinedManifestText, forbiddenAuthorityFields);
  assert.equal(policy.data.AI_POLICY_AUTHORITY, 'none');
  assert.equal(policy.data.AI_FINDING_AUTHORITY, 'none');
  assert.equal(policy.data.AI_WAIVER_SUPPRESSION_AUTHORITY, 'none');
  assert.equal(hpa.metadata.labels['aegisai.io/plane'], 'ai');
  assert.equal(hpa.metadata.annotations['aegisai.io/authority-boundary'], 'infrastructure-scaling-only');
});
