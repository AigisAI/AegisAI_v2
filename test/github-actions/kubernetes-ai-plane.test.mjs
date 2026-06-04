import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const manifestFiles = {
  namespace: new URL('../../deploy/kubernetes/ai-plane/namespace.json', import.meta.url),
  configMap: new URL('../../deploy/kubernetes/ai-plane/configmap.json', import.meta.url),
  deployment: new URL('../../deploy/kubernetes/ai-plane/deployment.json', import.meta.url),
  service: new URL('../../deploy/kubernetes/ai-plane/service.json', import.meta.url),
  networkPolicy: new URL('../../deploy/kubernetes/ai-plane/network-policy.json', import.meta.url)
};

const forbiddenBoundaryFields =
  /scmCredential|githubToken|gitlabToken|accessToken|refreshToken|tokenValue|secretValue|repositoryArchive|fullRepository|sourceArchive|rawScannerPayload|policyOverride|findingOverride|waiverApplied|staleSuppressed/i;

const readJson = (fileUrl) => JSON.parse(readFileSync(fileUrl, 'utf8'));

test('Kubernetes AI Plane manifests exist and describe the expected resource boundary', () => {
  for (const [name, fileUrl] of Object.entries(manifestFiles)) {
    assert.equal(existsSync(fileUrl), true, `Expected ${name} manifest to exist at ${fileUrl.pathname}`);
  }

  const namespace = readJson(manifestFiles.namespace);
  const configMap = readJson(manifestFiles.configMap);
  const deployment = readJson(manifestFiles.deployment);
  const service = readJson(manifestFiles.service);
  const networkPolicy = readJson(manifestFiles.networkPolicy);

  assert.equal(namespace.kind, 'Namespace');
  assert.equal(namespace.metadata.name, 'aegisai-ai-plane');

  assert.equal(configMap.kind, 'ConfigMap');
  assert.equal(configMap.metadata.namespace, 'aegisai-ai-plane');
  assert.equal(configMap.data.AI_ADVISORY_ONLY, 'true');
  assert.equal(configMap.data.AI_REDUCED_EVIDENCE_ONLY, 'true');
  assert.equal(configMap.data.AI_HEALTH_PATH, '/health');

  assert.equal(deployment.kind, 'Deployment');
  assert.equal(deployment.metadata.namespace, 'aegisai-ai-plane');
  assert.equal(deployment.spec.selector.matchLabels['app.kubernetes.io/name'], 'aegisai-ai');
  assert.equal(deployment.spec.template.spec.automountServiceAccountToken, false);

  const container = deployment.spec.template.spec.containers.find((candidate) => candidate.name === 'aegisai-ai');
  assert.ok(container, 'Expected aegisai-ai container to be present');
  assert.equal(container.image, 'ghcr.io/aigisai/aegisai-ai:latest');
  assert.deepEqual(container.ports, [{ name: 'http', containerPort: 8000 }]);
  assert.deepEqual(container.livenessProbe.httpGet, { path: '/health', port: 'http' });
  assert.deepEqual(container.readinessProbe.httpGet, { path: '/health', port: 'http' });
  assert.equal(container.securityContext.runAsNonRoot, true);
  assert.equal(container.securityContext.readOnlyRootFilesystem, true);
  assert.equal(container.envFrom[0].configMapRef.name, 'aegisai-ai-plane-config');

  assert.equal(service.kind, 'Service');
  assert.equal(service.metadata.namespace, 'aegisai-ai-plane');
  assert.equal(service.spec.type, 'ClusterIP');
  assert.deepEqual(service.spec.selector, deployment.spec.selector.matchLabels);
  assert.deepEqual(service.spec.ports, [{ name: 'http', port: 8000, targetPort: 'http' }]);

  assert.equal(networkPolicy.kind, 'NetworkPolicy');
  assert.equal(networkPolicy.metadata.namespace, 'aegisai-ai-plane');
  assert.deepEqual(networkPolicy.spec.podSelector.matchLabels, deployment.spec.selector.matchLabels);
  assert.deepEqual(networkPolicy.spec.policyTypes, ['Ingress', 'Egress']);
});

test('Kubernetes AI Plane manifests do not expose repository or policy authority inputs', () => {
  const combinedManifestText = Object.values(manifestFiles)
    .map((fileUrl) => readFileSync(fileUrl, 'utf8'))
    .join('\n');
  const deployment = readJson(manifestFiles.deployment);
  const configMap = readJson(manifestFiles.configMap);
  const container = deployment.spec.template.spec.containers.find((candidate) => candidate.name === 'aegisai-ai');
  const envNames = (container.env ?? []).map((entry) => entry.name);
  const volumeNames = (deployment.spec.template.spec.volumes ?? []).map((entry) => entry.name);
  const mounts = (container.volumeMounts ?? []).map((entry) => entry.mountPath);

  assert.doesNotMatch(combinedManifestText, forbiddenBoundaryFields);
  assert.deepEqual(envNames, ['AI_PORT']);
  assert.deepEqual(volumeNames, []);
  assert.deepEqual(mounts, []);
  assert.equal(configMap.data.AI_INPUT_BOUNDARY, 'normalized-findings-and-reduced-evidence-only');
  assert.equal(configMap.data.AI_POLICY_AUTHORITY, 'none');
  assert.equal(configMap.data.AI_FINDING_AUTHORITY, 'none');
});
