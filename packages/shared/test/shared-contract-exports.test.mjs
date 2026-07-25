import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const files = {
  common: new URL('../src/types/common.ts', import.meta.url),
  auth: new URL('../src/types/auth.ts', import.meta.url),
  repo: new URL('../src/types/repo.ts', import.meta.url),
  scan: new URL('../src/types/scan.ts', import.meta.url),
  vulnerability: new URL('../src/types/vulnerability.ts', import.meta.url),
  dashboard: new URL('../src/types/dashboard.ts', import.meta.url),
  report: new URL('../src/types/report.ts', import.meta.url),
  aiInferenceRuntime: new URL('../src/types/ai-inference-runtime.ts', import.meta.url),
  deploymentOperations: new URL('../src/types/deployment-operations.ts', import.meta.url),
  sastRuntime: new URL('../src/types/sast-runtime.ts', import.meta.url),
  sastArtifactValidation: new URL(
    '../src/types/sast-artifact-validation.ts',
    import.meta.url
  ),
  sastPlanning: new URL('../src/types/sast-planning.ts', import.meta.url),
  sastFetch: new URL('../src/types/sast-fetch.ts', import.meta.url),
  sastWrapper: new URL('../src/types/sast-wrapper.ts', import.meta.url),
  index: new URL('../src/index.ts', import.meta.url)
};

test('shared contract modules exist and are re-exported from the package root', () => {
  for (const [name, fileUrl] of Object.entries(files)) {
    assert.equal(existsSync(fileUrl), true, `Expected ${name} file to exist at ${fileUrl.pathname}`);
  }

  const indexContent = readFileSync(files.index, 'utf8');

  for (const moduleName of [
    'common',
    'auth',
    'repo',
    'scan',
    'vulnerability',
    'dashboard',
    'report',
    'ai-inference-runtime',
    'deployment-operations',
    'sast-runtime',
    'sast-artifact-validation',
    'sast-planning',
    'sast-fetch',
    'sast-wrapper'
  ]) {
    assert.match(
      indexContent,
      new RegExp(`export \\* from './types/${moduleName}'`),
      `Expected packages/shared/src/index.ts to re-export ./types/${moduleName}`
    );
  }
});

test('SAST wrapper contracts expose only fixed invocation and bounded observation metadata', () => {
  const contract = readFileSync(files.sastWrapper, 'utf8');

  const allowedExportNames = [
    'MAX_SAST_SANDBOX_ATTESTATION_TTL_SECONDS',
    'SAST_SANDBOX_ATTESTATION_AUDIENCE',
    'SAST_SANDBOX_ATTESTATION_ISSUER',
    'SAST_SANDBOX_ATTESTATION_VERSION',
    'SAST_SANDBOX_CLEANUP_TIMEOUT_SECONDS',
    'SAST_SCANNER_ASSET_ROOT',
    'SAST_SCANNER_OUTPUT_ROOT',
    'SAST_SCANNER_PLAN_DIGEST_VERSION',
    'SAST_SCANNER_RUNTIME_EVENT_TYPES',
    'SAST_SCANNER_SELECTED_WORKSPACE_ROOT',
    'SAST_SCANNER_WORKING_DIRECTORY',
    'SAST_SCANNER_WORKSPACE_ROOT',
    'SAST_SCANNER_WRAPPER_SCHEMA_VERSION',
    'SastBoundedLogObservation',
    'SastSandboxCleanupObservation',
    'SastSandboxRuntimeAttestation',
    'SastSandboxRuntimeAttestationClaims',
    'SastSandboxRuntimePolicy',
    'SastScannerArtifactObservation',
    'SastScannerExecutionRecord',
    'SastScannerInputBinding',
    'SastScannerInvocation',
    'SastScannerPreflightBinding',
    'SastScannerProcessObservation',
    'SastScannerRepositoryManifest',
    'SastScannerResourceObservation',
    'SastScannerRuntimeAuditSignal',
    'SastScannerRuntimeEventType',
    'SastScannerRuntimeExecutionResult',
    'SastScannerWrapperExecutionRequest',
    'SastSignedSandboxCleanupObservation',
    'buildSastScanPlanDigestPreimage',
    'deriveScannerExecutionStatus',
    'isSastSandboxRuntimePolicyValid',
    'isSastScannerInvocationBoundToPlan',
    'isSastScannerProcessObservationValid',
    'isSastScannerWrapperExecutionRequestValid',
    'scannerRuntimeLimits'
  ];
  const exportedNames = [
    ...contract.matchAll(
      /^export\s+(?:interface|const|function|type)\s+([A-Za-z_]\w*)\b/gm
    )
  ].map((match) => match[1]);

  assert.deepEqual(
    [...new Set(exportedNames)].sort(),
    [...allowedExportNames].sort()
  );
  for (const exportName of allowedExportNames) {
    assert.match(contract, new RegExp(`export (interface|const|function|type) ${exportName}\\b`));
  }

  for (const forbiddenInput of [
    'customerCommand',
    'customerArgs',
    'customerEnvironment',
    'pluginBody',
    'executableConfigBody',
    'repositoryContent',
    'credentialValue'
  ]) {
    assert.doesNotMatch(contract, new RegExp(`\\b${forbiddenInput}\\b`, 'i'));
  }

  assert.match(contract, /shellInterpolationAllowed:\s*false/);
  assert.match(contract, /publicInternetEgressAllowed:\s*false/);
  assert.match(contract, /runtimeAssetUpdateAllowed:\s*false/);
  assert.match(
    contract,
    /SAST_SCANNER_SELECTED_WORKSPACE_ROOT\s*=\s*[\r\n\s]*'\/workspace\/selected'/
  );
  assert.match(contract, /artifact\.byteSize\s*>\s*0/);
});

test('AI inference runtime contracts are advisory-only and exclude forbidden payload fields', () => {
  assert.equal(existsSync(files.aiInferenceRuntime), true);

  const contract = readFileSync(files.aiInferenceRuntime, 'utf8');

  for (const exportName of [
    'ReducedEvidence',
    'AiInferenceRequest',
    'AiInferenceResponse',
    'AiDetectorAdvisory',
    'AiPlannerAdvisory',
    'AiInferenceAuditEvent',
    'AI_INFERENCE_REJECTION_REASONS'
  ]) {
    assert.match(contract, new RegExp(`export (interface|const|type) ${exportName}\\b`));
  }

  for (const forbiddenField of [
    'scmCredential',
    'scmToken',
    'repositoryArchive',
    'sourceArchive',
    'fullRepository',
    'rawScannerPayload',
    'authoritativeFinding',
    'policyOverride'
  ]) {
    assert.doesNotMatch(contract, new RegExp(`\\b${forbiddenField}\\b`, 'i'));
  }

  assert.match(contract, /advisoryOnly:\s*true/);
  assert.match(contract, /redactionState:\s*'redacted'\s*\|\s*'reduced'/);
  assert.match(contract, /fallback:\s*AiInferenceFallback/);
});
