import type { AiInferenceRequest } from '@aegisai/shared';

const REQUEST_DIGEST = `sha256:${'a'.repeat(64)}`;

export function t043InferenceRequest(
  referenceTime = Date.now()
): AiInferenceRequest {
  const createdAt = new Date(referenceTime).toISOString();
  const payloadExpiresAt = new Date(
    referenceTime + 60 * 60 * 1000
  ).toISOString();
  return {
    tenantId: 'tenant-ai-runtime',
    scanRequestId: 'scan-ai-runtime',
    canonicalScanKey: [
      'tenant-ai-runtime',
      'repository-ai-runtime',
      'scan-ai-runtime',
      'attempt-ai-runtime',
      `sha256:${'d'.repeat(64)}`
    ].join(':'),
    requestId: `sast-ai-request://${'a'.repeat(64)}`,
    reducedEvidence: {
      findingIds: ['normalized-finding-ai-runtime'],
      scannerNames: ['OPENGREP'],
      evidencePackId: `sast-evidence-pack://${'e'.repeat(64)}`,
      summary: 'Unsafe deserialization (HIGH)',
      snippets: [],
      metadata: {
        handoffVersion: 'sast-ai-advisory-handoff-v1',
        handoffDigest: `sha256:${'b'.repeat(64)}`,
        requestDigest: REQUEST_DIGEST,
        repositoryBindingId: 'repository-ai-runtime',
        attemptId: 'attempt-ai-runtime',
        occurrenceId: `finding-occurrence://${'f'.repeat(64)}`,
        normalizedFindingId: 'normalized-finding-ai-runtime',
        findingFingerprint: `sha256:${'c'.repeat(64)}`,
        capability: 'SAST',
        severity: 'HIGH',
        confidence: 'HIGH',
        scanner: 'OPENGREP',
        ruleSemanticId: 'java.unsafe-deserialization',
        ruleRevision: '1.0.0',
        location: 'src/App.java:42',
        cweIds: 'CWE-502',
        cveIds: '',
        accessDecisionId: `sast-evidence-access://${'7'.repeat(64)}`,
        accessDecisionDigest: `sha256:${'d'.repeat(64)}`,
        reducedEvidenceRef: `sast-reduced-evidence://${'8'.repeat(64)}`,
        redactedProjectionDigest: `sha256:${'9'.repeat(64)}`,
        fragmentCount: 1,
        payloadExpiresAt,
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
      maxLatencyMs: 2500
    },
    createdAt
  };
}
