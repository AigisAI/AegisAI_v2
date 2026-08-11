import type { AiInferenceResponse } from '@aegisai/shared';
import axios from 'axios';

import { AiAdvisoryRuntimeClient } from '../../src/ai-plane/ai-advisory-runtime.client';
import { aiHandoff } from '../support/sast-ai-advisory-fixture';

jest.mock('axios');
const mockedAxios = jest.mocked(axios);

describe('AiAdvisoryRuntimeClient T043 boundary', () => {
  beforeEach(() => mockedAxios.post.mockReset());

  it('sends only normalized metadata and an opaque reduced reference', async () => {
    const handoff = aiHandoff();
    const runtimeResponse = responseFor(handoff.requestId);
    mockedAxios.post.mockResolvedValueOnce({ data: runtimeResponse });
    const client = new AiAdvisoryRuntimeClient(runtimeConfig());

    const result = await client.createAdvisory(handoff);
    const inferenceRequest = mockedAxios.post.mock.calls[0]?.[1] as {
      reducedEvidence: {
        snippets: unknown[];
        metadata: Record<string, unknown>;
      };
    };

    expect(mockedAxios.post).toHaveBeenCalledWith(
      'https://ai-runtime.example/ai/advisories',
      expect.objectContaining({
        tenantId: 'tenant-ai',
        scanRequestId: 'scan-ai',
        requestId: handoff.requestId,
        reducedEvidence: expect.objectContaining({
          findingIds: ['normalized-finding-ai'],
          evidencePackId: handoff.evidencePackId,
          scannerNames: ['OPENGREP'],
          snippets: [],
          redactionState: 'reduced',
          metadata: expect.objectContaining({
            handoffVersion: 'sast-ai-advisory-handoff-v1',
            handoffDigest: handoff.handoffDigest,
            requestDigest: handoff.requestDigest,
            normalizedFindingId: 'normalized-finding-ai',
            reducedEvidenceRef:
              handoff.reducedEvidenceReference.reducedEvidenceRef,
            retrievalAllowed: false,
            toolsAllowed: false,
            policyAuthority: false,
            lifecycleMutationAuthority: false,
            scmWriteAuthority: false,
            advisoryOnly: true
          })
        }),
        requestedCapabilities: ['detector', 'planner'],
        runtimePolicy: { allowFallback: true, maxLatencyMs: 2500 }
      }),
      { timeout: 2500 }
    );
    expect(inferenceRequest.reducedEvidence.snippets).toEqual([]);
    expect(inferenceRequest.reducedEvidence.metadata).not.toHaveProperty(
      'redactedContent'
    );
    expect(result).toEqual(runtimeResponse);
    expect(JSON.stringify(mockedAxios.post.mock.calls)).not.toMatch(
      /accessToken|secretValue|sourceArchive|fullRepository|rawScannerPayload|redactedContent/i
    );
  });

  it('rejects authority-bearing or cross-request runtime responses', async () => {
    const handoff = aiHandoff();
    const client = new AiAdvisoryRuntimeClient(runtimeConfig());
    mockedAxios.post.mockResolvedValueOnce({
      data: { ...responseFor(handoff.requestId), enforcementAction: 'BLOCK' }
    });
    await expect(client.createAdvisory(handoff)).rejects.toThrow(
      'AI advisory runtime response contains forbidden authority or sensitive content.'
    );

    mockedAxios.post.mockResolvedValueOnce({
      data: responseFor('sast-ai-request://' + 'f'.repeat(64))
    });
    await expect(client.createAdvisory(handoff)).rejects.toThrow(
      'AI advisory runtime response is malformed.'
    );
  });

  it('rejects a tampered handoff before any provider request', async () => {
    const handoff = aiHandoff();
    const client = new AiAdvisoryRuntimeClient(runtimeConfig());
    await expect(
      client.createAdvisory({
        ...handoff,
        authority: { ...handoff.authority, toolsAllowed: true }
      } as never)
    ).rejects.toThrow('AI advisory handoff is malformed.');
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });
});

function responseFor(requestId: string): AiInferenceResponse {
  return {
    requestId,
    tenantId: 'tenant-ai',
    scanRequestId: 'scan-ai',
    advisoryOnly: true,
    detectorAdvisories: [
      {
        findingId: 'normalized-finding-ai',
        confidence: 0.91,
        rationale: 'Model gateway mapped the reduced reference.',
        signals: ['SCANNER_CONFIRMED', 'MODEL_TRIAGED']
      }
    ],
    plannerAdvisories: [
      {
        findingId: 'normalized-finding-ai',
        action: 'Review normalized scanner evidence.',
        rationale: 'Advisory planning remains non-authoritative.',
        priority: 'high'
      }
    ],
    modelMetadata: {
      provider: 'deterministic',
      model: 'detector-planner-runtime',
      version: '2026-08-11'
    },
    fallback: { used: true, reason: 'provider not configured' },
    latencyMs: 13,
    createdAt: '2026-08-11T04:00:00.450Z'
  };
}

function runtimeConfig() {
  return {
    get: jest.fn((key: string) => {
      const values: Record<string, string | number> = {
        AI_SERVER_URL: 'https://ai-runtime.example',
        AI_ADVISORY_TIMEOUT_MS: 2500
      };
      return values[key];
    })
  } as never;
}
