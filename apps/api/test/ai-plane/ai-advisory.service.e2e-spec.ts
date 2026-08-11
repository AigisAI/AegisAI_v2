import type {
  AiAdvisoryResult,
  AiInferenceResponse,
  SastAiAdvisoryHandoff
} from '@aegisai/shared';
import { Logger } from '@nestjs/common';

import { AiAdvisoryService } from '../../src/ai-plane/ai-advisory.service';
import {
  aiAdvisoryIntent,
  aiNormalizedFinding,
  allowedAiAccess
} from '../support/sast-ai-advisory-fixture';

describe('AiAdvisoryService T043 handoff', () => {
  afterEach(() => jest.restoreAllMocks());

  it('derives an advisory from durable scope and never accepts caller payloads', async () => {
    const access = allowedAiAccess();
    const evidenceAccess = {
      classifyForAi: jest.fn().mockResolvedValue(access)
    };
    const store = memoryStore(access.decision);
    const runtime = { createAdvisory: jest.fn() };
    const service = new AiAdvisoryService(
      config(false),
      runtime as never,
      evidenceAccess as never,
      store as never
    );

    const advisory = await service.createAdvisory(
      aiAdvisoryIntent(),
      clock()
    );

    expect(evidenceAccess.classifyForAi).toHaveBeenCalledTimes(2);
    expect(evidenceAccess.classifyForAi).toHaveBeenNthCalledWith(
      1,
      {
        tenantId: 'tenant-ai',
        repositoryBindingId: 'repository-ai',
        evidencePackId: aiAdvisoryIntent().evidencePackId
      },
      expect.any(Function)
    );
    expect(store.loadNormalizedFinding).toHaveBeenCalledWith(
      access.decision
    );
    expect(store.persistHandoff).toHaveBeenCalledWith(
      expect.objectContaining({
        version: 'sast-ai-advisory-handoff-v1',
        tenantId: 'tenant-ai',
        evidencePackId: aiAdvisoryIntent().evidencePackId,
        authority: expect.objectContaining({
          aiProviderCallAllowed: true,
          retrievalAllowed: false,
          toolsAllowed: false,
          policyAuthority: false,
          lifecycleMutationAuthority: false,
          scmWriteAuthority: false
        }),
        audit: expect.objectContaining({
          callerFindingAccepted: false,
          callerEvidenceAccepted: false,
          requestPayloadStored: false
        })
      })
    );
    expect(runtime.createAdvisory).not.toHaveBeenCalled();
    expect(advisory).toEqual(
      expect.objectContaining({
        id: expect.stringMatching(/^sast-ai-advisory:\/\//u),
        sastHandoffId: expect.stringMatching(
          /^sast-ai-handoff:\/\//u
        ),
        tenantId: 'tenant-ai',
        scanRequestId: 'scan-ai',
        findingId: 'normalized-finding-ai',
        advisoryOnly: true,
        redactedEvidenceOnly: true,
        detectorSignals: expect.arrayContaining([
          'T043_REDUCED_REFERENCE_ONLY'
        ])
      })
    );
    expect(JSON.stringify({ advisory, calls: store.persistHandoff.mock.calls }))
      .not.toMatch(
        /sourceArchive|fullRepository|rawScannerPayload|redactedContent|policyOverride|findingOverride|"secretValue"\s*:/i
      );
  });

  it('rejects the legacy caller-supplied finding and evidence shape before access', async () => {
    const evidenceAccess = { classifyForAi: jest.fn() };
    const access = allowedAiAccess();
    const store = memoryStore(access.decision);
    const service = new AiAdvisoryService(
      config(false),
      { createAdvisory: jest.fn() } as never,
      evidenceAccess as never,
      store as never
    );

    await expect(
      service.createAdvisory({
        ...aiAdvisoryIntent(),
        normalizedFinding: { title: 'caller supplied' },
        evidence: { redacted: true }
      } as never)
    ).rejects.toThrow(
      'AI advisory intent must contain only durable scope identifiers.'
    );
    expect(evidenceAccess.classifyForAi).not.toHaveBeenCalled();
    expect(store.persistHandoff).not.toHaveBeenCalled();
  });

  it('fails closed on durable finding drift or a changed final access decision', async () => {
    const access = allowedAiAccess();
    const denied = {
      outcome: 'DENIED' as const,
      reasonCode: 'EVIDENCE_ACCESS_DELETION_PENDING' as const,
      decision: access.decision,
      replayed: false,
      dashboardEvidence: null,
      reducedEvidenceReference: null
    };
    const evidenceAccess = {
      classifyForAi: jest
        .fn()
        .mockResolvedValueOnce(access)
        .mockResolvedValueOnce(denied)
    };
    const store = memoryStore(access.decision);
    const service = new AiAdvisoryService(
      config(false),
      { createAdvisory: jest.fn() } as never,
      evidenceAccess as never,
      store as never
    );

    await expect(
      service.createAdvisory(aiAdvisoryIntent(), clock())
    ).rejects.toThrow('AI advisory source is unavailable.');
    expect(store.persistHandoff).not.toHaveBeenCalled();

    const missingStore = memoryStore(access.decision);
    missingStore.loadNormalizedFinding.mockResolvedValueOnce(null);
    const missingService = new AiAdvisoryService(
      config(false),
      { createAdvisory: jest.fn() } as never,
      { classifyForAi: jest.fn().mockResolvedValue(access) } as never,
      missingStore as never
    );
    await expect(
      missingService.createAdvisory(aiAdvisoryIntent(), clock())
    ).rejects.toThrow('AI advisory source is unavailable.');
    expect(missingStore.persistHandoff).not.toHaveBeenCalled();
  });

  it('fails closed on handoff or result persistence conflicts', async () => {
    const logger = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const access = allowedAiAccess();
    const runtime = { createAdvisory: jest.fn() };
    const handoffStore = memoryStore(access.decision);
    handoffStore.persistHandoff.mockRejectedValueOnce(
      new Error('handoff conflict')
    );
    const handoffService = new AiAdvisoryService(
      config(false),
      runtime as never,
      { classifyForAi: jest.fn().mockResolvedValue(access) } as never,
      handoffStore as never
    );

    await expect(
      handoffService.createAdvisory(aiAdvisoryIntent(), clock())
    ).rejects.toThrow('AI advisory source is unavailable.');
    expect(runtime.createAdvisory).not.toHaveBeenCalled();

    const resultStore = memoryStore(access.decision);
    resultStore.persistAdvisory.mockRejectedValueOnce(
      new Error('result conflict')
    );
    const resultService = new AiAdvisoryService(
      config(false),
      runtime as never,
      { classifyForAi: jest.fn().mockResolvedValue(access) } as never,
      resultStore as never
    );
    await expect(
      resultService.createAdvisory(aiAdvisoryIntent(), clock())
    ).rejects.toThrow('AI advisory source is unavailable.');
    expect(logger).toHaveBeenCalledWith(
      expect.stringContaining('AI advisory handoff persistence failed')
    );
    expect(logger).toHaveBeenCalledWith(
      expect.stringContaining('AI advisory persistence failed')
    );
    expect(JSON.stringify(logger.mock.calls)).not.toMatch(
      /handoff conflict|result conflict/u
    );
  });

  it('sends only the canonical handoff to the internal runtime and replays stored results', async () => {
    const access = allowedAiAccess();
    const runtimeResponse: AiInferenceResponse = {
      requestId: 'ignored-by-service-mock',
      tenantId: 'tenant-ai',
      scanRequestId: 'scan-ai',
      advisoryOnly: true,
      detectorAdvisories: [
        {
          findingId: 'normalized-finding-ai',
          confidence: 0.83,
          rationale: 'Runtime detector advisory.',
          signals: ['SCANNER_CONFIRMED', 'MODEL_TRIAGED']
        }
      ],
      plannerAdvisories: [
        {
          findingId: 'normalized-finding-ai',
          action: 'Review normalized evidence.',
          rationale: 'Runtime planner advisory.',
          priority: 'high'
        }
      ],
      modelMetadata: {
        provider: 'deterministic',
        model: 'detector-planner-runtime',
        version: '2026-08-11'
      },
      fallback: { used: true, reason: 'provider not configured' },
      latencyMs: 11,
      createdAt: '2026-08-11T04:00:00.450Z'
    };
    const runtime = {
      createAdvisory: jest.fn().mockResolvedValue(runtimeResponse)
    };
    const store = memoryStore(access.decision);
    const service = new AiAdvisoryService(
      config(true),
      runtime as never,
      { classifyForAi: jest.fn().mockResolvedValue(access) } as never,
      store as never
    );

    const advisory = await service.createAdvisory(
      aiAdvisoryIntent(),
      clock()
    );
    expect(runtime.createAdvisory).toHaveBeenCalledWith(
      expect.objectContaining({
        normalizedFinding: expect.objectContaining({
          normalizedFindingId: 'normalized-finding-ai'
        }),
        reducedEvidenceReference: expect.objectContaining({
          retrievalAllowed: false,
          toolsAllowed: false
        })
      })
    );
    expect(advisory.modelVersion).toBe('2026-08-11');
    expect(advisory.detectorSignals).toEqual([
      'SCANNER_CONFIRMED',
      'MODEL_TRIAGED'
    ]);

    store.loadAdvisory.mockResolvedValueOnce(advisory);
    runtime.createAdvisory.mockClear();
    const replayed = await service.createAdvisory(
      aiAdvisoryIntent(),
      clock()
    );
    expect(replayed).toEqual(advisory);
    expect(runtime.createAdvisory).not.toHaveBeenCalled();
  });
});

function memoryStore(decision: ReturnType<typeof allowedAiAccess>['decision']) {
  let persisted: SastAiAdvisoryHandoff | null = null;
  return {
    loadNormalizedFinding: jest
      .fn()
      .mockResolvedValue(aiNormalizedFinding(decision)),
    persistHandoff: jest.fn(async (handoff: SastAiAdvisoryHandoff) => {
      const replayed = persisted !== null;
      persisted = handoff;
      return { handoff, replayed };
    }),
    loadAdvisory: jest.fn<Promise<AiAdvisoryResult | null>, [unknown]>()
      .mockResolvedValue(null),
    persistAdvisory: jest.fn(async ({ advisory }: { advisory: AiAdvisoryResult }) => advisory)
  };
}

function config(enabled: boolean) {
  return {
    get: jest.fn((key: string) =>
      key === 'USE_INTERNAL_AI' ? String(enabled) : undefined
    )
  } as never;
}

function clock() {
  const values = [
    '2026-08-11T04:00:00.100Z',
    '2026-08-11T04:00:00.200Z',
    '2026-08-11T04:00:00.300Z',
    '2026-08-11T04:00:00.400Z',
    '2026-08-11T04:00:00.500Z'
  ];
  let index = 0;
  return () => values[Math.min(index++, values.length - 1)] as string;
}
