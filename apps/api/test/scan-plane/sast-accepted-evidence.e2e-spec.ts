import { createHash } from 'node:crypto';

import type {
  SastAcceptedEvidenceBuildResult,
  SastAcceptedEvidenceScope,
  SastEvidenceFragmentRequest
} from '@aegisai/shared';

import {
  SastAcceptedEvidenceSourceAuthority,
  type SastAcceptedEvidenceSourceResult
} from '../../src/scan-plane/sast-accepted-evidence-source.authority';
import { SastAcceptedEvidenceService } from '../../src/scan-plane/sast-accepted-evidence.service';
import {
  SastAcceptedEvidenceStore,
  type SastAcceptedEvidenceContext
} from '../../src/scan-plane/sast-accepted-evidence.store';

const DECIDED_AT = '2026-08-10T04:40:00.000Z';

describe('SastAcceptedEvidenceService', () => {
  it('redacts trusted source and persists a bounded internal-only pack', async () => {
    const context = evidenceContext();
    const store = new MemoryEvidenceStore(context);
    const source = new MemorySourceAuthority({
      platformSecretValues: ['platform-secret-value'],
      contentByCandidate: new Map([
        [
          candidateId('primary'),
          [
            'safe line',
            'password = "platform-secret-value"',
            'return safe'
          ].join('\n')
        ]
      ])
    });
    const service = new SastAcceptedEvidenceService(
      store,
      source
    );

    const result = await service.build(
      {
        freshnessDecisionId:
          context.scope.freshnessDecisionId,
        occurrenceId: context.scope.occurrenceId,
        fragments: [primaryRequest()]
      },
      () => DECIDED_AT
    );

    expect(result.outcome).toBe('BUILT');
    if (result.outcome !== 'BUILT') return;
    expect(result.pack.fragments).toHaveLength(1);
    expect(
      result.pack.fragments[0]?.redactedContent
    ).toContain('[REDACTED]');
    expect(
      result.pack.fragments[0]?.redactedContent
    ).not.toContain('platform-secret-value');
    expect(result.pack.dashboardSafe).toBe(false);
    expect(result.pack.aiSafe).toBe(false);
    expect(result.decision.audit.rawSourceStored).toBe(false);
    expect(result.decision.audit.aiPayloadCreated).toBe(false);
    expect(store.persisted?.pack).toEqual(result.pack);
  });

  it('redacts multiline known secrets without changing fragment line coordinates', async () => {
    const context = evidenceContext();
    const store = new MemoryEvidenceStore(context);
    const privateKey = [
      '-----BEGIN PRIVATE KEY-----',
      'SYNTHETIC_PRIVATE_KEY_NEVER_COPY',
      '-----END PRIVATE KEY-----'
    ].join('\n');
    const source = new MemorySourceAuthority({
      contentByCandidate: new Map([
        [candidateId('primary'), privateKey]
      ])
    });

    const result = await new SastAcceptedEvidenceService(
      store,
      source
    ).build(
      {
        freshnessDecisionId:
          context.scope.freshnessDecisionId,
        occurrenceId: context.scope.occurrenceId,
        fragments: [primaryRequest()]
      },
      () => DECIDED_AT
    );

    expect(result.outcome).toBe('BUILT');
    if (result.outcome !== 'BUILT') return;
    const content = result.pack.fragments[0]?.redactedContent;
    expect(content).toContain('[REDACTED]');
    expect(content).not.toContain('PRIVATE KEY');
    expect(content?.split('\n')).toHaveLength(3);
  });

  it('persists an immutable fail-closed decision when source authority is unavailable', async () => {
    const context = evidenceContext();
    const store = new MemoryEvidenceStore(context);
    const service = new SastAcceptedEvidenceService(
      store,
      new UnavailableMemorySource()
    );

    const result = await service.build(
      {
        freshnessDecisionId:
          context.scope.freshnessDecisionId,
        occurrenceId: context.scope.occurrenceId,
        fragments: [primaryRequest()]
      },
      () => DECIDED_AT
    );

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCode: 'EVIDENCE_SOURCE_UNAVAILABLE',
      dashboardPayloadCreated: false,
      aiPayloadCreated: false,
      publicationAttempted: false
    });
    expect(store.persisted?.decision.outcome).toBe('REJECTED');
    expect(store.persisted?.pack).toBeNull();
  });

  it('rejects full-file and overlapping reconstruction before creating a pack', async () => {
    const fullContext = evidenceContext({
      findingStartLine: 5,
      findingEndLine: 5
    });
    const fullStore = new MemoryEvidenceStore(fullContext);
    const fullSource = new MemorySourceAuthority({
      sourceFileLineCount: 10
    });
    const full = await new SastAcceptedEvidenceService(
      fullStore,
      fullSource
    ).build(
      {
        freshnessDecisionId:
          fullContext.scope.freshnessDecisionId,
        occurrenceId: fullContext.scope.occurrenceId,
        fragments: [
          request({
            seed: 'full',
            role: 'PRIMARY',
            path: fullContext.scope.normalizedPath,
            startLine: 1,
            endLine: 10
          })
        ]
      },
      () => DECIDED_AT
    );
    expect(full.outcome).toBe('REJECTED');
    if (full.outcome === 'REJECTED') {
      expect(full.decision?.reasonCodes).toContain(
        'EVIDENCE_FULL_FILE_FORBIDDEN'
      );
    }

    const context = evidenceContext();
    const overlapStore = new MemoryEvidenceStore(context);
    const overlapSource = new MemorySourceAuthority({
      relatedAnchorStartLine: 12,
      relatedAnchorEndLine: 12
    });
    const overlap = await new SastAcceptedEvidenceService(
      overlapStore,
      overlapSource
    ).build(
      {
        freshnessDecisionId:
          context.scope.freshnessDecisionId,
        occurrenceId: context.scope.occurrenceId,
        fragments: [
          primaryRequest(),
          request({
            seed: 'related',
            role: 'RELATED',
            path: context.scope.normalizedPath,
            startLine: 12,
            endLine: 14
          })
        ]
      },
      () => DECIDED_AT
    );
    expect(overlap.outcome).toBe('REJECTED');
    if (overlap.outcome === 'REJECTED') {
      expect(overlap.decision?.reasonCodes).toContain(
        'EVIDENCE_RECONSTRUCTION_OVERLAP'
      );
    }
  });

  it('returns the persisted exact replay and rejects changed input at the store boundary', async () => {
    const context = evidenceContext();
    const store = new MemoryEvidenceStore(context);
    const source = new MemorySourceAuthority({});
    const service = new SastAcceptedEvidenceService(
      store,
      source
    );
    const input = {
      freshnessDecisionId:
        context.scope.freshnessDecisionId,
      occurrenceId: context.scope.occurrenceId,
      fragments: [primaryRequest()]
    };
    const first = await service.build(input, () => DECIDED_AT);
    const second = await service.build(
      input,
      () => '2026-08-10T04:41:00.000Z'
    );

    expect(first.outcome).toBe('BUILT');
    expect(second).toMatchObject({
      outcome: 'BUILT',
      replayed: true
    });
    if (first.outcome !== 'BUILT' || second.outcome !== 'BUILT') {
      return;
    }
    expect(second.decision.decisionDigest).toBe(
      first.decision.decisionDigest
    );
    expect(second.pack.packDigest).toBe(first.pack.packDigest);
    expect(second.pack.createdAt).toBe(first.pack.createdAt);
    expect(source.calls).toBe(2);
  });

  it('rejects invalid requests and unavailable durable context without reading source', async () => {
    const source = new MemorySourceAuthority({});
    const store = new MemoryEvidenceStore(null);
    const service = new SastAcceptedEvidenceService(
      store,
      source
    );
    const invalid = await service.build({
      freshnessDecisionId: 'not-a-decision',
      occurrenceId: 'not-an-occurrence',
      fragments: []
    });
    expect(invalid).toMatchObject({
      outcome: 'REJECTED',
      reasonCode: 'EVIDENCE_INPUT_INVALID'
    });

    const context = evidenceContext();
    const unavailable = await service.build({
      freshnessDecisionId:
        context.scope.freshnessDecisionId,
      occurrenceId: context.scope.occurrenceId,
      fragments: [primaryRequest()]
    });
    expect(unavailable).toMatchObject({
      outcome: 'REJECTED',
      reasonCode: 'EVIDENCE_CONTEXT_UNAVAILABLE'
    });
    expect(source.calls).toBe(0);
  });

  it('fails closed for a throwing clock or malformed source provider result', async () => {
    const context = evidenceContext();
    const source = new MemorySourceAuthority({});
    const clockFailure = await new SastAcceptedEvidenceService(
      new MemoryEvidenceStore(context),
      source
    ).build(
      {
        freshnessDecisionId:
          context.scope.freshnessDecisionId,
        occurrenceId: context.scope.occurrenceId,
        fragments: [primaryRequest()]
      },
      () => {
        throw new Error('clock unavailable');
      }
    );
    expect(clockFailure).toMatchObject({
      outcome: 'REJECTED',
      reasonCode: 'EVIDENCE_INPUT_INVALID'
    });
    expect(source.calls).toBe(0);

    const malformed = await new SastAcceptedEvidenceService(
      new MemoryEvidenceStore(context),
      new MalformedMemorySource()
    ).build(
      {
        freshnessDecisionId:
          context.scope.freshnessDecisionId,
        occurrenceId: context.scope.occurrenceId,
        fragments: [primaryRequest()]
      },
      () => DECIDED_AT
    );
    expect(malformed).toMatchObject({
      outcome: 'REJECTED',
      reasonCode: 'EVIDENCE_SOURCE_INVALID'
    });
  });
});

class MemoryEvidenceStore extends SastAcceptedEvidenceStore {
  persisted?: SastAcceptedEvidenceBuildResult;

  constructor(
    private readonly context:
      | SastAcceptedEvidenceContext
      | null
  ) {
    super();
  }

  async loadContext() {
    return this.context;
  }

  async persist(input: {
    result: Readonly<SastAcceptedEvidenceBuildResult>;
  }) {
    const replayed = this.persisted !== undefined;
    if (
      this.persisted &&
      (this.persisted.decision.buildDecisionId !==
        input.result.decision.buildDecisionId ||
        this.persisted.decision.candidateSetDigest !==
          input.result.decision.candidateSetDigest)
    ) {
      throw new Error('changed replay');
    }
    this.persisted ??=
      input.result as SastAcceptedEvidenceBuildResult;
    const canonical = this.persisted;
    return {
      buildDecisionId: canonical.decision.buildDecisionId,
      decisionDigest: canonical.decision.decisionDigest,
      outcome: canonical.decision.outcome,
      evidencePackId:
        canonical.pack?.evidencePackId ?? null,
      replayed,
      result: canonical
    };
  }
}

class MemorySourceAuthority
  extends SastAcceptedEvidenceSourceAuthority {
  calls = 0;

  constructor(
    private readonly options: {
      platformSecretValues?: readonly string[];
      contentByCandidate?: ReadonlyMap<string, string>;
      sourceFileLineCount?: number;
      relatedAnchorStartLine?: number;
      relatedAnchorEndLine?: number;
    }
  ) {
    super();
  }

  async read(input: {
    scope: Readonly<SastAcceptedEvidenceScope>;
    request: Readonly<SastEvidenceFragmentRequest>;
  }) {
    this.calls += 1;
    const lineCount =
      input.request.endLine - input.request.startLine + 1;
    const content =
      this.options.contentByCandidate?.get(
        input.request.candidateId
      ) ??
      Array.from(
        { length: lineCount },
        (_, index) => 'safe line ' + index
      ).join('\n');
    const primary = input.request.role === 'PRIMARY';
    const anchorStartLine = primary
      ? input.scope.findingStartLine
      : (this.options.relatedAnchorStartLine ??
        input.request.startLine + 1);
    const anchorEndLine = primary
      ? input.scope.findingEndLine
      : (this.options.relatedAnchorEndLine ??
        anchorStartLine);
    return {
      status: 'VERIFIED' as const,
      candidateId: input.request.candidateId,
      role: input.request.role,
      normalizedPath: input.request.normalizedPath,
      startLine: input.request.startLine,
      endLine: input.request.endLine,
      anchorStartLine,
      anchorEndLine,
      sourceFileLineCount:
        this.options.sourceFileLineCount ?? 100,
      scannerRedactedContent: content,
      sourceContentDigest: digest(content),
      sourceAttestationRef:
        'source-attestation://' +
        input.request.candidateId,
      scannerRedactionApplied: true as const,
      scannerRedactionDecisionRef:
        'scanner-redaction://' +
        input.request.candidateId,
      platformSecretValues:
        this.options.platformSecretValues ?? []
    };
  }
}

class UnavailableMemorySource
  extends SastAcceptedEvidenceSourceAuthority {
  async read() {
    return { status: 'UNAVAILABLE' as const };
  }
}

class MalformedMemorySource
  extends SastAcceptedEvidenceSourceAuthority {
  async read(): Promise<SastAcceptedEvidenceSourceResult> {
    return null as unknown as SastAcceptedEvidenceSourceResult;
  }
}

function evidenceContext(
  overrides: Partial<SastAcceptedEvidenceScope> = {}
): SastAcceptedEvidenceContext {
  return {
    scope: {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      scanRequestId: 'scan-1',
      attemptId: 'attempt-1',
      targetRef: 'refs/pull/1/head',
      commitSha: 'a'.repeat(40),
      canonicalScanKey: digest('canonical-scan'),
      planDigest: digest('plan'),
      profileId: 'JAVA_FAST_V1',
      profileDigest: digest('profile'),
      freshnessDecisionId: id(
        'sast-freshness',
        'freshness'
      ),
      freshnessDecisionDigest: digest(
        'freshness-decision'
      ),
      coverageDecisionId: id('sast-coverage', 'coverage'),
      coverageDecisionDigest: digest(
        'coverage-decision'
      ),
      occurrenceId: id(
        'finding-occurrence',
        'occurrence'
      ),
      observationBatchId: id(
        'finding-observation',
        'observation'
      ),
      normalizedFindingId: 'normalized-finding-1',
      lineageId: id('finding-lineage', 'lineage'),
      findingFingerprint: digest('fingerprint'),
      fingerprintVersion: 'sast-fingerprint-v1',
      capability: 'SAST',
      normalizedPath: 'src/main/java/App.java',
      findingStartLine: 11,
      findingEndLine: 11,
      policyVersion: 'sast-evidence-policy-v1',
      ...overrides
    },
    freshnessDecidedAt: '2026-08-10T04:39:59.000Z'
  };
}

function primaryRequest(): SastEvidenceFragmentRequest {
  return request({
    seed: 'primary',
    role: 'PRIMARY',
    path: 'src/main/java/App.java',
    startLine: 10,
    endLine: 12
  });
}

function request(input: {
  seed: string;
  role: 'PRIMARY' | 'RELATED';
  path: string;
  startLine: number;
  endLine: number;
}): SastEvidenceFragmentRequest {
  return {
    candidateId: candidateId(input.seed),
    role: input.role,
    normalizedPath: input.path,
    startLine: input.startLine,
    endLine: input.endLine
  };
}

function candidateId(seed: string): string {
  return id('sast-evidence-candidate', seed);
}

function id(prefix: string, value: string): string {
  return prefix + '://' + hex(value);
}

function digest(value: string): string {
  return 'sha256:' + hex(value);
}

function hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
