import { createHash } from 'node:crypto';
import { setImmediate as yieldToEventLoop } from 'node:timers/promises';

import {
  SAST_ACCEPTED_EVIDENCE_LIMITS,
  SAST_ACCEPTED_EVIDENCE_POLICY,
  SAST_SECRET_REDACTION_LIMITS,
  buildSastAcceptedEvidence,
  buildSastEvidenceEarlyRejection,
  canonicalizeSastEvidenceCandidate,
  canonicalizeSastEvidenceFragmentRequests,
  isSastAcceptedEvidenceBuildResultShapeValid,
  isSastEvidenceFragmentRequestValid,
  isSastRedactedEvidenceCandidateShapeValid,
  type SastAcceptedEvidenceBuildResult,
  type SastEvidenceFragmentRequest,
  type SastEvidenceReasonCode,
  type SastRedactedEvidenceCandidate,
  type SastRedactedEvidenceCandidateCore
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import {
  SastAcceptedEvidenceSourceAuthority,
  type SastAcceptedEvidenceSourceResult
} from './sast-accepted-evidence-source.authority';
import {
  SastAcceptedEvidencePersistenceError,
  SastAcceptedEvidenceStore,
  type SastAcceptedEvidenceContext
} from './sast-accepted-evidence.store';

const REDACTION_TOKEN = '[REDACTED]';
const KNOWN_SECRET_PATTERNS = [
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]{0,4096}?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/gu,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu,
  /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/gu,
  /\b(?:glpat|gloas|gldt|glrt|glrtr|glcbt|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_-]{8,255}\b/gu,
  /\beyJ[A-Za-z0-9_-]{5,511}\.[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}\b/gu,
  /(?<![\p{L}\p{N}])["']?(?:[\p{L}\p{N}]{1,64}[-_.]){0,8}(?:access[-_ ]?key|api[-_ ]?key|client[-_ ]?secret|passwd|password|private[-_ ]?key|pwd|secret|session[-_ ]?token|token)["']?\s*(?:=>|=|:)\s*(?:"[^"\r\n]{1,512}"|'[^'\r\n]{1,512}'|[^\s,;]{4,512})/giu
] as const;

export type SastAcceptedEvidenceOutcome =
  | {
      outcome: 'BUILT';
      decision: SastAcceptedEvidenceBuildResult['decision'];
      pack: NonNullable<SastAcceptedEvidenceBuildResult['pack']>;
      replayed: boolean;
    }
  | {
      outcome: 'REJECTED';
      reasonCode: SastEvidenceReasonCode;
      decision: SastAcceptedEvidenceBuildResult['decision'] | null;
      replayed: boolean;
      dashboardPayloadCreated: false;
      aiPayloadCreated: false;
      publicationAttempted: false;
    };

type EvidenceClock = () => string;

@Injectable()
export class SastAcceptedEvidenceService {
  constructor(
    private readonly store: SastAcceptedEvidenceStore,
    private readonly source: SastAcceptedEvidenceSourceAuthority
  ) {}

  async build(
    input: {
      freshnessDecisionId: string;
      occurrenceId: string;
      fragments: readonly SastEvidenceFragmentRequest[];
    },
    clock: EvidenceClock = () => new Date().toISOString()
  ): Promise<SastAcceptedEvidenceOutcome> {
    if (!isBuildRequestValid(input)) {
      return this.reject('EVIDENCE_INPUT_INVALID');
    }
    let context: SastAcceptedEvidenceContext | null;
    try {
      context = await this.store.loadContext(
        input.freshnessDecisionId,
        input.occurrenceId
      );
    } catch {
      return this.reject('EVIDENCE_CONTEXT_UNAVAILABLE');
    }
    if (!context) {
      return this.reject('EVIDENCE_CONTEXT_UNAVAILABLE');
    }
    let decidedAt: string;
    try {
      decidedAt = clock();
    } catch {
      return this.reject('EVIDENCE_INPUT_INVALID');
    }
    if (
      !isCanonicalTimestamp(decidedAt) ||
      Date.parse(decidedAt) <
        Date.parse(context.freshnessDecidedAt)
    ) {
      return this.reject('EVIDENCE_INPUT_INVALID');
    }
    const requestDigest = digest(
      canonicalizeSastEvidenceFragmentRequests(input.fragments)
    );
    const candidates: SastRedactedEvidenceCandidate[] = [];
    for (let index = 0; index < input.fragments.length; index += 1) {
      if (
        index > 0 &&
        index %
          SAST_ACCEPTED_EVIDENCE_LIMITS.yieldCandidateInterval ===
          0
      ) {
        await yieldToEventLoop();
      }
      const request = input.fragments[index];
      if (!request) {
        return this.persistEarlyRejection(
          context,
          requestDigest,
          'EVIDENCE_INPUT_INVALID',
          decidedAt
        );
      }
      let source: unknown;
      try {
        source = await this.source.read({
          scope: context.scope,
          request
        });
      } catch {
        source = { status: 'UNAVAILABLE' };
      }
      if (isUnavailableSourceResult(source)) {
        return this.persistEarlyRejection(
          context,
          requestDigest,
          'EVIDENCE_SOURCE_UNAVAILABLE',
          decidedAt
        );
      }
      if (!isVerifiedSourceResult(source)) {
        return this.persistEarlyRejection(
          context,
          requestDigest,
          'EVIDENCE_SOURCE_INVALID',
          decidedAt
        );
      }
      let redaction: ReturnType<typeof redactCandidate>;
      try {
        redaction = redactCandidate(
          context,
          request,
          source
        );
      } catch {
        return this.persistEarlyRejection(
          context,
          requestDigest,
          'EVIDENCE_SOURCE_INVALID',
          decidedAt
        );
      }
      if (redaction.status === 'REJECTED') {
        return this.persistEarlyRejection(
          context,
          requestDigest,
          redaction.reasonCode,
          decidedAt
        );
      }
      candidates.push(redaction.candidate);
    }

    const result = buildSastAcceptedEvidence({
      scope: context.scope,
      candidates,
      policy: SAST_ACCEPTED_EVIDENCE_POLICY,
      decidedAt,
      digestCanonical: digest
    });
    if (
      !isSastAcceptedEvidenceBuildResultShapeValid(
        result,
        digest,
        SAST_ACCEPTED_EVIDENCE_POLICY
      )
    ) {
      return this.persistEarlyRejection(
        context,
        requestDigest,
        'EVIDENCE_OUTPUT_INVALID',
        decidedAt
      );
    }
    return this.persistResult(context, result);
  }

  private async persistEarlyRejection(
    context: Readonly<SastAcceptedEvidenceContext>,
    requestDigest: string,
    reasonCode: SastEvidenceReasonCode,
    decidedAt: string
  ): Promise<SastAcceptedEvidenceOutcome> {
    const result: SastAcceptedEvidenceBuildResult = {
      decision: buildSastEvidenceEarlyRejection({
        scope: context.scope,
        requestDigest,
        reasonCode,
        decidedAt,
        digestCanonical: digest
      }),
      pack: null
    };
    return this.persistResult(context, result);
  }

  private async persistResult(
    context: Readonly<SastAcceptedEvidenceContext>,
    result: Readonly<SastAcceptedEvidenceBuildResult>
  ): Promise<SastAcceptedEvidenceOutcome> {
    try {
      const persisted = await this.store.persist({
        context,
        result
      });
      const canonicalResult = persisted.result;
      if (
        !isSastAcceptedEvidenceBuildResultShapeValid(
          canonicalResult,
          digest,
          SAST_ACCEPTED_EVIDENCE_POLICY
        ) ||
        persisted.buildDecisionId !==
          canonicalResult.decision.buildDecisionId ||
        persisted.decisionDigest !==
          canonicalResult.decision.decisionDigest ||
        persisted.outcome !== canonicalResult.decision.outcome ||
        persisted.evidencePackId !==
          (canonicalResult.pack?.evidencePackId ?? null) ||
        canonicalResult.decision.buildDecisionId !==
          result.decision.buildDecisionId ||
        canonicalResult.decision.candidateSetDigest !==
          result.decision.candidateSetDigest
      ) {
        return this.reject('EVIDENCE_PERSISTENCE_CONFLICT');
      }
      if (canonicalResult.pack) {
        return {
          outcome: 'BUILT',
          decision: canonicalResult.decision,
          pack: canonicalResult.pack,
          replayed: persisted.replayed
        };
      }
      return {
        outcome: 'REJECTED',
        reasonCode:
          canonicalResult.decision.reasonCodes[0] ??
          'EVIDENCE_OUTPUT_INVALID',
        decision: canonicalResult.decision,
        replayed: persisted.replayed,
        dashboardPayloadCreated: false,
        aiPayloadCreated: false,
        publicationAttempted: false
      };
    } catch (error) {
      if (error instanceof SastAcceptedEvidencePersistenceError) {
        return this.reject(
          mapPersistenceReason(error.reason)
        );
      }
      return this.reject('EVIDENCE_PERSISTENCE_CONFLICT');
    }
  }

  private reject(
    reasonCode: SastEvidenceReasonCode
  ): SastAcceptedEvidenceOutcome {
    return {
      outcome: 'REJECTED',
      reasonCode,
      decision: null,
      replayed: false,
      dashboardPayloadCreated: false,
      aiPayloadCreated: false,
      publicationAttempted: false
    };
  }
}

function mapPersistenceReason(
  reason: SastAcceptedEvidencePersistenceError['reason']
): SastEvidenceReasonCode {
  switch (reason) {
    case 'CONTEXT_DRIFT':
      return 'EVIDENCE_CONTEXT_UNAVAILABLE';
    case 'OUTPUT_INVALID':
      return 'EVIDENCE_OUTPUT_INVALID';
    case 'REPLAY_CONFLICT':
      return 'EVIDENCE_PERSISTENCE_CONFLICT';
  }
}

function redactCandidate(
  context: Readonly<SastAcceptedEvidenceContext>,
  request: Readonly<SastEvidenceFragmentRequest>,
  source: Extract<
    SastAcceptedEvidenceSourceResult,
    { status: 'VERIFIED' }
  >
):
  | {
      status: 'ACCEPTED';
      candidate: SastRedactedEvidenceCandidate;
    }
  | {
      status: 'REJECTED';
      reasonCode:
        | 'EVIDENCE_SOURCE_INVALID'
        | 'EVIDENCE_REDACTION_INVALID';
    } {
  const platformSecrets = normalizePlatformSecretValues(
    source.platformSecretValues
  );
  if (
    source.candidateId !== request.candidateId ||
    source.role !== request.role ||
    source.normalizedPath !== request.normalizedPath ||
    source.startLine !== request.startLine ||
    source.endLine !== request.endLine ||
    source.scannerRedactionApplied !== true ||
    source.anchorStartLine < source.startLine ||
    source.anchorEndLine < source.anchorStartLine ||
    source.anchorEndLine > source.endLine ||
    source.sourceFileLineCount < source.endLine ||
    !isCanonicalEvidenceText(source.scannerRedactedContent) ||
    utf8Bytes(source.scannerRedactedContent) >
      SAST_ACCEPTED_EVIDENCE_POLICY.maxFragmentBytes ||
    digest(source.scannerRedactedContent) !==
      source.sourceContentDigest ||
    !isBoundedReference(source.sourceAttestationRef) ||
    !isBoundedReference(source.scannerRedactionDecisionRef) ||
    platformSecrets === null
  ) {
    return {
      status: 'REJECTED',
      reasonCode: 'EVIDENCE_SOURCE_INVALID'
    };
  }
  if (
    source.role === 'PRIMARY' &&
    (source.normalizedPath !== context.scope.normalizedPath ||
      source.anchorStartLine !==
        context.scope.findingStartLine ||
      source.anchorEndLine !== context.scope.findingEndLine)
  ) {
    return {
      status: 'REJECTED',
      reasonCode: 'EVIDENCE_SOURCE_INVALID'
    };
  }
  let redactedContent = source.scannerRedactedContent;
  let replacementCount = 0;
  for (const pattern of KNOWN_SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    redactedContent = redactedContent.replace(
      pattern,
      (matched) => {
        replacementCount += 1;
        return redactionReplacement(matched);
      }
    );
  }
  for (const secret of platformSecrets) {
    const parts = redactedContent.split(secret);
    if (parts.length > 1) {
      replacementCount += parts.length - 1;
      redactedContent = parts.join(
        redactionReplacement(secret)
      );
    }
  }
  if (
    !isCanonicalEvidenceText(redactedContent) ||
    countLines(redactedContent) !==
      source.endLine - source.startLine + 1 ||
    utf8Bytes(redactedContent) >
      SAST_ACCEPTED_EVIDENCE_POLICY.maxFragmentBytes
  ) {
    return {
      status: 'REJECTED',
      reasonCode: 'EVIDENCE_REDACTION_INVALID'
    };
  }
  const contentDigest = digest(redactedContent);
  const platformRedactionDecisionRef =
    deterministicId(
      'sast-evidence-redaction',
      [
        source.candidateId,
        source.sourceContentDigest,
        contentDigest,
        String(replacementCount)
      ].join('\0')
    );
  const core: SastRedactedEvidenceCandidateCore = {
    candidateId: source.candidateId,
    role: source.role,
    normalizedPath: source.normalizedPath,
    startLine: source.startLine,
    endLine: source.endLine,
    anchorStartLine: source.anchorStartLine,
    anchorEndLine: source.anchorEndLine,
    sourceFileLineCount: source.sourceFileLineCount,
    redactedContent,
    byteSize: utf8Bytes(redactedContent),
    sourceContentDigest: source.sourceContentDigest,
    contentDigest,
    sourceAttestationRef: source.sourceAttestationRef,
    scannerRedactionDecisionRef:
      source.scannerRedactionDecisionRef,
    platformRedactionDecisionRef,
    secretRedactionApplied: true,
    rawSourceStored: false
  };
  const candidate: SastRedactedEvidenceCandidate = {
    ...core,
    candidateDigest: digest(
      canonicalizeSastEvidenceCandidate(core)
    )
  };
  return isSastRedactedEvidenceCandidateShapeValid(
    candidate,
    digest
  )
    ? { status: 'ACCEPTED', candidate }
    : {
        status: 'REJECTED',
        reasonCode: 'EVIDENCE_REDACTION_INVALID'
      };
}

function isBuildRequestValid(value: unknown): value is {
  freshnessDecisionId: string;
  occurrenceId: string;
  fragments: readonly SastEvidenceFragmentRequest[];
} {
  return (
    !!value &&
    typeof value === 'object' &&
    Object.keys(value).length === 3 &&
    Object.keys(value).every((key) =>
      [
        'freshnessDecisionId',
        'occurrenceId',
        'fragments'
      ].includes(key)
    ) &&
    typeof (value as { freshnessDecisionId?: unknown })
      .freshnessDecisionId === 'string' &&
    /^sast-freshness:\/\/[a-f0-9]{64}$/u.test(
      (value as { freshnessDecisionId: string })
        .freshnessDecisionId
    ) &&
    typeof (value as { occurrenceId?: unknown }).occurrenceId ===
      'string' &&
    /^finding-occurrence:\/\/[a-f0-9]{64}$/u.test(
      (value as { occurrenceId: string }).occurrenceId
    ) &&
    Array.isArray(
      (value as { fragments?: unknown }).fragments
    ) &&
    (value as { fragments: unknown[] }).fragments.length > 0 &&
    (value as { fragments: unknown[] }).fragments.length <=
      SAST_ACCEPTED_EVIDENCE_LIMITS.maximumSourceCandidates &&
    (value as { fragments: unknown[] }).fragments.every(
      isSastEvidenceFragmentRequestValid
    ) &&
    new Set(
      (
        value as {
          fragments: SastEvidenceFragmentRequest[];
        }
      ).fragments.map((fragment) => fragment.candidateId)
    ).size ===
      (value as { fragments: unknown[] }).fragments.length
  );
}

function isUnavailableSourceResult(
  value: unknown
): value is Extract<
  SastAcceptedEvidenceSourceResult,
  { status: 'UNAVAILABLE' }
> {
  return (
    !!value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    (value as { status?: unknown }).status === 'UNAVAILABLE'
  );
}

function isVerifiedSourceResult(
  value: unknown
): value is Extract<
  SastAcceptedEvidenceSourceResult,
  { status: 'VERIFIED' }
> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = [
    'status',
    'candidateId',
    'role',
    'normalizedPath',
    'startLine',
    'endLine',
    'anchorStartLine',
    'anchorEndLine',
    'sourceFileLineCount',
    'scannerRedactedContent',
    'sourceContentDigest',
    'sourceAttestationRef',
    'scannerRedactionApplied',
    'scannerRedactionDecisionRef',
    'platformSecretValues'
  ];
  return (
    Object.keys(record).length === keys.length &&
    Object.keys(record).every((key) => keys.includes(key)) &&
    record.status === 'VERIFIED' &&
    typeof record.candidateId === 'string' &&
    (record.role === 'PRIMARY' || record.role === 'RELATED') &&
    typeof record.normalizedPath === 'string' &&
    Number.isSafeInteger(record.startLine) &&
    Number.isSafeInteger(record.endLine) &&
    Number.isSafeInteger(record.anchorStartLine) &&
    Number.isSafeInteger(record.anchorEndLine) &&
    Number.isSafeInteger(record.sourceFileLineCount) &&
    typeof record.scannerRedactedContent === 'string' &&
    typeof record.sourceContentDigest === 'string' &&
    typeof record.sourceAttestationRef === 'string' &&
    record.scannerRedactionApplied === true &&
    typeof record.scannerRedactionDecisionRef === 'string' &&
    Array.isArray(record.platformSecretValues)
  );
}

function normalizePlatformSecretValues(
  values: readonly string[]
): string[] | null {
  if (
    !Array.isArray(values) ||
    values.length >
      SAST_SECRET_REDACTION_LIMITS.maximumPlatformSecretValues
  ) {
    return null;
  }
  const seen = new Set<string>();
  let totalBytes = 0;
  for (const value of values as readonly unknown[]) {
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      value !== value.normalize('NFC') ||
      !isCanonicalEvidenceText(value) ||
      value.includes(REDACTION_TOKEN) ||
      !/\S/u.test(value)
    ) {
      return null;
    }
    const byteSize = utf8Bytes(value);
    if (
      byteSize < 8 ||
      byteSize >
        SAST_SECRET_REDACTION_LIMITS
          .maximumPlatformSecretValueBytes ||
      totalBytes >
        SAST_SECRET_REDACTION_LIMITS
          .maximumPlatformSecretValueTotalBytes -
          byteSize ||
      seen.has(value)
    ) {
      return null;
    }
    totalBytes += byteSize;
    seen.add(value);
  }
  return [...seen].sort(
    (left, right) =>
      right.length - left.length ||
      compareCodeUnits(left, right)
  );
}

function redactionReplacement(value: string): string {
  return REDACTION_TOKEN + '\n'.repeat(countNewlines(value));
}

function countNewlines(value: string): number {
  let count = 0;
  for (const character of value) {
    if (character === '\n') count += 1;
  }
  return count;
}

function compareCodeUnits(left: string, right: string): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference =
      left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function isCanonicalEvidenceText(value: string): boolean {
  return (
    value.length > 0 &&
    value === value.normalize('NFC') &&
    !value.includes('\r') &&
    !value.includes('\u0000') &&
    ![...value].some((character) => {
      const point = character.codePointAt(0) ?? 0;
      return (
        (point >= 0xd800 && point <= 0xdfff) ||
        (point < 0x20 && point !== 0x09 && point !== 0x0a) ||
        (point >= 0x7f && point <= 0x9f)
      );
    })
  );
}

function countLines(value: string): number {
  return value.split('\n').length;
}

function utf8Bytes(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

function isBoundedReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 2048 &&
    value === value.normalize('NFC') &&
    value === value.trim()
  );
}

function digest(value: string): string {
  return (
    'sha256:' +
    createHash('sha256').update(value).digest('hex')
  );
}

function deterministicId(
  prefix: string,
  preimage: string
): string {
  return (
    prefix +
    '://' +
    createHash('sha256').update(preimage).digest('hex')
  );
}

function isCanonicalTimestamp(value: string): boolean {
  const milliseconds = Date.parse(value);
  return (
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value
  );
}
