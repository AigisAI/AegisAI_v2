import { createHash } from 'node:crypto';

import {
  SAST_ACCEPTED_EVIDENCE_POLICY,
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_DASHBOARD_EVIDENCE_VERSION,
  SAST_REDUCED_EVIDENCE_REFERENCE_VERSION,
  SAST_SECRET_REDACTION_LIMITS,
  buildSastEvidenceAccessDecision,
  canonicalizeSastEvidenceSafeFragments,
  isSafeNormalizedPath,
  isSastAcceptedEvidenceBuildResultShapeValid,
  isSastEvidenceAccessDecisionShapeValid,
  isSastEvidenceAccessScopeValid,
  isSastEvidenceDeletionScheduleShapeValid,
  isSastEvidenceSafeFragmentShapeValid,
  type SastDashboardEvidence,
  type SastEvidenceAccessDecision,
  type SastEvidenceAccessPurpose,
  type SastEvidenceAccessReasonCode,
  type SastEvidenceAccessScope,
  type SastEvidenceSafeFragment,
  type SastReducedEvidenceReference
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import {
  SastEvidenceAccessPersistenceError,
  SastEvidenceAccessStore,
  sastEvidenceAccessScopeFromResult,
  type SastEvidenceAccessContext
} from './sast-evidence-access.store';
import {
  SastEvidenceSecretRegistry,
  type SastEvidenceSecretRegistryResult
} from './sast-evidence-secret-registry';

const REDACTION_TOKEN = '[REDACTED]';
const UNCHECKED_REGISTRY_VERSION = 'not-checked-v1';
const KNOWN_SECRET_PATTERNS = [
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]{0,4096}?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/gu,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu,
  /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/gu,
  /\b(?:glpat|gloas|gldt|glrt|glrtr|glcbt|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_-]{8,255}\b/gu,
  /\beyJ[A-Za-z0-9_-]{5,511}\.[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}\b/gu,
  /(?<![\p{L}\p{N}])["']?(?:[\p{L}\p{N}]{1,64}[-_.]){0,8}(?:access[-_ ]?key|api[-_ ]?key|client[-_ ]?secret|passwd|password|private[-_ ]?key|pwd|secret|session[-_ ]?token|token)["']?\s*(?:=>|=|:)\s*(?:"[^"\r\n]{1,512}"|'[^'\r\n]{1,512}'|[^\s,;]{4,512})/giu
] as const;
const ENTROPY_TOKEN_PATTERN =
  /(?<![\p{L}\p{N}])[A-Za-z0-9+/_=-]{24,512}(?![\p{L}\p{N}])/gu;

type EvidenceClock = () => string;

export type SastEvidenceAccessResult =
  | {
      outcome: 'ALLOWED';
      decision: SastEvidenceAccessDecision;
      replayed: boolean;
      dashboardEvidence: SastDashboardEvidence | null;
      reducedEvidenceReference: SastReducedEvidenceReference | null;
    }
  | {
      outcome: 'DENIED';
      reasonCode: SastEvidenceAccessReasonCode;
      decision: SastEvidenceAccessDecision | null;
      replayed: boolean;
      dashboardEvidence: null;
      reducedEvidenceReference: null;
    };

interface RedactionProjection {
  fragments: SastEvidenceSafeFragment[];
  projectionDigest: `sha256:${string}`;
  totalBytes: number;
  redactionCount: number;
}

interface InternalAllowedResult {
  outcome: 'ALLOWED';
  decision: SastEvidenceAccessDecision;
  context: SastEvidenceAccessContext;
  registryVersion: string;
  projection: RedactionProjection;
  replayed: boolean;
}

@Injectable()
export class SastEvidenceAccessService {
  constructor(
    private readonly store: SastEvidenceAccessStore,
    private readonly secretRegistry: SastEvidenceSecretRegistry
  ) {}

  async readDashboard(
    input: {
      tenantId: string;
      repositoryBindingId: string;
      evidencePackId: string;
    },
    clock: EvidenceClock = () => new Date().toISOString()
  ): Promise<SastEvidenceAccessResult> {
    const startedAt = readClock(clock);
    if (!startedAt) {
      return denied('EVIDENCE_ACCESS_INPUT_INVALID');
    }
    const classified = await this.classifyAt(
      { ...input, purpose: 'DASHBOARD' },
      startedAt
    );
    if (classified.outcome === 'DENIED') return classified;

    const currentRegistry = await this.readRegistry(input);
    if (
      currentRegistry.status !== 'VERIFIED' ||
      currentRegistry.registryVersion !== classified.registryVersion
    ) {
      return denied(
        'EVIDENCE_ACCESS_CLASSIFICATION_STALE',
        classified.decision
      );
    }
    const secrets = normalizeSecretRegistry(currentRegistry);
    if (!secrets) {
      return denied(
        'EVIDENCE_ACCESS_REDACTION_FAILED',
        classified.decision
      );
    }
    const refreshedAt = readClock(clock);
    if (!refreshedAt || Date.parse(refreshedAt) < Date.parse(startedAt)) {
      return denied(
        'EVIDENCE_ACCESS_INPUT_INVALID',
        classified.decision
      );
    }
    const refreshed = await this.confirmAccess({
      ...input,
      accessDecisionId: classified.decision.accessDecisionId,
      purpose: 'DASHBOARD',
      secretRegistryVersion: classified.registryVersion,
      redactedProjectionDigest:
        classified.projection.projectionDigest,
      referenceTime: refreshedAt
    });
    const refreshedProjection =
      refreshed?.result?.pack === undefined ||
      refreshed.result.pack === null
        ? null
        : redactPack(refreshed.result.pack.fragments, secrets);
    if (
      !refreshed ||
      refreshed.deletionState !== 'ACTIVE' ||
      !refreshedProjection ||
      refreshedProjection.projectionDigest !==
        classified.decision.redactedProjectionDigest
    ) {
      return denied(
        'EVIDENCE_ACCESS_CLASSIFICATION_STALE',
        classified.decision
      );
    }
    const completedAt = readClock(clock);
    if (
      !completedAt ||
      Date.parse(completedAt) < Date.parse(refreshedAt) ||
      Date.parse(completedAt) >=
        Date.parse(classified.decision.evidenceExpiresAt)
    ) {
      return denied(
        'EVIDENCE_ACCESS_EXPIRED',
        classified.decision
      );
    }
    const confirmed = await this.confirmAccess({
      ...input,
      accessDecisionId: classified.decision.accessDecisionId,
      purpose: 'DASHBOARD',
      secretRegistryVersion: classified.registryVersion,
      redactedProjectionDigest:
        classified.projection.projectionDigest,
      referenceTime: completedAt
    });
    if (!confirmed || confirmed.deletionState !== 'ACTIVE') {
      return denied(
        'EVIDENCE_ACCESS_CLASSIFICATION_STALE',
        classified.decision
      );
    }
    return {
      outcome: 'ALLOWED',
      decision: classified.decision,
      replayed: classified.replayed,
      dashboardEvidence: dashboardEvidence(
        classified.decision,
        refreshedProjection,
        classified.context.result?.pack?.truncated ?? false
      ),
      reducedEvidenceReference: null
    };
  }

  async classifyForAi(
    input: {
      tenantId: string;
      repositoryBindingId: string;
      evidencePackId: string;
    },
    clock: EvidenceClock = () => new Date().toISOString()
  ): Promise<SastEvidenceAccessResult> {
    const decidedAt = readClock(clock);
    if (!decidedAt) {
      return denied('EVIDENCE_ACCESS_INPUT_INVALID');
    }
    const classified = await this.classifyAt(
      { ...input, purpose: 'AI_ADVISORY' },
      decidedAt
    );
    if (classified.outcome === 'DENIED') return classified;

    const currentRegistry = await this.readRegistry(input);
    if (
      currentRegistry.status !== 'VERIFIED' ||
      currentRegistry.registryVersion !== classified.registryVersion
    ) {
      return denied(
        'EVIDENCE_ACCESS_CLASSIFICATION_STALE',
        classified.decision
      );
    }
    const secrets = normalizeSecretRegistry(currentRegistry);
    if (!secrets) {
      return denied(
        'EVIDENCE_ACCESS_REDACTION_FAILED',
        classified.decision
      );
    }
    const completedAt = readClock(clock);
    if (
      !completedAt ||
      Date.parse(completedAt) < Date.parse(decidedAt) ||
      Date.parse(completedAt) >=
        Date.parse(classified.decision.evidenceExpiresAt) ||
      !classified.decision.aiPayloadExpiresAt ||
      Date.parse(completedAt) >=
        Date.parse(classified.decision.aiPayloadExpiresAt)
    ) {
      return denied(
        'EVIDENCE_ACCESS_EXPIRED',
        classified.decision
      );
    }
    const confirmed = await this.confirmAccess({
      ...input,
      accessDecisionId: classified.decision.accessDecisionId,
      purpose: 'AI_ADVISORY',
      secretRegistryVersion: classified.registryVersion,
      redactedProjectionDigest:
        classified.projection.projectionDigest,
      referenceTime: completedAt
    });
    const confirmedProjection = confirmed?.result?.pack
      ? redactPack(confirmed.result.pack.fragments, secrets)
      : null;
    if (
      !confirmed ||
      confirmed.deletionState !== 'ACTIVE' ||
      !confirmedProjection ||
      confirmedProjection.projectionDigest !==
        classified.decision.redactedProjectionDigest
    ) {
      return denied(
        'EVIDENCE_ACCESS_CLASSIFICATION_STALE',
        classified.decision
      );
    }
    return {
      outcome: 'ALLOWED',
      decision: classified.decision,
      replayed: classified.replayed,
      dashboardEvidence: null,
      reducedEvidenceReference: reducedReference(
        classified.decision
      )
    };
  }

  private async classifyAt(
    input: {
      tenantId: string;
      repositoryBindingId: string;
      evidencePackId: string;
      purpose: SastEvidenceAccessPurpose;
    },
    decidedAt: string
  ): Promise<InternalAllowedResult | Extract<SastEvidenceAccessResult, { outcome: 'DENIED' }>> {
    if (!isClassificationInputValid(input)) {
      return denied('EVIDENCE_ACCESS_INPUT_INVALID');
    }
    let context: SastEvidenceAccessContext | null;
    try {
      context = await this.store.load({
        tenantId: input.tenantId,
        repositoryBindingId: input.repositoryBindingId,
        evidencePackId: input.evidencePackId,
        referenceTime: decidedAt
      });
    } catch {
      return denied('EVIDENCE_ACCESS_CONTEXT_UNAVAILABLE');
    }
    if (!context) {
      return denied('EVIDENCE_ACCESS_CONTEXT_UNAVAILABLE');
    }
    if (
      !isSastEvidenceDeletionScheduleShapeValid(
        context.schedule,
        digest
      ) ||
      !isSastEvidenceAccessScopeValid(context.schedule.scope) ||
      context.schedule.scope.tenantId !== input.tenantId ||
      context.schedule.scope.repositoryBindingId !==
        input.repositoryBindingId ||
      context.schedule.scope.evidencePackId !== input.evidencePackId
    ) {
      return denied('EVIDENCE_ACCESS_CONTEXT_DRIFT');
    }
    if (context.deletionState === 'DELETED') {
      return this.persistDenied(
        context,
        input.purpose,
        'EVIDENCE_ACCESS_DELETED',
        UNCHECKED_REGISTRY_VERSION,
        decidedAt
      );
    }
    if (context.deletionState === 'DELETION_PENDING') {
      return this.persistDenied(
        context,
        input.purpose,
        'EVIDENCE_ACCESS_DELETION_PENDING',
        UNCHECKED_REGISTRY_VERSION,
        decidedAt
      );
    }
    if (
      Date.parse(decidedAt) >= Date.parse(context.schedule.deleteAfter)
    ) {
      return this.persistDenied(
        context,
        input.purpose,
        'EVIDENCE_ACCESS_EXPIRED',
        UNCHECKED_REGISTRY_VERSION,
        decidedAt
      );
    }
    const validated = validateActiveContext(context);
    if (validated.status === 'DENIED') {
      return this.persistDenied(
        context,
        input.purpose,
        validated.reasonCode,
        UNCHECKED_REGISTRY_VERSION,
        decidedAt
      );
    }
    if (!context.coverageComplete || !context.freshnessEligible) {
      return this.persistDenied(
        context,
        input.purpose,
        'EVIDENCE_ACCESS_COVERAGE_INELIGIBLE',
        UNCHECKED_REGISTRY_VERSION,
        decidedAt
      );
    }
    const profile = validated.scope.profileId;
    if (
      SAST_APPROVED_PROFILE_DIGESTS[profile] !==
      validated.scope.profileDigest
    ) {
      return this.persistDenied(
        context,
        input.purpose,
        'EVIDENCE_ACCESS_PROFILE_UNAPPROVED',
        UNCHECKED_REGISTRY_VERSION,
        decidedAt
      );
    }
    if (
      input.purpose === 'AI_ADVISORY' &&
      (!context.tenantAiAdvisoryOptIn ||
        !context.repositoryAiAdvisoryOptIn)
    ) {
      return this.persistDenied(
        context,
        input.purpose,
        'EVIDENCE_ACCESS_OPT_IN_REQUIRED',
        UNCHECKED_REGISTRY_VERSION,
        decidedAt
      );
    }
    const registry = await this.readRegistry(input);
    if (registry.status !== 'VERIFIED') {
      return this.persistDenied(
        context,
        input.purpose,
        'EVIDENCE_ACCESS_SECRET_AUTHORITY_UNAVAILABLE',
        UNCHECKED_REGISTRY_VERSION,
        decidedAt
      );
    }
    const secrets = normalizeSecretRegistry(registry);
    if (!secrets) {
      return this.persistDenied(
        context,
        input.purpose,
        'EVIDENCE_ACCESS_REDACTION_FAILED',
        UNCHECKED_REGISTRY_VERSION,
        decidedAt
      );
    }
    const pack = context.result?.pack;
    if (!pack) {
      return this.persistDenied(
        context,
        input.purpose,
        'EVIDENCE_ACCESS_CONTEXT_DRIFT',
        registry.registryVersion,
        decidedAt
      );
    }
    const pathReason = classifyPaths(
      pack.fragments.map((fragment) => fragment.normalizedPath),
      secrets
    );
    if (pathReason) {
      return this.persistDenied(
        context,
        input.purpose,
        pathReason,
        registry.registryVersion,
        decidedAt
      );
    }
    const projection = redactPack(pack.fragments, secrets);
    if (!projection) {
      return this.persistDenied(
        context,
        input.purpose,
        'EVIDENCE_ACCESS_REDACTION_FAILED',
        registry.registryVersion,
        decidedAt
      );
    }
    const decision = buildSastEvidenceAccessDecision({
      purpose: input.purpose,
      scope: validated.scope,
      schedule: context.schedule,
      secretRegistryVersion: registry.registryVersion,
      outcome: 'ALLOWED',
      reasonCodes: [],
      redactedProjectionDigest: projection.projectionDigest,
      redactedFragmentCount: projection.fragments.length,
      redactedTotalBytes: projection.totalBytes,
      redactionCount: projection.redactionCount,
      evidenceExpiresAt: pack.expiresAt,
      decidedAt,
      digestCanonical: digest
    });
    const persisted = await this.persist(context, decision);
    if (persisted.outcome === 'DENIED') return persisted;
    if (
      Date.parse(persisted.decision.decidedAt) >
      Date.parse(decidedAt)
    ) {
      return denied(
        'EVIDENCE_ACCESS_INPUT_INVALID',
        persisted.decision,
        persisted.replayed
      );
    }
    return {
      outcome: 'ALLOWED',
      decision: persisted.decision,
      context,
      registryVersion: registry.registryVersion,
      projection,
      replayed: persisted.replayed
    };
  }

  private async persistDenied(
    context: SastEvidenceAccessContext,
    purpose: SastEvidenceAccessPurpose,
    reasonCode: SastEvidenceAccessReasonCode,
    secretRegistryVersion: string,
    decidedAt: string
  ): Promise<Extract<SastEvidenceAccessResult, { outcome: 'DENIED' }>> {
    const decision = buildSastEvidenceAccessDecision({
      purpose,
      scope: context.schedule.scope,
      schedule: context.schedule,
      secretRegistryVersion,
      outcome: 'DENIED',
      reasonCodes: [reasonCode],
      redactedProjectionDigest: null,
      redactedFragmentCount: 0,
      redactedTotalBytes: 0,
      redactionCount: 0,
      evidenceExpiresAt: context.schedule.deleteAfter,
      decidedAt,
      digestCanonical: digest
    });
    const persisted = await this.persist(context, decision);
    if (persisted.outcome === 'DENIED') return persisted;
    return denied(reasonCode, persisted.decision, persisted.replayed);
  }

  private async persist(
    context: SastEvidenceAccessContext,
    decision: SastEvidenceAccessDecision
  ): Promise<
    | { outcome: 'ALLOWED'; decision: SastEvidenceAccessDecision; replayed: boolean }
    | Extract<SastEvidenceAccessResult, { outcome: 'DENIED' }>
  > {
    if (!isSastEvidenceAccessDecisionShapeValid(decision, digest)) {
      return denied('EVIDENCE_ACCESS_OUTPUT_INVALID');
    }
    try {
      const persisted = await this.store.persistDecision({
        context,
        decision
      });
      if (
        !isSastEvidenceAccessDecisionShapeValid(
          persisted.decision,
          digest
        ) ||
        persisted.decision.accessDecisionId !==
          decision.accessDecisionId ||
        persisted.decision.purpose !== decision.purpose ||
        persisted.decision.scope.sourcePackDigest !==
          decision.scope.sourcePackDigest
      ) {
        return denied('EVIDENCE_ACCESS_PERSISTENCE_CONFLICT');
      }
      if (persisted.decision.outcome === 'DENIED') {
        return denied(
          persisted.decision.reasonCodes[0] ??
            'EVIDENCE_ACCESS_OUTPUT_INVALID',
          persisted.decision,
          persisted.replayed
        );
      }
      return {
        outcome: 'ALLOWED',
        decision: persisted.decision,
        replayed: persisted.replayed
      };
    } catch (error) {
      if (error instanceof SastEvidenceAccessPersistenceError) {
        return denied(
          error.reason === 'CONTEXT_DRIFT'
            ? 'EVIDENCE_ACCESS_CONTEXT_DRIFT'
            : error.reason === 'OUTPUT_INVALID'
              ? 'EVIDENCE_ACCESS_OUTPUT_INVALID'
              : 'EVIDENCE_ACCESS_PERSISTENCE_CONFLICT'
        );
      }
      return denied('EVIDENCE_ACCESS_PERSISTENCE_CONFLICT');
    }
  }

  private async readRegistry(input: {
    tenantId: string;
    repositoryBindingId: string;
    evidencePackId: string;
  }): Promise<SastEvidenceSecretRegistryResult> {
    try {
      return await this.secretRegistry.read(input);
    } catch {
      return { status: 'UNAVAILABLE' };
    }
  }

  private async confirmAccess(input: Parameters<
    SastEvidenceAccessStore['confirmAccess']
  >[0]): Promise<SastEvidenceAccessContext | null> {
    try {
      return await this.store.confirmAccess(input);
    } catch {
      return null;
    }
  }
}

function validateActiveContext(
  context: Readonly<SastEvidenceAccessContext>
):
  | { status: 'ACCEPTED'; scope: SastEvidenceAccessScope }
  | { status: 'DENIED'; reasonCode: SastEvidenceAccessReasonCode } {
  const result = context.result;
  if (
    !result ||
    !isSastAcceptedEvidenceBuildResultShapeValid(
      result,
      digest,
      SAST_ACCEPTED_EVIDENCE_POLICY
    ) ||
    result.decision.outcome !== 'ACCEPTED' ||
    !result.pack ||
    result.decision.evidencePackId !== result.pack.evidencePackId ||
    result.decision.evidencePackDigest !== result.pack.packDigest ||
    result.pack.dashboardSafe !== false ||
    result.pack.aiSafe !== false ||
    result.pack.classificationDecisionRef !== null ||
    result.pack.deletionScheduleRef !== null ||
    result.pack.authority.dashboardAccessAllowed !== false ||
    result.pack.authority.aiPayloadAllowed !== false
  ) {
    return {
      status: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_TAMPERED'
    };
  }
  const scope = sastEvidenceAccessScopeFromResult(result);
  if (
    !isSastEvidenceAccessScopeValid(scope) ||
    stableJson(scope) !== stableJson(context.schedule.scope) ||
    result.pack.createdAt !== context.schedule.scheduledAt ||
    result.pack.expiresAt !== context.schedule.deleteAfter
  ) {
    return {
      status: 'DENIED',
      reasonCode: 'EVIDENCE_ACCESS_CONTEXT_DRIFT'
    };
  }
  return { status: 'ACCEPTED', scope };
}

export function toSastEvidenceAccessScope(
  result: Readonly<NonNullable<SastEvidenceAccessContext['result']>>
): SastEvidenceAccessScope {
  return sastEvidenceAccessScopeFromResult(result);
}

function classifyPaths(
  paths: readonly string[],
  secrets: readonly string[]
): SastEvidenceAccessReasonCode | null {
  for (const path of paths) {
    if (!isSafeNormalizedPath(path)) {
      return 'EVIDENCE_ACCESS_PATH_UNSAFE';
    }
    if (
      containsKnownSecret(path) ||
      secrets.some((secret) => path.includes(secret)) ||
      path
        .split('/')
        .some(
          (segment) =>
            segment.length >= 24 && looksHighEntropy(segment)
        )
    ) {
      return 'EVIDENCE_ACCESS_IDENTIFIER_UNSAFE';
    }
  }
  return null;
}

function redactPack(
  fragments: ReadonlyArray<{
    fragmentId: string;
    ordinal: number;
    role: 'PRIMARY' | 'RELATED';
    normalizedPath: string;
    startLine: number;
    endLine: number;
    redactedContent: string;
  }>,
  secrets: readonly string[]
): RedactionProjection | null {
  const safe: SastEvidenceSafeFragment[] = [];
  let totalBytes = 0;
  let redactionCount = 0;
  for (const fragment of [...fragments].sort(
    (left, right) => left.ordinal - right.ordinal
  )) {
    let content = fragment.redactedContent;
    const expectedLines = countLines(content);
    for (const pattern of KNOWN_SECRET_PATTERNS) {
      pattern.lastIndex = 0;
      content = content.replace(pattern, (matched) => {
        redactionCount += 1;
        return redactionReplacement(matched);
      });
    }
    for (const secret of secrets) {
      const parts = content.split(secret);
      if (parts.length > 1) {
        redactionCount += parts.length - 1;
        content = parts.join(redactionReplacement(secret));
      }
    }
    ENTROPY_TOKEN_PATTERN.lastIndex = 0;
    content = content.replace(ENTROPY_TOKEN_PATTERN, (matched) => {
      if (!looksHighEntropy(matched)) return matched;
      redactionCount += 1;
      return redactionReplacement(matched);
    });
    const byteSize = Buffer.byteLength(content, 'utf8');
    const projected: SastEvidenceSafeFragment = {
      fragmentId: fragment.fragmentId,
      ordinal: fragment.ordinal,
      role: fragment.role,
      normalizedPath: fragment.normalizedPath,
      startLine: fragment.startLine,
      endLine: fragment.endLine,
      redactedContent: content,
      byteSize,
      contentDigest: digest(content)
    };
    if (
      countLines(content) !== expectedLines ||
      byteSize <= 0 ||
      byteSize > SAST_ACCEPTED_EVIDENCE_POLICY.maxFragmentBytes ||
      totalBytes >
        SAST_ACCEPTED_EVIDENCE_POLICY.maxTotalBytes - byteSize ||
      !isSastEvidenceSafeFragmentShapeValid(projected)
    ) {
      return null;
    }
    totalBytes += byteSize;
    safe.push(projected);
  }
  if (
    safe.length === 0 ||
    safe.length > SAST_ACCEPTED_EVIDENCE_POLICY.maxFragmentCount
  ) {
    return null;
  }
  return {
    fragments: safe,
    projectionDigest: digest(
      canonicalizeSastEvidenceSafeFragments(safe)
    ),
    totalBytes,
    redactionCount
  };
}

function normalizeSecretRegistry(
  registry: Extract<
    SastEvidenceSecretRegistryResult,
    { status: 'VERIFIED' }
  >
): string[] | null {
  if (
    !isBoundedText(registry.registryVersion, 2048) ||
    !Array.isArray(registry.platformSecretValues) ||
    registry.platformSecretValues.length >
      SAST_SECRET_REDACTION_LIMITS.maximumPlatformSecretValues
  ) {
    return null;
  }
  const seen = new Set<string>();
  let totalBytes = 0;
  for (const value of registry.platformSecretValues as readonly unknown[]) {
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      value !== value.normalize('NFC') ||
      value.includes(REDACTION_TOKEN) ||
      !/\S/u.test(value) ||
      /\p{Cc}/u.test(value)
    ) {
      return null;
    }
    const bytes = Buffer.byteLength(value, 'utf8');
    if (
      bytes < 8 ||
      bytes >
        SAST_SECRET_REDACTION_LIMITS.maximumPlatformSecretValueBytes ||
      totalBytes >
        SAST_SECRET_REDACTION_LIMITS
          .maximumPlatformSecretValueTotalBytes -
          bytes ||
      seen.has(value)
    ) {
      return null;
    }
    totalBytes += bytes;
    seen.add(value);
  }
  if (
    containsKnownSecret(registry.registryVersion) ||
    [...seen].some((secret) => registry.registryVersion.includes(secret))
  ) {
    return null;
  }
  return [...seen].sort(
    (left, right) =>
      right.length - left.length || compareCodeUnits(left, right)
  );
}

function containsKnownSecret(value: string): boolean {
  for (const pattern of KNOWN_SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(value)) {
      pattern.lastIndex = 0;
      return true;
    }
  }
  return false;
}

function dashboardEvidence(
  decision: Readonly<SastEvidenceAccessDecision>,
  projection: Readonly<RedactionProjection>,
  truncated: boolean
): SastDashboardEvidence {
  return {
    version: SAST_DASHBOARD_EVIDENCE_VERSION,
    accessDecisionId: decision.accessDecisionId,
    accessDecisionDigest: decision.decisionDigest,
    evidencePackId: decision.scope.evidencePackId,
    findingFingerprint: decision.scope.findingFingerprint,
    fragments: projection.fragments,
    totalBytes: projection.totalBytes,
    truncated,
    expiresAt: decision.evidenceExpiresAt,
    advisoryOnly: true
  };
}

function reducedReference(
  decision: Readonly<SastEvidenceAccessDecision>
): SastReducedEvidenceReference {
  if (
    !decision.reducedEvidenceRef ||
    !decision.redactedProjectionDigest ||
    !decision.aiPayloadExpiresAt
  ) {
    throw new Error('Allowed AI classification is incomplete.');
  }
  return {
    version: SAST_REDUCED_EVIDENCE_REFERENCE_VERSION,
    reducedEvidenceRef: decision.reducedEvidenceRef,
    accessDecisionId: decision.accessDecisionId,
    accessDecisionDigest: decision.decisionDigest,
    evidencePackId: decision.scope.evidencePackId,
    findingFingerprint: decision.scope.findingFingerprint,
    redactedProjectionDigest: decision.redactedProjectionDigest,
    fragmentCount: decision.redactedFragmentCount,
    payloadExpiresAt: decision.aiPayloadExpiresAt,
    aiPayloadCreated: false,
    aiProviderCalled: false,
    retrievalAllowed: false,
    toolsAllowed: false,
    advisoryOnly: true
  };
}

function denied(
  reasonCode: SastEvidenceAccessReasonCode,
  decision: SastEvidenceAccessDecision | null = null,
  replayed = false
): Extract<SastEvidenceAccessResult, { outcome: 'DENIED' }> {
  return {
    outcome: 'DENIED',
    reasonCode,
    decision,
    replayed,
    dashboardEvidence: null,
    reducedEvidenceReference: null
  };
}

function isClassificationInputValid(value: unknown): value is {
  tenantId: string;
  repositoryBindingId: string;
  evidencePackId: string;
  purpose: SastEvidenceAccessPurpose;
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    Object.keys(record).length === 4 &&
    ['tenantId', 'repositoryBindingId', 'evidencePackId', 'purpose'].every(
      (key) => Object.hasOwn(record, key)
    ) &&
    isBoundedText(record.tenantId, 255) &&
    isBoundedText(record.repositoryBindingId, 255) &&
    typeof record.evidencePackId === 'string' &&
    /^sast-evidence-pack:\/\/[a-f0-9]{64}$/u.test(
      record.evidencePackId
    ) &&
    (record.purpose === 'DASHBOARD' ||
      record.purpose === 'AI_ADVISORY')
  );
}

function isBoundedText(value: unknown, maximum: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maximum &&
    value === value.normalize('NFC') &&
    value === value.trim() &&
    !/\p{Cc}/u.test(value)
  );
}

function looksHighEntropy(value: string): boolean {
  if (value.length < 24 || value === REDACTION_TOKEN) return false;
  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  const classes = [/[a-z]/u, /[A-Z]/u, /[0-9]/u, /[^A-Za-z0-9]/u].filter(
    (pattern) => pattern.test(value)
  ).length;
  return entropy >= 3.5 && classes >= 2;
}

function redactionReplacement(value: string): string {
  return REDACTION_TOKEN + '\n'.repeat(countNewlines(value));
}

function countLines(value: string): number {
  return value.split('\n').length;
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

function readClock(clock: EvidenceClock): string | null {
  try {
    const value = clock();
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) &&
      new Date(milliseconds).toISOString() === value
      ? value
      : null;
  } catch {
    return null;
  }
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return '[' + value.map(stableJson).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return (
      '{' +
      Object.keys(record)
        .sort()
        .map(
          (key) =>
            JSON.stringify(key) + ':' + stableJson(record[key])
        )
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(value);
}
