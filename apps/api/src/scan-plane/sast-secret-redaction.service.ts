import { createHash } from 'node:crypto';
import { TextEncoder } from 'node:util';

import { Injectable } from '@nestjs/common';
import {
  SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
  SAST_SECRET_REDACTION_LIMITS,
  SAST_SECRET_REDACTION_TOKEN,
  SAST_SECRET_REDACTION_VERSION,
  canonicalizeOpenGrepSarifNormalizationBatch,
  canonicalizeSastArtifactDispositionDecision,
  canonicalizeSastSecretRedactionBatch,
  canonicalizeSastSecretRedactionDecision,
  canonicalizeSastSecretRedactionRejection,
  canonicalizeTrivyJsonNormalizationBatch,
  compareSastNormalizedFindingCandidates,
  isOpenGrepSarifNormalizationBatchShapeValid,
  isSastArtifactDispositionDecisionShapeValid,
  isSastSecretRedactedFindingCandidateShapeValid,
  isSastSecretRedactionBatchShapeValid,
  isTrivyJsonNormalizationBatchShapeValid,
  orderSastSecretDetectorKinds,
  orderSastSecretRedactableFields,
  orderSastSecretRedactionRejectionReasons,
  stripSastSecretRedaction,
  type OpenGrepSarifNormalizationBatch,
  type SastArtifactDispositionDecision,
  type SastNormalizedFindingCandidate,
  type SastSecretDetectorKind,
  type SastSecretRedactableField,
  type SastSecretRedactedFindingCandidate,
  type SastSecretRedactedFindingCandidateCore,
  type SastSecretRedactionBatchCore,
  type SastSecretRedactionRejectionCore,
  type SastSecretRedactionRejectionReasonCode,
  type SastSecretRedactionResult,
  type TrivyJsonNormalizationBatch
} from '@aegisai/shared';

const UTF8_ENCODER = new TextEncoder();
const SECRET_CONTEXT =
  /(?:api[-_ ]?key|authorization|bearer|client[-_ ]?secret|credential|passwd|password|private[-_ ]?key|secret|session|token)/iu;

interface SecretPattern {
  kind: SastSecretDetectorKind;
  expression: RegExp;
  contextual?: true;
}

/**
 * These patterns are deliberately bounded and linear over already-bounded
 * candidate text. Provider lists are versioned with this redaction contract;
 * any expansion requires corpus review and a version change.
 */
const KNOWN_SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    kind: 'PRIVATE_KEY',
    expression:
      /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]{0,4096}?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/gu
  },
  {
    kind: 'AUTHORIZATION_CREDENTIAL',
    contextual: true,
    expression:
      /\b(?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9+/_=.-]{4,2048}/giu
  },
  {
    kind: 'URL_CREDENTIAL',
    contextual: true,
    expression:
      /\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s/@:]{1,256}:[^\s/@]{1,512}@/giu
  },
  {
    kind: 'AWS_ACCESS_KEY_ID',
    expression: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu
  },
  {
    kind: 'GITHUB_TOKEN',
    expression:
      /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/gu
  },
  {
    kind: 'GITLAB_TOKEN',
    expression:
      /\b(?:glpat|gloas|gldt|glrt|glrtr|glcbt|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_-]{8,255}\b/gu
  },
  {
    kind: 'SLACK_TOKEN',
    expression:
      /\b(?:xox[baprs]-[A-Za-z0-9-]{10,255}|https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,512})\b/gu
  },
  {
    kind: 'GOOGLE_API_KEY',
    expression: /\bAIza[A-Za-z0-9_-]{35}\b/gu
  },
  {
    kind: 'STRIPE_KEY',
    expression:
      /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b/gu
  },
  {
    kind: 'SENDGRID_KEY',
    expression:
      /\bSG\.[A-Za-z0-9_-]{16,255}\.[A-Za-z0-9_-]{16,255}\b/gu
  },
  {
    kind: 'JWT',
    expression:
      /\beyJ[A-Za-z0-9_-]{5,511}\.[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}\b/gu
  },
  {
    kind: 'SECRET_ASSIGNMENT',
    contextual: true,
    expression:
      /\b(?:access[-_ ]?key|api[-_ ]?key|client[-_ ]?secret|passwd|password|private[-_ ]?key|pwd|secret|session[-_ ]?token|token)\b\s*(?:=>|=|:)\s*(?:"[^"\r\n]{1,512}"|'[^'\r\n]{1,512}'|[^\s,;]{4,512})/giu
  }
];

interface SecretSpan {
  start: number;
  end: number;
  kinds: Set<SastSecretDetectorKind>;
}

interface SecretInspection {
  spans: SecretSpan[];
  kinds: SastSecretDetectorKind[];
}

interface RedactedText {
  value: string;
  replacementCount: number;
  detectorKinds: SastSecretDetectorKind[];
}

interface PlatformSecretMatcherNode {
  transitions: Map<string, number>;
  failure: number;
  outputLengths: number[];
}

interface CandidateRedaction {
  candidate?: SastSecretRedactedFindingCandidate;
  inspectedFieldCount: number;
  rejectionReason?: Extract<
    SastSecretRedactionRejectionReasonCode,
    | 'SECRET_REDACTION_RESERVED_TOKEN_PRESENT'
    | 'SECRET_REDACTION_IDENTITY_FIELD_BLOCKED'
    | 'SECRET_REDACTION_OUTPUT_INVALID'
  >;
}

export type SastSecretRedactionSourceBatch =
  | OpenGrepSarifNormalizationBatch
  | TrivyJsonNormalizationBatch;

export interface SastSecretRedactionInput {
  batch: Readonly<SastSecretRedactionSourceBatch>;
  disposition: Readonly<SastArtifactDispositionDecision>;
  /**
   * Caller-owned transient values from the Data/Security Plane. The service
   * never copies them into a result, digest, exception, log, or class field.
   */
  platformSecretValues?: readonly string[];
}

@Injectable()
export class SastSecretRedactionService {
  redact(
    input: Readonly<SastSecretRedactionInput>,
    clock: () => Date = () => new Date()
  ): SastSecretRedactionResult {
    if (!hasCandidateCountWithinLimit(input?.batch)) {
      return this.reject(['SECRET_REDACTION_INPUT_INVALID']);
    }
    const source = classifySourceBatch(input?.batch);
    if (!source) {
      return this.reject(['SECRET_REDACTION_INPUT_INVALID']);
    }
    if (
      source.batch.findings.length >
      SAST_SECRET_REDACTION_LIMITS.maximumCandidates
    ) {
      return this.reject(['SECRET_REDACTION_INPUT_INVALID']);
    }
    if (!isSourceBatchDigestValid(source)) {
      return this.reject([
        'SECRET_REDACTION_SOURCE_DIGEST_MISMATCH'
      ]);
    }

    const dispositionReasons = validateDisposition(
      input.disposition,
      source.batch
    );
    const firstReferenceTime = readReferenceTime(clock);
    if (
      dispositionReasons.length > 0 ||
      !Number.isFinite(firstReferenceTime) ||
      firstReferenceTime <
        Date.parse(input.disposition.decidedAt)
    ) {
      return this.reject([
        ...dispositionReasons,
        'SECRET_REDACTION_DISPOSITION_INVALID'
      ]);
    }
    const retentionExpiresAt =
      input.disposition.retentionExpiresAt as string;
    if (firstReferenceTime >= Date.parse(retentionExpiresAt)) {
      return this.reject([
        'SECRET_REDACTION_RETENTION_EXPIRED'
      ]);
    }

    const platformSecrets = normalizePlatformSecretValues(
      input.platformSecretValues
    );
    if (!platformSecrets) {
      return this.reject([
        'SECRET_REDACTION_PLATFORM_VALUES_INVALID'
      ]);
    }
    const platformMatcher =
      new PlatformSecretMatcher(platformSecrets);
    if (
      batchBindingFields(source.batch).some(
        (field) =>
          inspectSecrets(
            field,
            platformMatcher,
            false,
            false,
            false
          ).spans.length > 0
      )
    ) {
      return this.reject([
        'SECRET_REDACTION_IDENTITY_FIELD_BLOCKED'
      ]);
    }

    const findings: SastSecretRedactedFindingCandidate[] = [];
    let inspectedFieldCount = 0;
    for (const finding of source.batch.findings) {
      const redacted = redactCandidate(
        finding,
        platformMatcher
      );
      inspectedFieldCount += redacted.inspectedFieldCount;
      if (!redacted.candidate || redacted.rejectionReason) {
        return this.reject([
          redacted.rejectionReason ??
            'SECRET_REDACTION_OUTPUT_INVALID'
        ]);
      }
      findings.push(redacted.candidate);
    }
    findings.sort((left, right) =>
      compareSastNormalizedFindingCandidates(
        stripSastSecretRedaction(left),
        stripSastSecretRedaction(right)
      )
    );

    const secondReferenceTime = readReferenceTime(clock);
    if (
      !Number.isFinite(secondReferenceTime) ||
      secondReferenceTime < firstReferenceTime
    ) {
      return this.reject([
        'SECRET_REDACTION_DISPOSITION_INVALID'
      ]);
    }
    if (secondReferenceTime >= Date.parse(retentionExpiresAt)) {
      return this.reject([
        'SECRET_REDACTION_RETENTION_EXPIRED'
      ]);
    }

    const redactedCandidateCount = findings.filter(
      (finding) => finding.redaction.replacementCount > 0
    ).length;
    const redactedFieldCount = findings.reduce(
      (sum, finding) =>
        sum + finding.redaction.redactedFields.length,
      0
    );
    const replacementCount = findings.reduce(
      (sum, finding) =>
        sum + finding.redaction.replacementCount,
      0
    );
    const detectorKinds = orderSastSecretDetectorKinds(
      findings.flatMap(
        (finding) => finding.redaction.detectorKinds
      )
    );
    const batchCore: SastSecretRedactionBatchCore = {
      version: SAST_SECRET_REDACTION_VERSION,
      outcome: 'REDACTED',
      sourceAdapterVersion: source.batch.adapterVersion,
      artifactSchema: source.batch.artifactSchema,
      artifactSchemaVersion: source.batch.artifactSchemaVersion,
      ingestionId: source.batch.ingestionId,
      scope: {
        tenantId: source.batch.scope.tenantId,
        repositoryBindingId:
          source.batch.scope.repositoryBindingId,
        scanRequestId: source.batch.scope.scanRequestId,
        attemptId: source.batch.scope.attemptId,
        scannerRunId: source.batch.scope.scannerRunId
      },
      scannerRunId: source.batch.scannerRunId,
      scanner: source.batch.scanner,
      scannerVersion: source.batch.scannerVersion,
      scannerImageDigest: source.batch.scannerImageDigest,
      ruleBundleDigest: source.batch.ruleBundleDigest,
      ...('vulnerabilityDatabaseDigest' in source.batch
        ? {
            vulnerabilityDatabaseDigest:
              source.batch.vulnerabilityDatabaseDigest
          }
        : {}),
      planDigest: source.batch.planDigest,
      canonicalScanKey: source.batch.canonicalScanKey,
      preflightAttestationRef:
        source.batch.preflightAttestationRef,
      preflightInventoryDigest:
        source.batch.preflightInventoryDigest,
      lane: source.batch.lane,
      commitSha: source.batch.commitSha,
      envelopeDigest: source.batch.envelopeDigest,
      artifactDigest: source.batch.artifactDigest,
      schemaBundleDigest: source.batch.schemaBundleDigest,
      normalizerBundleDigest:
        source.batch.normalizerBundleDigest,
      validationResultDigest:
        source.batch.validationResultDigest,
      dispositionDecisionDigest:
        source.batch.dispositionDecisionDigest,
      retentionExpiresAt,
      findings,
      redaction: {
        version: SAST_SECRET_REDACTION_VERSION,
        secretRedactionApplied: true,
        candidateCount: findings.length,
        batchInspectedFieldCount:
          SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
        inspectedFieldCount:
          inspectedFieldCount +
          SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
        redactedCandidateCount,
        redactedFieldCount,
        replacementCount,
        detectorKinds,
        secretValuesStored: false,
        matchedValueDigestsStored: false,
        rawCandidatesStored: false,
        sourceCandidateDigestStored: false
      },
      durablePersistenceAllowed: false
    };
    const batch = {
      ...batchCore,
      batchDigest: digest(
        canonicalizeSastSecretRedactionBatch(batchCore)
      )
    };
    if (!isSastSecretRedactionBatchShapeValid(batch)) {
      return this.reject(['SECRET_REDACTION_OUTPUT_INVALID']);
    }
    return {
      outcome: 'REDACTED',
      batch
    };
  }

  private reject(
    reasons: Iterable<SastSecretRedactionRejectionReasonCode>
  ): SastSecretRedactionResult {
    const core: SastSecretRedactionRejectionCore = {
      version: SAST_SECRET_REDACTION_VERSION,
      outcome: 'REJECTED',
      reasonCodes:
        orderSastSecretRedactionRejectionReasons(reasons),
      secretValuesStored: false,
      matchedValueDigestsStored: false,
      sourceCandidateDigestStored: false
    };
    return {
      ...core,
      rejectionDigest: digest(
        canonicalizeSastSecretRedactionRejection(core)
      )
    };
  }
}

type ClassifiedSource =
  | {
      kind: 'OPENGREP';
      batch: Readonly<OpenGrepSarifNormalizationBatch>;
    }
  | {
      kind: 'TRIVY';
      batch: Readonly<TrivyJsonNormalizationBatch>;
    };

function classifySourceBatch(value: unknown): ClassifiedSource | null {
  if (isOpenGrepSarifNormalizationBatchShapeValid(value)) {
    return { kind: 'OPENGREP', batch: value };
  }
  if (isTrivyJsonNormalizationBatchShapeValid(value)) {
    return { kind: 'TRIVY', batch: value };
  }
  return null;
}

function hasCandidateCountWithinLimit(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return true;
  }
  const findings = (value as { findings?: unknown }).findings;
  return (
    !Array.isArray(findings) ||
    findings.length <=
      SAST_SECRET_REDACTION_LIMITS.maximumCandidates
  );
}

function isSourceBatchDigestValid(source: ClassifiedSource): boolean {
  if (source.kind === 'OPENGREP') {
    const { batchDigest, ...core } = source.batch;
    return (
      digest(
        canonicalizeOpenGrepSarifNormalizationBatch(core)
      ) === batchDigest
    );
  }
  const { batchDigest, ...core } = source.batch;
  return (
    digest(canonicalizeTrivyJsonNormalizationBatch(core)) ===
    batchDigest
  );
}

function validateDisposition(
  disposition: unknown,
  batch: Readonly<SastSecretRedactionSourceBatch>
): SastSecretRedactionRejectionReasonCode[] {
  if (!isSastArtifactDispositionDecisionShapeValid(disposition)) {
    return ['SECRET_REDACTION_DISPOSITION_INVALID'];
  }
  const { decisionDigest, ...core } = disposition;
  if (
    digest(canonicalizeSastArtifactDispositionDecision(core)) !==
      decisionDigest ||
    disposition.disposition !== 'ACCEPTED' ||
    disposition.normalizationEligible !== true ||
    disposition.ingestionId !== batch.ingestionId ||
    disposition.validationResultDigest !==
      batch.validationResultDigest ||
    disposition.decisionDigest !==
      batch.dispositionDecisionDigest ||
    !disposition.retentionExpiresAt
  ) {
    return ['SECRET_REDACTION_DISPOSITION_INVALID'];
  }
  return [];
}

function batchBindingFields(
  batch: Readonly<SastSecretRedactionSourceBatch>
): readonly string[] {
  return [
    batch.ingestionId,
    batch.scope.tenantId,
    batch.scope.repositoryBindingId,
    batch.scope.scanRequestId,
    batch.scope.attemptId,
    batch.scope.scannerRunId,
    batch.scannerVersion,
    batch.preflightAttestationRef
  ];
}

function normalizePlatformSecretValues(
  values: readonly string[] | undefined
): string[] | null {
  if (values === undefined) return [];
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
      hasUnsafePlatformSecretCharacter(value) ||
      value.includes(SAST_SECRET_REDACTION_TOKEN) ||
      !/\S/u.test(value)
    ) {
      return null;
    }
    const byteSize = UTF8_ENCODER.encode(value).byteLength;
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

function redactCandidate(
  candidate: Readonly<SastNormalizedFindingCandidate>,
  platformMatcher: Readonly<PlatformSecretMatcher>
): CandidateRedaction {
  const displayFields: Array<{
    field: SastSecretRedactableField;
    value: string;
  }> = [
    { field: 'TITLE', value: candidate.title },
    { field: 'DESCRIPTION', value: candidate.description },
    ...(candidate.location.symbol === undefined
      ? []
      : [
          {
            field: 'LOCATION_SYMBOL' as const,
            value: candidate.location.symbol
          }
        ])
  ];
  const identityFields = identityBearingFields(candidate);
  const inspectedFieldCount =
    displayFields.length + identityFields.length;
  if (
    [
      ...displayFields.map(({ value }) => value),
      ...identityFields.map(({ value }) => value)
    ]
      .some((value) =>
        value.includes(SAST_SECRET_REDACTION_TOKEN)
      )
  ) {
    return {
      inspectedFieldCount,
      rejectionReason:
        'SECRET_REDACTION_RESERVED_TOKEN_PRESENT'
    };
  }

  for (const identityField of identityFields) {
    if (
      inspectSecrets(
        identityField.value,
        platformMatcher,
        identityField.includeEntropy,
        identityField.includeContextual,
        false
      ).spans.length > 0
    ) {
      return {
        inspectedFieldCount,
        rejectionReason:
          'SECRET_REDACTION_IDENTITY_FIELD_BLOCKED'
      };
    }
  }

  const redactedByField = new Map<
    SastSecretRedactableField,
    RedactedText
  >();
  for (const { field, value } of displayFields) {
    redactedByField.set(
      field,
      redactText(value, platformMatcher)
    );
  }
  const title =
    redactedByField.get('TITLE')?.value ?? candidate.title;
  const description =
    redactedByField.get('DESCRIPTION')?.value ??
    candidate.description;
  const location = cloneLocation(
    candidate,
    redactedByField.get('LOCATION_SYMBOL')?.value
  );
  const base = cloneCandidate(
    candidate,
    title,
    description,
    location
  );
  const redactedFields = orderSastSecretRedactableFields(
    [...redactedByField.entries()]
      .filter(([, result]) => result.replacementCount > 0)
      .map(([field]) => field)
  );
  const replacementCount = [...redactedByField.values()].reduce(
    (sum, result) => sum + result.replacementCount,
    0
  );
  const detectorKinds = orderSastSecretDetectorKinds(
    [...redactedByField.values()].flatMap(
      (result) => result.detectorKinds
    )
  );
  const redactionCore = {
    version: SAST_SECRET_REDACTION_VERSION,
    secretRedactionApplied: true as const,
    replacementToken: SAST_SECRET_REDACTION_TOKEN,
    inspectedFieldCount,
    redactedFields,
    replacementCount,
    detectorKinds,
    secretValueStored: false as const,
    matchedValueDigestStored: false as const,
    rawCandidateStored: false as const
  };
  const decisionCore = {
    ...base,
    redaction: redactionCore
  } as SastSecretRedactedFindingCandidateCore;
  const decisionDigest = digest(
    canonicalizeSastSecretRedactionDecision(decisionCore)
  );
  const redacted = {
    ...base,
    redaction: {
      ...redactionCore,
      decisionDigest,
      decisionRef:
        `redaction://${SAST_SECRET_REDACTION_VERSION}/${decisionDigest.slice(
          'sha256:'.length
        )}`
    }
  } as SastSecretRedactedFindingCandidate;
  if (!isSastSecretRedactedFindingCandidateShapeValid(redacted)) {
    return {
      inspectedFieldCount,
      rejectionReason: 'SECRET_REDACTION_OUTPUT_INVALID'
    };
  }
  return { candidate: redacted, inspectedFieldCount };
}

function identityBearingFields(
  candidate: Readonly<SastNormalizedFindingCandidate>
): Array<{
  value: string;
  includeEntropy: boolean;
  includeContextual: boolean;
}> {
  const fields: Array<{
    value: string;
    includeEntropy: boolean;
    includeContextual: boolean;
  }> = [
    {
      value: candidate.identityMaterial.ruleSemanticId,
      includeEntropy: true,
      includeContextual: false
    },
    {
      value: candidate.identityMaterial.symbolAnchor,
      includeEntropy: true,
      includeContextual: true
    },
    {
      value: candidate.identityMaterial.sinkKind,
      includeEntropy: true,
      includeContextual: true
    },
    {
      value: candidate.identityMaterial.scannerMatchBasedId,
      includeEntropy: true,
      includeContextual: false
    },
    {
      value: candidate.provenance.scannerVersion,
      includeEntropy: true,
      includeContextual: false
    },
    {
      value: candidate.provenance.ruleId,
      includeEntropy: true,
      includeContextual: false
    },
    {
      value: candidate.provenance.ruleRevision,
      includeEntropy: true,
      includeContextual: false
    }
  ];
  if (candidate.location.kind === 'FILE') {
    fields.push({
      value: candidate.location.normalizedPath,
      includeEntropy: true,
      includeContextual: true
    });
  }
  if (!('trivy' in candidate)) return fields;
  if (candidate.trivy.kind === 'DEPENDENCY_VULNERABILITY') {
    fields.push(
      {
        value: candidate.trivy.vulnerabilityId,
        includeEntropy: true,
        includeContextual: false
      },
      {
        value: candidate.trivy.packageName,
        includeEntropy: true,
        includeContextual: true
      },
      {
        value: candidate.trivy.packageType,
        includeEntropy: true,
        includeContextual: true
      },
      {
        value: candidate.trivy.installedVersion,
        includeEntropy: true,
        includeContextual: true
      },
      {
        value: candidate.trivy.fixedVersion,
        includeEntropy: true,
        includeContextual: true
      }
    );
  } else if (candidate.trivy.kind === 'SECRET_DETECTION') {
    fields.push({
      value: candidate.trivy.category,
      includeEntropy: true,
      includeContextual: true
    });
  } else {
    fields.push(
      {
        value: candidate.trivy.checkType,
        includeEntropy: true,
        includeContextual: true
      },
      {
        value: candidate.trivy.avdId,
        includeEntropy: true,
        includeContextual: true
      }
    );
  }
  return fields;
}

function cloneCandidate(
  candidate: Readonly<SastNormalizedFindingCandidate>,
  title: string,
  description: string,
  location: SastNormalizedFindingCandidate['location']
): SastNormalizedFindingCandidate {
  const common = {
    ...candidate,
    title,
    description,
    cweIds: [...candidate.cweIds],
    cveIds: [...candidate.cveIds],
    location,
    identityMaterial: { ...candidate.identityMaterial },
    provenance: { ...candidate.provenance },
    notes: [...candidate.notes],
    durablePersistenceAllowed: false as const
  };
  if (!('trivy' in candidate)) {
    return common as SastNormalizedFindingCandidate;
  }
  return {
    ...common,
    scannerDisposition: { ...candidate.scannerDisposition },
    trivy: { ...candidate.trivy }
  } as SastNormalizedFindingCandidate;
}

function cloneLocation(
  candidate: Readonly<SastNormalizedFindingCandidate>,
  redactedSymbol: string | undefined
): SastNormalizedFindingCandidate['location'] {
  const location = candidate.location;
  if (location.kind === 'UNKNOWN') {
    return {
      kind: location.kind,
      reasonCode: location.reasonCode,
      ...(redactedSymbol === undefined
        ? {}
        : { symbol: redactedSymbol })
    };
  }
  return {
    kind: location.kind,
    normalizedPath: location.normalizedPath,
    lineStart: location.lineStart,
    ...(location.lineEnd === undefined
      ? {}
      : { lineEnd: location.lineEnd }),
    ...(location.columnStart === undefined
      ? {}
      : { columnStart: location.columnStart }),
    ...(location.columnEnd === undefined
      ? {}
      : { columnEnd: location.columnEnd }),
    ...(redactedSymbol === undefined
      ? {}
      : { symbol: redactedSymbol })
  };
}

function redactText(
  value: string,
  platformMatcher: Readonly<PlatformSecretMatcher>
): RedactedText {
  const inspection = inspectSecrets(
    value,
    platformMatcher,
    true
  );
  if (inspection.spans.length === 0) {
    return {
      value,
      replacementCount: 0,
      detectorKinds: []
    };
  }
  let output = '';
  let offset = 0;
  for (const span of inspection.spans) {
    output += value.slice(offset, span.start);
    output += SAST_SECRET_REDACTION_TOKEN;
    offset = span.end;
  }
  output += value.slice(offset);
  return {
    value: output,
    replacementCount: inspection.spans.length,
    detectorKinds: inspection.kinds
  };
}

function inspectSecrets(
  value: string,
  platformMatcher: Readonly<PlatformSecretMatcher>,
  includeEntropy: boolean,
  includeContextual = true,
  aggressiveEntropy = true
): SecretInspection {
  const spans = platformMatcher.find(value);
  for (const pattern of KNOWN_SECRET_PATTERNS) {
    if (pattern.contextual && !includeContextual) continue;
    pattern.expression.lastIndex = 0;
    for (const match of value.matchAll(pattern.expression)) {
      const start = match.index;
      if (
        start !== undefined &&
        match[0].length > 0
      ) {
        addSpan(
          spans,
          start,
          start + match[0].length,
          pattern.kind
        );
      }
    }
  }
  if (includeEntropy) {
    const expression =
      /[A-Za-z0-9][A-Za-z0-9+/_=-]{19,511}/gu;
    for (const match of value.matchAll(expression)) {
      const start = match.index;
      const token = match[0];
      if (
        start !== undefined &&
        isHighEntropySecret(
          value,
          token,
          start,
          aggressiveEntropy
        )
      ) {
        addSpan(
          spans,
          start,
          start + token.length,
          'HIGH_ENTROPY'
        );
      }
    }
  }
  const merged = mergeSpans(spans);
  return {
    spans: merged,
    kinds: orderSastSecretDetectorKinds(
      merged.flatMap((span) => [...span.kinds])
    )
  };
}

/**
 * A per-call Aho-Corasick matcher keeps registered-value inspection linear in
 * total candidate text plus matches instead of rescanning each field up to 64
 * times. Nodes are local to one redaction call and never escape in results.
 */
class PlatformSecretMatcher {
  private readonly nodes: PlatformSecretMatcherNode[] = [
    {
      transitions: new Map(),
      failure: 0,
      outputLengths: []
    }
  ];

  constructor(values: readonly string[]) {
    for (const value of values) this.insert(value);
    this.buildFailures();
  }

  find(value: string): SecretSpan[] {
    const spans: SecretSpan[] = [];
    let state = 0;
    for (let index = 0; index < value.length; index += 1) {
      const character = value[index] as string;
      while (
        state !== 0 &&
        !this.nodes[state]?.transitions.has(character)
      ) {
        state = this.nodes[state]?.failure ?? 0;
      }
      state =
        this.nodes[state]?.transitions.get(character) ??
        this.nodes[0]?.transitions.get(character) ??
        0;
      const lengths =
        this.nodes[state]?.outputLengths ?? [];
      if (lengths.length === 0) continue;
      const end = index + 1;
      const start = Math.min(
        ...lengths.map((length) => end - length)
      );
      const previous = spans.at(-1);
      if (previous && start <= previous.end) {
        previous.start = Math.min(previous.start, start);
        previous.end = Math.max(previous.end, end);
        previous.kinds.add('PLATFORM_VALUE');
      } else {
        spans.push({
          start,
          end,
          kinds: new Set(['PLATFORM_VALUE'])
        });
      }
    }
    return spans;
  }

  private insert(value: string): void {
    let state = 0;
    for (let index = 0; index < value.length; index += 1) {
      const character = value[index] as string;
      const existing =
        this.nodes[state]?.transitions.get(character);
      if (existing !== undefined) {
        state = existing;
        continue;
      }
      const next = this.nodes.length;
      this.nodes.push({
        transitions: new Map(),
        failure: 0,
        outputLengths: []
      });
      this.nodes[state]?.transitions.set(character, next);
      state = next;
    }
    this.nodes[state]?.outputLengths.push(value.length);
  }

  private buildFailures(): void {
    const queue: number[] = [];
    for (const state of this.nodes[0]?.transitions.values() ?? []) {
      queue.push(state);
    }
    for (let offset = 0; offset < queue.length; offset += 1) {
      const state = queue[offset] as number;
      const node = this.nodes[state] as PlatformSecretMatcherNode;
      for (const [character, next] of node.transitions) {
        queue.push(next);
        let failure = node.failure;
        while (
          failure !== 0 &&
          !this.nodes[failure]?.transitions.has(character)
        ) {
          failure = this.nodes[failure]?.failure ?? 0;
        }
        const fallback =
          this.nodes[failure]?.transitions.get(character);
        this.nodes[next]!.failure =
          fallback === undefined || fallback === next
            ? 0
            : fallback;
        const inherited =
          this.nodes[this.nodes[next]!.failure]?.outputLengths ?? [];
        this.nodes[next]!.outputLengths = [
          ...new Set([
            ...this.nodes[next]!.outputLengths,
            ...inherited
          ])
        ];
      }
    }
  }
}

function isHighEntropySecret(
  source: string,
  token: string,
  start: number,
  aggressive: boolean
): boolean {
  const classes = [
    /[a-z]/u,
    /[A-Z]/u,
    /[0-9]/u,
    /[+/_=-]/u
  ].filter((expression) => expression.test(token)).length;
  const entropy = shannonEntropy(token);
  const context = source.slice(
    Math.max(0, start - 64),
    Math.min(source.length, start + token.length + 24)
  );
  const hexadecimal =
    token.length >= 32 && /^[A-Fa-f0-9]+$/u.test(token);
  return (
    (token.length >= 32 && classes >= 3 && entropy >= 4.2) ||
    (aggressive &&
      classes >= 2 &&
      entropy >= 4.5) ||
    (aggressive && hexadecimal && entropy >= 3.5) ||
    (classes >= 2 && entropy >= 3.2 && SECRET_CONTEXT.test(context))
  );
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function addSpan(
  spans: SecretSpan[],
  start: number,
  end: number,
  kind: SastSecretDetectorKind
): void {
  if (start < 0 || end <= start) return;
  spans.push({ start, end, kinds: new Set([kind]) });
}

function mergeSpans(spans: readonly SecretSpan[]): SecretSpan[] {
  const ordered = [...spans].sort(
    (left, right) =>
      left.start - right.start || left.end - right.end
  );
  const merged: SecretSpan[] = [];
  for (const span of ordered) {
    const previous = merged.at(-1);
    if (!previous || span.start > previous.end) {
      merged.push({
        start: span.start,
        end: span.end,
        kinds: new Set(span.kinds)
      });
      continue;
    }
    previous.end = Math.max(previous.end, span.end);
    for (const kind of span.kinds) previous.kinds.add(kind);
  }
  return merged;
}

function readReferenceTime(clock: () => Date): number {
  try {
    return Date.prototype.getTime.call(clock());
  } catch {
    return Number.NaN;
  }
}

function hasUnsafePlatformSecretCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return (
      (codePoint <= 0x1f &&
        codePoint !== 0x09 &&
        codePoint !== 0x0a) ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      (codePoint >= 0xd800 && codePoint <= 0xdfff)
    );
  });
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

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256')
    .update(value)
    .digest('hex')}`;
}
