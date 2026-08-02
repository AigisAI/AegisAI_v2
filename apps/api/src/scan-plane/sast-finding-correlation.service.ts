import { createHash } from 'node:crypto';
import { setImmediate as yieldToEventLoop } from 'node:timers/promises';

import { Injectable } from '@nestjs/common';
import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_FINDING_CORRELATION_LIMITS,
  SAST_FINDING_CORRELATION_PROVENANCE_VERSION,
  SAST_FINDING_CORRELATION_VERSION,
  SAST_SCAN_PROFILES,
  SAST_SCANNER_RESPONSIBILITIES,
  buildSastFindingCorrelationBasisPreimage,
  buildSastFindingCorrelationBatchKeyPreimage,
  buildSastFindingCorrelationSourceSetPreimage,
  canonicalizeSastFindingCorrelationEdge,
  canonicalizeSastFindingCorrelationProvenance,
  canonicalizeSastFindingCorrelationRejection,
  canonicalizeSastFindingCorrelationResult,
  canonicalizeSastFindingCorrelationSourceBinding,
  canonicalizeSastFingerprintedFinding,
  confidenceForSastFindingCorrelationKind,
  isSastFindingCorrelationEdgeShapeValid,
  isSastFindingCorrelationProvenanceShapeValid,
  isSastFindingCorrelationResultShapeValid,
  isSastFindingCorrelationScopeValid,
  isSastFindingCorrelationSourceBindingShapeValid,
  isSastFindingLineageObservationResultShapeValid,
  isSastFingerprintedFindingShapeValid,
  orderSastFindingCorrelationRejectionReasons,
  sastFindingCorrelationAuthority,
  sastFindingCorrelationSafety,
  type SastFindingCorrelationAuthorityLevel,
  type SastFindingCorrelationEdgeDecision,
  type SastFindingCorrelationEdgeDecisionCore,
  type SastFindingCorrelationKind,
  type SastFindingCorrelationOutcome,
  type SastFindingCorrelationProvenance,
  type SastFindingCorrelationProvenanceCore,
  type SastFindingCorrelationRejection,
  type SastFindingCorrelationRejectionCore,
  type SastFindingCorrelationRejectionReasonCode,
  type SastFindingCorrelationResult,
  type SastFindingCorrelationResultCore,
  type SastFindingCorrelationSourceBinding,
  type SastFindingCorrelationSourceBindingCore,
  type SastFindingLineageObservationResult,
  type SastFingerprintedFinding,
  type SastCapability
} from '@aegisai/shared';

import {
  SastFindingCorrelationAuthorityError,
  SastFindingCorrelationDurableScopeError,
  SastFindingCorrelationOccurrenceError,
  SastFindingCorrelationReplayConflictError,
  SastFindingCorrelationSourceSetIncompleteError,
  SastFindingCorrelationStore,
  type PersistSastFindingCorrelationEdge,
  type SastFindingCorrelationContext,
  type SastFindingCorrelationOccurrence
} from './sast-finding-correlation.store';

export interface CorrelateSastFindingsInput {
  /**
   * Every T037 result for the current attempt, including zero-finding
   * observation batches. Result digests are verified but are not used as
   * replay identity because T037's replay flag intentionally changes them.
   */
  observations: readonly Readonly<SastFindingLineageObservationResult>[];
}

interface PreparedOccurrence {
  occurrence: Readonly<SastFindingCorrelationOccurrence>;
  finding: Readonly<SastFingerprintedFinding>;
  scanner: 'OPENGREP' | 'TRIVY';
  authorityLevel: SastFindingCorrelationAuthorityLevel;
  sourceFindingDigest: `sha256:${string}`;
}

interface MutableEdge {
  kind: SastFindingCorrelationKind;
  source: Readonly<PreparedOccurrence>;
  target: Readonly<PreparedOccurrence>;
  basisDigests: Set<`sha256:${string}`>;
}

interface CorrelationGroup {
  basisDigest: `sha256:${string}`;
  basisComponents: string[];
  occurrences: PreparedOccurrence[];
}

const KIND_PRIORITY: Readonly<Record<SastFindingCorrelationKind, number>> =
  Object.freeze({
    EXACT_FINGERPRINT: 4,
    SAME_DEPENDENCY_CVE: 3,
    SUPPORTING_EVIDENCE: 2,
    POSSIBLE_OVERLAP: 1
  });

@Injectable()
export class SastFindingCorrelationService {
  constructor(private readonly store: SastFindingCorrelationStore) {}

  async correlate(
    input: Readonly<CorrelateSastFindingsInput>,
    clock: () => Date = () => new Date()
  ): Promise<SastFindingCorrelationOutcome> {
    if (!isObservationInputWithinLimits(input?.observations)) {
      return this.reject(['FINDING_CORRELATION_INPUT_INVALID']);
    }
    const observations = [...input.observations];
    if (
      observations.some(
        (observation) =>
          !isSastFindingLineageObservationResultShapeValid(
            observation,
            digest
          )
      )
    ) {
      return this.reject(['FINDING_CORRELATION_INPUT_INVALID']);
    }
    observations.sort((left, right) =>
      compareStrings(
        left.observationBatchId,
        right.observationBatchId
      )
    );
    if (
      observations.some(
        (observation, index) =>
          index > 0 &&
          observations[index - 1]?.observationBatchId ===
            observation.observationBatchId
      ) ||
      new Set(
        observations.map(
          (observation) => observation.lifecycleContextKey
        )
      ).size !== 1
    ) {
      return this.reject(['FINDING_CORRELATION_INPUT_INVALID']);
    }

    try {
      const context = await this.store.loadContext(
        observations.map(
          (observation) => observation.observationBatchId
        )
      );
      if (!context || !isSastFindingCorrelationScopeValid(context.scope)) {
        return this.reject([
          'FINDING_CORRELATION_DURABLE_SCOPE_INVALID'
        ]);
      }
      if (!contextAuthorityMatchesProfile(context)) {
        return this.reject([
          'FINDING_CORRELATION_AUTHORITY_INVALID'
        ]);
      }
      if (!observationSetMatchesContext(observations, context)) {
        return this.reject([
          'FINDING_CORRELATION_SOURCE_SET_INCOMPLETE'
        ]);
      }

      const sources = buildSourceBindings(context.sources);
      if (
        sources.length !== observations.length ||
        sources.some(
          (source) =>
            !isSastFindingCorrelationSourceBindingShapeValid(
              source,
              digest
            )
        )
      ) {
        return this.reject([
          'FINDING_CORRELATION_DURABLE_SCOPE_INVALID'
        ]);
      }
      const sourceSetDigest = digest(
        buildSastFindingCorrelationSourceSetPreimage(sources)
      );
      const correlationBatchId =
        `finding-correlation://${digestHex(
          buildSastFindingCorrelationBatchKeyPreimage({
            scope: context.scope,
            sourceSetDigest
          })
        )}`;

      let firstReferenceTime: number;
      let correlatedAt: string;
      if (context.existingCorrelation) {
        if (
          context.existingCorrelation.correlationBatchId !==
            correlationBatchId ||
          context.existingCorrelation.sourceSetDigest !==
            sourceSetDigest ||
          !isCanonicalIsoTimestamp(
            context.existingCorrelation.correlatedAt
          )
        ) {
          return this.reject([
            'FINDING_CORRELATION_REPLAY_CONFLICT'
          ]);
        }
        correlatedAt = context.existingCorrelation.correlatedAt;
        firstReferenceTime = Date.parse(correlatedAt);
      } else {
        firstReferenceTime = readReferenceTime(clock);
        if (!Number.isFinite(firstReferenceTime)) {
          return this.reject([
            'FINDING_CORRELATION_INPUT_INVALID'
          ]);
        }
        correlatedAt = new Date(firstReferenceTime).toISOString();
      }
      const latestObservationTime = Math.max(
        ...sources.map((source) => Date.parse(source.observedAt))
      );
      if (
        !Number.isFinite(firstReferenceTime) ||
        firstReferenceTime < latestObservationTime
      ) {
        return this.reject([
          context.existingCorrelation
            ? 'FINDING_CORRELATION_REPLAY_CONFLICT'
            : 'FINDING_CORRELATION_INPUT_INVALID'
        ]);
      }

      const prepared = await this.prepareOccurrences(context);
      const edges = this.buildEdges(
        correlationBatchId,
        correlatedAt,
        prepared
      );
      if (edges.length > SAST_FINDING_CORRELATION_LIMITS.maximumEdges) {
        return this.reject([
          'FINDING_CORRELATION_EDGE_LIMIT_EXCEEDED'
        ]);
      }
      if (!context.existingCorrelation) {
        const secondReferenceTime = readReferenceTime(clock);
        if (
          !Number.isFinite(secondReferenceTime) ||
          secondReferenceTime < firstReferenceTime
        ) {
          return this.reject([
            'FINDING_CORRELATION_INPUT_INVALID'
          ]);
        }
        correlatedAt = new Date(secondReferenceTime).toISOString();
        if (correlatedAt !== edges[0]?.decision.decidedAt && edges.length > 0) {
          for (const edge of edges) {
            edge.decision = buildEdgeDecision(
              correlationBatchId,
              correlatedAt,
              edge.decision.kind,
              edge.decision.sourceOccurrenceId,
              edge.decision.targetOccurrenceId,
              edge.decision.basisDigests,
              edge.sourceProvenance.provenanceDigest,
              edge.targetProvenance.provenanceDigest
            );
          }
        }
      }

      const persisted = await this.store.correlate({
        correlationBatchId,
        sourceSetDigest,
        correlatedAt,
        context,
        sources,
        edges
      });
      const expectedCounts = correlationCounts(edges);
      if (
        persisted.correlationBatchId !== correlationBatchId ||
        persisted.sourceSetDigest !== sourceSetDigest ||
        persisted.lifecycleContextKey !==
          context.scope.lifecycleContextKey ||
        persisted.sourceBatchCount !== sources.length ||
        persisted.occurrenceCount !== prepared.length ||
        persisted.edgeCount !== edges.length ||
        persisted.exactFingerprintCount !==
          expectedCounts.exactFingerprintCount ||
        persisted.sameDependencyCveCount !==
          expectedCounts.sameDependencyCveCount ||
        persisted.supportingEvidenceCount !==
          expectedCounts.supportingEvidenceCount ||
        persisted.possibleOverlapCount !==
          expectedCounts.possibleOverlapCount ||
        persisted.correlatedAt !== correlatedAt
      ) {
        return this.reject([
          'FINDING_CORRELATION_PERSISTENCE_FAILED'
        ]);
      }
      const core: SastFindingCorrelationResultCore = {
        version: SAST_FINDING_CORRELATION_VERSION,
        outcome: 'CORRELATED',
        ...persisted,
        authority: sastFindingCorrelationAuthority()
      };
      const result: SastFindingCorrelationResult = {
        ...core,
        resultDigest: digest(
          canonicalizeSastFindingCorrelationResult(core)
        )
      };
      if (!isSastFindingCorrelationResultShapeValid(result, digest)) {
        return this.reject([
          'FINDING_CORRELATION_PERSISTENCE_FAILED'
        ]);
      }
      return result;
    } catch (error) {
      return this.reject([mapStoreError(error)]);
    }
  }

  protected async yieldEventLoop(): Promise<void> {
    await yieldToEventLoop();
  }

  private async prepareOccurrences(
    context: Readonly<SastFindingCorrelationContext>
  ): Promise<PreparedOccurrence[]> {
    const sourceById = new Map(
      context.sources.map((source) => [
        source.observationBatchId,
        source
      ])
    );
    const occurrenceIds = new Set<string>();
    const normalizedFindingIds = new Set<string>();
    const prepared: PreparedOccurrence[] = [];
    for (
      let index = 0;
      index < context.occurrences.length;
      index += 1
    ) {
      if (
        index > 0 &&
        index %
          SAST_FINDING_CORRELATION_LIMITS.yieldOccurrenceInterval ===
          0
      ) {
        await this.yieldEventLoop();
      }
      const occurrence = context.occurrences[index];
      if (!occurrence) throw new SastFindingCorrelationOccurrenceError();
      const source = sourceById.get(occurrence.observationBatchId);
      const finding = occurrence.sourceFinding;
      if (
        !source ||
        occurrenceIds.has(occurrence.id) ||
        normalizedFindingIds.has(occurrence.normalizedFindingId) ||
        !isSastFingerprintedFindingShapeValid(finding, digest, digest) ||
        !occurrenceMatchesContext(occurrence, finding, source, context)
      ) {
        throw new SastFindingCorrelationOccurrenceError();
      }
      occurrenceIds.add(occurrence.id);
      normalizedFindingIds.add(occurrence.normalizedFindingId);

      const responsibilities =
        SAST_SCANNER_RESPONSIBILITIES[source.scanner];
      if (
        !responsibilities.mayCreateFindings ||
        !(responsibilities.authoritativeCapabilities as readonly SastCapability[])
          .includes(finding.capability)
      ) {
        throw new SastFindingCorrelationAuthorityError();
      }
      prepared.push({
        occurrence,
        finding,
        scanner: source.scanner,
        authorityLevel: context.requiredCapabilities.includes(
          finding.capability
        )
          ? 'AUTHORITATIVE'
          : 'SUPPORTING_ONLY',
        sourceFindingDigest: digest(
          canonicalizeSastFingerprintedFinding(finding)
        )
      });
    }
    prepared.sort((left, right) =>
      compareStrings(left.occurrence.id, right.occurrence.id)
    );
    return prepared;
  }

  private buildEdges(
    correlationBatchId: string,
    correlatedAt: string,
    occurrences: readonly Readonly<PreparedOccurrence>[]
  ): PersistSastFindingCorrelationEdge[] {
    const edgeByPair = new Map<string, MutableEdge>();
    const exactGroups = new Map<string, CorrelationGroup>();
    const dependencyGroups = new Map<string, CorrelationGroup>();
    const overlapGroups = new Map<string, CorrelationGroup>();

    for (const occurrence of occurrences) {
      const exactComponents = [
        occurrence.finding.capability,
        occurrence.occurrence.lineageId,
        occurrence.finding.fingerprint.stableFingerprint
      ];
      addToGroup(
        exactGroups,
        JSON.stringify(exactComponents),
        digest(
          buildSastFindingCorrelationBasisPreimage({
            kind: 'EXACT_FINGERPRINT',
            components: exactComponents
          })
        ),
        exactComponents,
        occurrence
      );

      if (
        occurrence.finding.capability ===
        'DEPENDENCY_VULNERABILITY'
      ) {
        const finding = occurrence.finding;
        for (const cve of canonicalCveIds(finding)) {
          const components = [
            finding.trivy.packageType.normalize('NFC'),
            finding.trivy.packageName.normalize('NFC'),
            finding.trivy.installedVersion.normalize('NFC'),
            cve
          ];
          addToGroup(
            dependencyGroups,
            JSON.stringify(components),
            digest(
              buildSastFindingCorrelationBasisPreimage({
                kind: 'SAME_DEPENDENCY_CVE',
                components
              })
            ),
            components,
            occurrence
          );
        }
      }

      for (const cve of canonicalCveIds(occurrence.finding)) {
        addToGroup(
          overlapGroups,
          `CVE\0${cve}`,
          digest(
            buildSastFindingCorrelationBasisPreimage({
              kind: 'POSSIBLE_OVERLAP',
              components: ['CVE', cve]
            })
          ),
          ['CVE', cve],
          occurrence
        );
      }
      if (occurrence.finding.location.kind === 'FILE') {
        for (const cwe of canonicalCweIds(occurrence.finding)) {
          const path =
            occurrence.finding.location.normalizedPath.normalize(
              'NFC'
            );
          addToGroup(
            overlapGroups,
            `CWE\0${cwe}\0${path}`,
            digest(
              buildSastFindingCorrelationBasisPreimage({
                kind: 'POSSIBLE_OVERLAP',
                components: ['CWE', cwe, path]
              })
            ),
            ['CWE', cwe, path],
            occurrence
          );
        }
      }
    }

    for (const group of exactGroups.values()) {
      connectStar(
        group,
        'EXACT_FINGERPRINT',
        edgeByPair
      );
    }
    for (const group of dependencyGroups.values()) {
      connectStar(
        group,
        'SAME_DEPENDENCY_CVE',
        edgeByPair
      );
    }
    for (const group of overlapGroups.values()) {
      connectAcrossCapabilities(group, edgeByPair);
    }

    if (
      edgeByPair.size >
      SAST_FINDING_CORRELATION_LIMITS.maximumEdges
    ) {
      throw new CorrelationEdgeLimitError();
    }
    return [...edgeByPair.values()]
      .sort((left, right) => {
        const sourceOrder = compareStrings(
          left.source.occurrence.id,
          right.source.occurrence.id
        );
        return sourceOrder !== 0
          ? sourceOrder
          : compareStrings(
              left.target.occurrence.id,
              right.target.occurrence.id
            );
      })
      .map((edge) => {
        const sourceProvenance = buildProvenance(
          edge.source,
          'SOURCE'
        );
        const targetProvenance = buildProvenance(
          edge.target,
          'TARGET'
        );
        const decision = buildEdgeDecision(
          correlationBatchId,
          correlatedAt,
          edge.kind,
          edge.source.occurrence.id,
          edge.target.occurrence.id,
          [...edge.basisDigests].sort(compareStrings),
          sourceProvenance.provenanceDigest,
          targetProvenance.provenanceDigest
        );
        if (
          !isSastFindingCorrelationProvenanceShapeValid(
            sourceProvenance,
            digest
          ) ||
          !isSastFindingCorrelationProvenanceShapeValid(
            targetProvenance,
            digest
          ) ||
          !isSastFindingCorrelationEdgeShapeValid(
            decision,
            digest
          )
        ) {
          throw new SastFindingCorrelationOccurrenceError();
        }
        return {
          decision,
          sourceProvenance,
          targetProvenance
        };
      });
  }

  private reject(
    reasons: Iterable<SastFindingCorrelationRejectionReasonCode>
  ): SastFindingCorrelationRejection {
    const core: SastFindingCorrelationRejectionCore = {
      version: SAST_FINDING_CORRELATION_VERSION,
      outcome: 'REJECTED',
      reasonCodes:
        orderSastFindingCorrelationRejectionReasons(reasons),
      observationBatchIdsStored: false,
      sourceResultDigestsStored: false,
      sourceFindingStored: false,
      correlationBasisStored: false,
      secretValueStored: false
    };
    return {
      ...core,
      rejectionDigest: digest(
        canonicalizeSastFindingCorrelationRejection(core)
      )
    };
  }
}

function buildSourceBindings(
  sources: readonly Readonly<SastFindingCorrelationSourceBindingCore>[]
): SastFindingCorrelationSourceBinding[] {
  return [...sources]
    .sort((left, right) =>
      compareStrings(
        left.observationBatchId,
        right.observationBatchId
      )
    )
    .map((source) => ({
      ...source,
      sourceBindingDigest: digest(
        canonicalizeSastFindingCorrelationSourceBinding(source)
      )
    }));
}

function observationSetMatchesContext(
  observations: readonly Readonly<SastFindingLineageObservationResult>[],
  context: Readonly<SastFindingCorrelationContext>
): boolean {
  if (
    context.sources.length !== observations.length ||
    context.occurrences.length >
      SAST_FINDING_CORRELATION_LIMITS.maximumOccurrences ||
    context.scope.lifecycleContextKey !==
      observations[0]?.lifecycleContextKey
  ) {
    return false;
  }
  const sourceById = new Map(
    context.sources.map((source) => [
      source.observationBatchId,
      source
    ])
  );
  let expectedOccurrences = 0;
  for (const observation of observations) {
    const source = sourceById.get(observation.observationBatchId);
    if (
      !source ||
      source.sourceIdentityBatchDigest !==
        observation.sourceIdentityBatchDigest ||
      source.lifecycleContextKey !==
        observation.lifecycleContextKey ||
      source.findingCount !== observation.findingCount ||
      source.occurrenceCount !== observation.occurrenceCount ||
      source.observedAt !== observation.observedAt
    ) {
      return false;
    }
    expectedOccurrences += source.occurrenceCount;
  }
  return expectedOccurrences === context.occurrences.length;
}

function contextAuthorityMatchesProfile(
  context: Readonly<SastFindingCorrelationContext>
): boolean {
  const profile = SAST_SCAN_PROFILES[context.scope.profileId];
  if (!profile) return false;
  const requiredCapabilities = profile.requiredCapabilities.filter(
    (capability): capability is SastFingerprintedFinding['capability'] =>
      capability !== 'SBOM'
  );
  return (
    context.scope.profileDigest ===
      SAST_APPROVED_PROFILE_DIGESTS[context.scope.profileId] &&
    context.scope.lane === profile.lane &&
    requiredCapabilities.length === context.requiredCapabilities.length &&
    requiredCapabilities.every(
      (capability, index) =>
        capability === context.requiredCapabilities[index]
    ) &&
    context.sources.every((source) => {
      if (source.scanner !== 'OPENGREP' && source.scanner !== 'TRIVY') {
        return false;
      }
      const active =
        profile.requiredScanners.includes(source.scanner) ||
        profile.optionalScanners.includes(source.scanner);
      const responsibilities =
        SAST_SCANNER_RESPONSIBILITIES[source.scanner]
          .authoritativeCapabilities as readonly SastCapability[];
      return (
        active &&
        source.capabilities.every((capability) =>
          responsibilities.includes(capability)
        )
      );
    })
  );
}

function occurrenceMatchesContext(
  occurrence: Readonly<SastFindingCorrelationOccurrence>,
  finding: Readonly<SastFingerprintedFinding>,
  source: Readonly<SastFindingCorrelationSourceBindingCore>,
  context: Readonly<SastFindingCorrelationContext>
): boolean {
  const scope = context.scope;
  return (
    occurrence.scannerRunId === source.scannerRunId &&
    occurrence.ordinal >= 0 &&
    occurrence.ordinal < source.occurrenceCount &&
    finding.tenantId === scope.tenantId &&
    finding.repositoryBindingId === scope.repositoryBindingId &&
    finding.scanRequestId === scope.scanRequestId &&
    finding.attemptId === scope.attemptId &&
    finding.scannerRunId === source.scannerRunId &&
    finding.provenance.scanner === source.scanner &&
    finding.commitSha === scope.commitSha &&
    finding.lane === scope.lane &&
    finding.canonicalScanKey === scope.canonicalScanKey &&
    finding.planDigest === scope.planDigest &&
    source.capabilities.includes(finding.capability)
  );
}

function addToGroup(
  groups: Map<string, CorrelationGroup>,
  key: string,
  basisDigest: `sha256:${string}`,
  basisComponents: readonly string[],
  occurrence: Readonly<PreparedOccurrence>
): void {
  const existing = groups.get(key);
  if (existing) {
    if (
      !existing.occurrences.some(
        (candidate) =>
          candidate.occurrence.id === occurrence.occurrence.id
      )
    ) {
      existing.occurrences.push({ ...occurrence });
    }
    return;
  }
  groups.set(key, {
    basisDigest,
    basisComponents: [...basisComponents],
    occurrences: [{ ...occurrence }]
  });
}

function connectStar(
  group: Readonly<CorrelationGroup>,
  kind: Extract<
    SastFindingCorrelationKind,
    'EXACT_FINGERPRINT' | 'SAME_DEPENDENCY_CVE'
  >,
  edges: Map<string, MutableEdge>
): void {
  const occurrences = [...group.occurrences].sort((left, right) =>
    compareStrings(left.occurrence.id, right.occurrence.id)
  );
  const anchor = occurrences[0];
  if (!anchor) return;
  for (let index = 1; index < occurrences.length; index += 1) {
    const candidate = occurrences[index];
    if (candidate) {
      addEdge(edges, anchor, candidate, kind, group.basisDigest);
    }
  }
}

function connectAcrossCapabilities(
  group: Readonly<CorrelationGroup>,
  edges: Map<string, MutableEdge>
): void {
  const byCapability = new Map<string, PreparedOccurrence[]>();
  for (const occurrence of group.occurrences) {
    const values = byCapability.get(occurrence.finding.capability) ?? [];
    values.push(occurrence);
    byCapability.set(occurrence.finding.capability, values);
  }
  const capabilities = [...byCapability.keys()].sort(compareStrings);
  if (capabilities.length < 2) return;
  const first = byCapability.get(capabilities[0] ?? '')?.sort(
    occurrenceOrder
  );
  const second = byCapability.get(capabilities[1] ?? '')?.sort(
    occurrenceOrder
  );
  const firstRepresentative = first?.[0];
  const secondRepresentative = second?.[0];
  if (!firstRepresentative || !secondRepresentative) return;

  for (const occurrence of first) {
    addAuthorityEdge(
      edges,
      occurrence,
      secondRepresentative,
      group.basisComponents
    );
  }
  for (const capability of capabilities.slice(1)) {
    for (const occurrence of byCapability.get(capability) ?? []) {
      if (
        capability === capabilities[1] &&
        occurrence.occurrence.id ===
          secondRepresentative.occurrence.id
      ) {
        continue;
      }
      addAuthorityEdge(
        edges,
        firstRepresentative,
        occurrence,
        group.basisComponents
      );
    }
  }
}

function addAuthorityEdge(
  edges: Map<string, MutableEdge>,
  left: Readonly<PreparedOccurrence>,
  right: Readonly<PreparedOccurrence>,
  basisComponents: readonly string[]
): void {
  const kind =
    left.authorityLevel !== right.authorityLevel
      ? 'SUPPORTING_EVIDENCE'
      : 'POSSIBLE_OVERLAP';
  addEdge(
    edges,
    left,
    right,
    kind,
    digest(
      buildSastFindingCorrelationBasisPreimage({
        kind,
        components: basisComponents
      })
    )
  );
}

function addEdge(
  edges: Map<string, MutableEdge>,
  left: Readonly<PreparedOccurrence>,
  right: Readonly<PreparedOccurrence>,
  kind: SastFindingCorrelationKind,
  basisDigest: `sha256:${string}`
): void {
  if (left.occurrence.id === right.occurrence.id) return;
  const [source, target] =
    left.occurrence.id < right.occurrence.id
      ? [left, right]
      : [right, left];
  const pairKey = `${source.occurrence.id}\0${target.occurrence.id}`;
  const existing = edges.get(pairKey);
  if (existing) {
    existing.basisDigests.add(basisDigest);
    if (KIND_PRIORITY[kind] > KIND_PRIORITY[existing.kind]) {
      existing.kind = kind;
    }
    return;
  }
  edges.set(pairKey, {
    kind,
    source,
    target,
    basisDigests: new Set([basisDigest])
  });
  if (
    edges.size > SAST_FINDING_CORRELATION_LIMITS.maximumEdges
  ) {
    throw new CorrelationEdgeLimitError();
  }
}

function buildProvenance(
  occurrence: Readonly<PreparedOccurrence>,
  side: 'SOURCE' | 'TARGET'
): SastFindingCorrelationProvenance {
  const finding = occurrence.finding;
  const core: SastFindingCorrelationProvenanceCore = {
    version: SAST_FINDING_CORRELATION_PROVENANCE_VERSION,
    side,
    occurrenceId: occurrence.occurrence.id,
    observationBatchId:
      occurrence.occurrence.observationBatchId,
    lineageId: occurrence.occurrence.lineageId,
    normalizedFindingId:
      occurrence.occurrence.normalizedFindingId,
    scannerRunId: occurrence.occurrence.scannerRunId,
    scanner: occurrence.scanner,
    capability: finding.capability,
    authorityLevel: occurrence.authorityLevel,
    severity: finding.severity,
    fingerprintVersion: finding.fingerprint.version,
    stableFingerprint: finding.fingerprint.stableFingerprint,
    fingerprintDecisionDigest:
      finding.fingerprint.decisionDigest,
    sourceFindingDigest: occurrence.sourceFindingDigest,
    scannerVersion: finding.provenance.scannerVersion,
    scannerImageDigest: finding.provenance.scannerImageDigest,
    ruleId: finding.provenance.ruleId,
    ruleRevision: finding.provenance.ruleRevision,
    ruleBundleDigest: finding.provenance.ruleBundleDigest,
    artifactDigest: finding.provenance.artifactDigest,
    ...('vulnerabilityDatabaseDigest' in finding.provenance
      ? {
          vulnerabilityDatabaseDigest:
            finding.provenance.vulnerabilityDatabaseDigest
        }
      : {})
  };
  return {
    ...core,
    provenanceDigest: digest(
      canonicalizeSastFindingCorrelationProvenance(core)
    )
  };
}

function buildEdgeDecision(
  correlationBatchId: string,
  decidedAt: string,
  kind: SastFindingCorrelationKind,
  sourceOccurrenceId: string,
  targetOccurrenceId: string,
  basisDigests: readonly `sha256:${string}`[],
  sourceProvenanceDigest: `sha256:${string}`,
  targetProvenanceDigest: `sha256:${string}`
): SastFindingCorrelationEdgeDecision {
  const core: SastFindingCorrelationEdgeDecisionCore = {
    version: SAST_FINDING_CORRELATION_VERSION,
    correlationBatchId,
    kind,
    sourceOccurrenceId,
    targetOccurrenceId,
    basisDigests: [...basisDigests],
    confidenceBasisPoints:
      confidenceForSastFindingCorrelationKind(kind),
    sourceProvenanceDigest,
    targetProvenanceDigest,
    safety: sastFindingCorrelationSafety(),
    decidedAt
  };
  return {
    ...core,
    edgeDigest: digest(canonicalizeSastFindingCorrelationEdge(core))
  };
}

function canonicalCveIds(
  finding: Readonly<SastFingerprintedFinding>
): string[] {
  const identifiers = new Set(
    finding.cveIds.map((identifier) =>
      identifier.normalize('NFC').toUpperCase()
    )
  );
  if (
    finding.capability === 'DEPENDENCY_VULNERABILITY' &&
    /^CVE-\d{4}-\d{4,}$/u.test(
      finding.trivy.vulnerabilityId.toUpperCase()
    )
  ) {
    identifiers.add(finding.trivy.vulnerabilityId.toUpperCase());
  }
  return [...identifiers]
    .filter((identifier) => /^CVE-\d{4}-\d{4,}$/u.test(identifier))
    .sort(compareStrings);
}

function canonicalCweIds(
  finding: Readonly<SastFingerprintedFinding>
): string[] {
  return [
    ...new Set(
      finding.cweIds.map((identifier) =>
        identifier.normalize('NFC').toUpperCase()
      )
    )
  ]
    .filter((identifier) => /^CWE-\d+$/u.test(identifier))
    .sort(compareStrings);
}

function correlationCounts(
  edges: readonly Readonly<PersistSastFindingCorrelationEdge>[]
) {
  return {
    exactFingerprintCount: edges.filter(
      (edge) => edge.decision.kind === 'EXACT_FINGERPRINT'
    ).length,
    sameDependencyCveCount: edges.filter(
      (edge) => edge.decision.kind === 'SAME_DEPENDENCY_CVE'
    ).length,
    supportingEvidenceCount: edges.filter(
      (edge) => edge.decision.kind === 'SUPPORTING_EVIDENCE'
    ).length,
    possibleOverlapCount: edges.filter(
      (edge) => edge.decision.kind === 'POSSIBLE_OVERLAP'
    ).length
  };
}

function isObservationInputWithinLimits(
  value: unknown
): value is readonly Readonly<SastFindingLineageObservationResult>[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <=
      SAST_FINDING_CORRELATION_LIMITS.maximumObservationBatches
  );
}

function mapStoreError(
  error: unknown
): SastFindingCorrelationRejectionReasonCode {
  if (
    error instanceof SastFindingCorrelationSourceSetIncompleteError
  ) {
    return 'FINDING_CORRELATION_SOURCE_SET_INCOMPLETE';
  }
  if (error instanceof SastFindingCorrelationDurableScopeError) {
    return 'FINDING_CORRELATION_DURABLE_SCOPE_INVALID';
  }
  if (error instanceof SastFindingCorrelationAuthorityError) {
    return 'FINDING_CORRELATION_AUTHORITY_INVALID';
  }
  if (error instanceof SastFindingCorrelationOccurrenceError) {
    return 'FINDING_CORRELATION_OCCURRENCE_INVALID';
  }
  if (error instanceof CorrelationEdgeLimitError) {
    return 'FINDING_CORRELATION_EDGE_LIMIT_EXCEEDED';
  }
  if (error instanceof SastFindingCorrelationReplayConflictError) {
    return 'FINDING_CORRELATION_REPLAY_CONFLICT';
  }
  return 'FINDING_CORRELATION_PERSISTENCE_FAILED';
}

class CorrelationEdgeLimitError extends Error {
  constructor() {
    super('The finding-correlation edge limit was exceeded.');
    this.name = 'CorrelationEdgeLimitError';
  }
}

function occurrenceOrder(
  left: Readonly<PreparedOccurrence>,
  right: Readonly<PreparedOccurrence>
): number {
  return compareStrings(left.occurrence.id, right.occurrence.id);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function readReferenceTime(clock: () => Date): number {
  try {
    const value = clock();
    return value instanceof Date ? value.getTime() : Number.NaN;
  } catch {
    return Number.NaN;
  }
}

function isCanonicalIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return (
    Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString() === value
  );
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${digestHex(value)}`;
}

function digestHex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
