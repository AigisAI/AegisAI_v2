import {
  buildSastAiAdvisoryHandoff,
  isSastAiAdvisoryIntentShapeValid,
  type AiAdvisoryResult,
  type AiDetectorAdvisory,
  type AiInferenceFallback,
  type AiInferenceResponse,
  type AiModelMetadata,
  type AiPlannerAdvisory,
  type SastAiAdvisoryHandoff,
  type SastAiAdvisoryIntent
} from '@aegisai/shared';
import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException
} from '@nestjs/common';
import { createHash } from 'node:crypto';

import { ConfigService } from '../config/config.service';
import { SastKillSwitchGate } from '../rule-governance/sast-kill-switch.gate';
import { SastEvidenceAccessService } from '../scan-plane/sast-evidence-access.service';
import { AiAdvisoryRuntimeClient } from './ai-advisory-runtime.client';
import { SastAiAdvisoryStore } from './sast-ai-advisory.store';

interface AiAdvisoryRuntimeProjection {
  detectorSignals: string[];
  plannerSteps: string[];
  confidence: number;
  modelVersion: string;
  detectorAdvisories?: AiDetectorAdvisory[];
  plannerAdvisories?: AiPlannerAdvisory[];
  modelMetadata?: AiModelMetadata;
  fallback?: AiInferenceFallback;
}

type AdvisoryClock = () => string;

@Injectable()
export class AiAdvisoryService {
  private readonly logger = new Logger(AiAdvisoryService.name);

  constructor(
    private readonly config: ConfigService,
    private readonly runtimeClient: AiAdvisoryRuntimeClient,
    private readonly evidenceAccess: SastEvidenceAccessService,
    private readonly store: SastAiAdvisoryStore,
    private readonly killSwitch: SastKillSwitchGate
  ) {}

  async createAdvisory(
    input: SastAiAdvisoryIntent,
    clock: AdvisoryClock = () => new Date().toISOString()
  ): Promise<AiAdvisoryResult> {
    if (!isSastAiAdvisoryIntentShapeValid(input)) {
      throw new BadRequestException(
        'AI advisory intent must contain only durable scope identifiers.'
      );
    }

    const startedAt = readClock(clock);
    if (!startedAt) throw unavailable();

    const scope = {
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      evidencePackId: input.evidencePackId
    };
    const firstAccess = await this.classify(scope, clock);
    if (firstAccess.outcome !== 'ALLOWED') throw unavailable();
    await this.assertKillSwitchClear(
      firstAccess.decision.scope.tenantId,
      firstAccess.decision.scope.repositoryBindingId,
      firstAccess.decision.scope.scanRequestId,
      startedAt
    );

    const normalizedFinding = await this.loadFinding(
      firstAccess.decision
    );
    if (!normalizedFinding) throw unavailable();

    const reboundAt = readClock(clock);
    if (
      !reboundAt ||
      Date.parse(reboundAt) < Date.parse(startedAt)
    ) {
      throw unavailable();
    }
    const finalAccess = await this.classify(scope, clock);
    if (
      finalAccess.outcome !== 'ALLOWED' ||
      !sameAccess(firstAccess, finalAccess) ||
      finalAccess.reducedEvidenceReference === null
    ) {
      throw unavailable();
    }
    const reducedEvidenceReference =
      finalAccess.reducedEvidenceReference;

    const createdAt = readClock(clock);
    if (
      !createdAt ||
      Date.parse(createdAt) < Date.parse(reboundAt) ||
      Date.parse(createdAt) >=
        Date.parse(reducedEvidenceReference.payloadExpiresAt)
    ) {
      throw unavailable();
    }
    const handoff = buildSastAiAdvisoryHandoff({
      decision: finalAccess.decision,
      reducedEvidenceReference,
      normalizedFinding,
      modelVersion: input.modelVersion,
      createdAt,
      digestCanonical: digest
    });
    if (!handoff) throw unavailable();

    const { persisted, existing } =
      await this.persistHandoffAndRead(handoff);
    if (existing) {
      await this.assertKillSwitchClear(
        handoff.tenantId,
        handoff.repositoryBindingId,
        handoff.scanRequestId,
        createdAt
      );
      return existing;
    }

    const invokedAt = readClock(clock);
    if (
      !invokedAt ||
      Date.parse(invokedAt) < Date.parse(createdAt) ||
      Date.parse(invokedAt) >= Date.parse(handoff.payloadExpiresAt)
    ) {
      throw unavailable();
    }

    await this.assertKillSwitchClear(
      handoff.tenantId,
      handoff.repositoryBindingId,
      handoff.scanRequestId,
      invokedAt
    );

    const runtimeOutput = await this.resolveRuntimeOutput(
      persisted.handoff
    );
    const completedAt = readClock(clock);
    if (
      !completedAt ||
      Date.parse(completedAt) < Date.parse(invokedAt) ||
      Date.parse(completedAt) >= Date.parse(handoff.payloadExpiresAt)
    ) {
      throw unavailable();
    }

    try {
      return await this.store.persistAdvisory({
        handoff: persisted.handoff,
        advisory: {
          id: handoff.advisoryId,
          sastHandoffId: handoff.handoffId,
          requestDigest: handoff.requestDigest,
          tenantId: handoff.tenantId,
          scanRequestId: handoff.scanRequestId,
          findingId: handoff.normalizedFinding.normalizedFindingId,
          modelVersion: runtimeOutput.modelVersion,
          advisoryOnly: true,
          redactedEvidenceOnly: true,
          detectorSignals: runtimeOutput.detectorSignals,
          plannerSteps: runtimeOutput.plannerSteps,
          confidence: runtimeOutput.confidence,
          detectorAdvisories: runtimeOutput.detectorAdvisories,
          plannerAdvisories: runtimeOutput.plannerAdvisories,
          modelMetadata: runtimeOutput.modelMetadata,
          fallback: runtimeOutput.fallback,
          createdAt: completedAt
        }
      });
    } catch (error) {
      this.logFailure('persistence', error, handoff.handoffId);
      throw unavailable();
    }
  }

  async getAdvisory(
    tenantId: string,
    advisoryId: string
  ): Promise<AiAdvisoryResult> {
    const advisory = await this.store.loadAdvisory({
      tenantId,
      advisoryId
    });
    if (!advisory) {
      throw new NotFoundException(
        'AI advisory was not found for tenant.'
      );
    }
    return advisory;
  }

  private async classify(
    scope: {
      tenantId: string;
      repositoryBindingId: string;
      evidencePackId: string;
    },
    clock: AdvisoryClock
  ) {
    try {
      return await this.evidenceAccess.classifyForAi(scope, clock);
    } catch (error) {
      this.logFailure('access classification', error);
      throw unavailable();
    }
  }

  private async assertKillSwitchClear(
    tenantId: string,
    repositoryBindingId: string,
    scanRequestId: string,
    evaluatedAt: string
  ): Promise<void> {
    try {
      const result = await this.killSwitch.evaluatePersistedScan({
        gate: 'AI_ADVISORY',
        tenantId,
        repositoryBindingId,
        scanRequestId,
        evaluatedAt
      });
      if (result.receipt.outcome !== 'CLEAR') throw unavailable();
    } catch (error) {
      this.logFailure('kill-switch authorization', error);
      throw unavailable();
    }
  }

  private async loadFinding(
    decision: Parameters<
      SastAiAdvisoryStore['loadNormalizedFinding']
    >[0]
  ) {
    try {
      return await this.store.loadNormalizedFinding(decision);
    } catch (error) {
      this.logFailure('finding load', error);
      throw unavailable();
    }
  }

  private async resolveRuntimeOutput(
    handoff: Readonly<SastAiAdvisoryHandoff>
  ): Promise<AiAdvisoryRuntimeProjection> {
    if (this.config.get('USE_INTERNAL_AI') === 'true') {
      return this.projectInferenceResponse(
        await this.runtimeClient.createAdvisory(handoff)
      );
    }

    return {
      detectorSignals: this.detectorSignalsFor(handoff),
      plannerSteps: this.plannerStepsFor(handoff),
      confidence: this.confidenceFor(handoff),
      modelVersion: handoff.modelVersion
    };
  }

  private async persistHandoffAndRead(
    handoff: Readonly<SastAiAdvisoryHandoff>
  ) {
    try {
      const persisted = await this.store.persistHandoff(handoff);
      const existing = await this.store.loadAdvisory({
        tenantId: handoff.tenantId,
        advisoryId: handoff.advisoryId
      });
      return { persisted, existing };
    } catch (error) {
      this.logFailure('handoff persistence', error, handoff.handoffId);
      throw unavailable();
    }
  }

  private logFailure(
    stage: string,
    error: unknown,
    handoffId?: string
  ): void {
    const category = safeErrorCategory(error);
    const handoff = handoffId === undefined ? '' : ` [${handoffId}]`;
    this.logger.error(
      `AI advisory ${stage} failed${handoff} (${category}).`
    );
  }

  private projectInferenceResponse(
    response: AiInferenceResponse
  ): AiAdvisoryRuntimeProjection {
    return {
      detectorSignals: Array.from(
        new Set(
          response.detectorAdvisories.flatMap(
            (advisory) => advisory.signals
          )
        )
      ),
      plannerSteps: response.plannerAdvisories.map(
        (advisory) => advisory.action
      ),
      confidence: response.detectorAdvisories.reduce(
        (highest, advisory) =>
          Math.max(highest, advisory.confidence),
        0
      ),
      modelVersion: response.modelMetadata.version,
      detectorAdvisories: response.detectorAdvisories,
      plannerAdvisories: response.plannerAdvisories,
      modelMetadata: response.modelMetadata,
      fallback: response.fallback
    };
  }

  private detectorSignalsFor(
    handoff: Readonly<SastAiAdvisoryHandoff>
  ): string[] {
    return [
      'SCANNER_CONFIRMED',
      `SEVERITY_${handoff.normalizedFinding.severity}`,
      `PROVENANCE_${handoff.normalizedFinding.scanner}`,
      'T043_REDUCED_REFERENCE_ONLY'
    ];
  }

  private plannerStepsFor(
    handoff: Readonly<SastAiAdvisoryHandoff>
  ): string[] {
    const steps = [
      'Review normalized scanner evidence before remediation.'
    ];
    if (
      handoff.normalizedFinding.severity === 'CRITICAL' ||
      handoff.normalizedFinding.severity === 'HIGH'
    ) {
      steps.push(
        'Prioritize owner review before merging affected changes.'
      );
    }
    steps.push(
      'Keep remediation, policy, and merge decisions outside the AI Plane.'
    );
    return steps;
  }

  private confidenceFor(
    handoff: Readonly<SastAiAdvisoryHandoff>
  ): number {
    if (handoff.normalizedFinding.severity === 'CRITICAL') return 0.82;
    if (handoff.normalizedFinding.severity === 'HIGH') return 0.74;
    return 0.61;
  }
}

function sameAccess(
  left: Awaited<
    ReturnType<SastEvidenceAccessService['classifyForAi']>
  > & { outcome: 'ALLOWED' },
  right: Awaited<
    ReturnType<SastEvidenceAccessService['classifyForAi']>
  > & { outcome: 'ALLOWED' }
): boolean {
  if (
    left.reducedEvidenceReference === null ||
    right.reducedEvidenceReference === null
  ) {
    return false;
  }
  return (
    left.decision.accessDecisionId ===
      right.decision.accessDecisionId &&
    left.decision.decisionDigest ===
      right.decision.decisionDigest &&
    left.reducedEvidenceReference.reducedEvidenceRef ===
      right.reducedEvidenceReference.reducedEvidenceRef &&
    left.reducedEvidenceReference.redactedProjectionDigest ===
      right.reducedEvidenceReference.redactedProjectionDigest &&
    left.reducedEvidenceReference.payloadExpiresAt ===
      right.reducedEvidenceReference.payloadExpiresAt
  );
}

function safeErrorCategory(error: unknown): string {
  if (!(error instanceof Error)) return 'UnknownError';
  return [
    'Error',
    'TypeError',
    'PrismaClientKnownRequestError',
    'PrismaClientUnknownRequestError',
    'PrismaClientInitializationError'
  ].includes(error.name)
    ? error.name
    : 'UnknownError';
}

function readClock(clock: AdvisoryClock): string | null {
  try {
    const value = clock();
    return typeof value === 'string' &&
      Number.isFinite(Date.parse(value)) &&
      new Date(value).toISOString() === value
      ? value
      : null;
  } catch {
    return null;
  }
}

function unavailable(): NotFoundException {
  return new NotFoundException('AI advisory source is unavailable.');
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
