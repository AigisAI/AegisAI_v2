import {
  SAST_KILL_SWITCH_CANARY_SUSPENSION_REASON_CODES,
  buildSastKillSwitchCanarySuspensionSignal,
  isSastKillSwitchCanarySuspensionRequestValid,
  type SastKillSwitchCanarySuspensionRequest,
  type SastKillSwitchCanarySuspensionSignal,
  type SastKillSwitchCanarySuspensionReasonCode,
  type SastProfileId
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import { PrismaService } from '../prisma/prisma.service';
import {
  asSastKillSwitchDigest,
  digestSastKillSwitchValue,
  runSastKillSwitchSerializable
} from './sast-kill-switch-persistence';

interface LifecycleHeadRow {
  manifestId: string;
  manifestDigest: string;
  bundleId: string;
  bundleDigest: string;
  transitionId: string;
  transitionDigest: string;
  lifecycleState: string;
}

interface CanaryHeadRow {
  rolloutId: string;
  rolloutDigest: string;
  latestDecisionId: string | null;
  latestDecisionDigest: string | null;
  latestOutcome: string | null;
}

export class SastKillSwitchCanarySuspensionSignalError extends Error {
  constructor(readonly reason: 'INPUT_INVALID' | 'STATE_STALE' | 'STORE_UNAVAILABLE') {
    super('The T048 canary suspension signal failed closed.');
    this.name = 'SastKillSwitchCanarySuspensionSignalError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

@Injectable()
export class SastKillSwitchCanarySuspensionService {
  constructor(private readonly prisma: PrismaService) {}

  async resolve(
    request: Readonly<SastKillSwitchCanarySuspensionRequest>
  ): Promise<SastKillSwitchCanarySuspensionSignal> {
    if (!isSastKillSwitchCanarySuspensionRequestValid(request)) {
      throw new SastKillSwitchCanarySuspensionSignalError('INPUT_INVALID');
    }

    let reference: { rolloutId: string; candidateManifestId: string } | null;
    try {
      reference = await this.prisma.sastRuleBundleCanaryStepDecision.findUnique({
        where: { id: request.canaryDecisionId },
        select: { rolloutId: true, candidateManifestId: true }
      });
    } catch {
      throw new SastKillSwitchCanarySuspensionSignalError('STORE_UNAVAILABLE');
    }
    if (!reference) {
      throw new SastKillSwitchCanarySuspensionSignalError('STATE_STALE');
    }

    try {
      return await runSastKillSwitchSerializable(
        this.prisma,
          async (tx) => {
            const lifecycleRows = await tx.$queryRaw<LifecycleHeadRow[]>`
              SELECT "manifestId", "manifestDigest", "bundleId", "bundleDigest",
                     "transitionId", "transitionDigest", "lifecycleState"
              FROM "SastRuleBundleLifecycleHead"
              WHERE "manifestId" = ${reference.candidateManifestId}
              FOR UPDATE
            `;
            const canaryRows = await tx.$queryRaw<CanaryHeadRow[]>`
              SELECT "rolloutId", "rolloutDigest", "latestDecisionId",
                     "latestDecisionDigest", "latestOutcome"
              FROM "SastRuleBundleCanaryRolloutHead"
              WHERE "rolloutId" = ${reference.rolloutId}
              FOR UPDATE
            `;
            const [decision, rollout, reasons] = await Promise.all([
              tx.sastRuleBundleCanaryStepDecision.findUnique({
                where: { id: request.canaryDecisionId }
              }),
              tx.sastRuleBundleCanaryRollout.findUnique({
                where: { id: reference.rolloutId }
              }),
              tx.sastRuleBundleCanaryStepDecisionReason.findMany({
                where: { decisionId: request.canaryDecisionId },
                orderBy: { position: 'asc' }
              })
            ]);
            const lifecycle = lifecycleRows[0];
            const head = canaryRows[0];
            if (
              !decision ||
              !rollout ||
              !lifecycle ||
              !head ||
              decision.decisionDigest !== request.canaryDecisionDigest ||
              decision.outcome !== 'PAUSED' ||
              decision.reasonCodeCount !== reasons.length ||
              head.latestOutcome !== 'PAUSED' ||
              head.latestDecisionId !== decision.id ||
              head.latestDecisionDigest !== decision.decisionDigest ||
              head.rolloutDigest !== decision.rolloutDigest ||
              rollout.id !== decision.rolloutId ||
              rollout.rolloutDigest !== decision.rolloutDigest ||
              rollout.candidateManifestId !== decision.candidateManifestId ||
              rollout.candidateManifestDigest !== decision.candidateManifestDigest ||
              rollout.candidateBundleDigest !== decision.candidateBundleDigest ||
              rollout.profileId !== decision.profileId ||
              rollout.profileDigest !== decision.profileDigest ||
              lifecycle.manifestId !== rollout.candidateManifestId ||
              lifecycle.manifestDigest !== rollout.candidateManifestDigest ||
              lifecycle.bundleId !== rollout.candidateBundleId ||
              lifecycle.bundleDigest !== rollout.candidateBundleDigest ||
              lifecycle.transitionId !== rollout.canaryTransitionId ||
              lifecycle.transitionDigest !== rollout.canaryTransitionDigest ||
              lifecycle.lifecycleState !== 'CANARY'
            ) {
              throw new SastKillSwitchCanarySuspensionSignalError('STATE_STALE');
            }

            const reasonCodes = reasons.map((reason, position) => {
              if (
                reason.position !== position ||
                !SAST_KILL_SWITCH_CANARY_SUSPENSION_REASON_CODES.includes(
                  reason.reasonCode as SastKillSwitchCanarySuspensionReasonCode
                )
              ) {
                throw new SastKillSwitchCanarySuspensionSignalError('STATE_STALE');
              }
              return reason.reasonCode as SastKillSwitchCanarySuspensionReasonCode;
            });
            const signal = buildSastKillSwitchCanarySuspensionSignal(
              {
                canaryDecisionId: decision.id,
                canaryDecisionDigest: asDigest(decision.decisionDigest),
                rolloutId: rollout.id,
                rolloutDigest: asDigest(rollout.rolloutDigest),
                candidateManifestId: rollout.candidateManifestId,
                candidateManifestDigest: asDigest(
                  rollout.candidateManifestDigest
                ),
                candidateBundleId: rollout.candidateBundleId,
                candidateBundleDigest: asDigest(rollout.candidateBundleDigest),
                profileId: rollout.profileId as SastProfileId,
                profileDigest: asDigest(rollout.profileDigest),
                lifecycleTransitionId: lifecycle.transitionId,
                lifecycleTransitionDigest: asDigest(
                  lifecycle.transitionDigest
                ),
                lifecycleState: 'CANARY',
                reasonCodes,
                observedAt: decision.evaluatedAt.toISOString()
              },
              digest
            );
            if (!signal) {
              throw new SastKillSwitchCanarySuspensionSignalError('STATE_STALE');
            }
            return signal;
          }
      );
    } catch (error) {
      if (error instanceof SastKillSwitchCanarySuspensionSignalError) {
        throw error;
      }
      throw new SastKillSwitchCanarySuspensionSignalError('STORE_UNAVAILABLE');
    }
  }
}

function asDigest(value: string): `sha256:${string}` {
  return asSastKillSwitchDigest(
    value,
    () => new SastKillSwitchCanarySuspensionSignalError('STATE_STALE')
  );
}

function digest(value: string): `sha256:${string}` {
  return digestSastKillSwitchValue(value);
}
