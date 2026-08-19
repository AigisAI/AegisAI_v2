import { createHash } from 'node:crypto';

import {
  buildSastRuleBundleLifecycleTransition,
  buildSastRuleBundleManifest,
  buildSastRuleBundlePromotionApproval,
  buildSastRuleBundlePromotionEvidence,
  buildSastRuleBundleSupplyChainAttestation,
  type RuleBundleState,
  type SastRuleBundleLifecycleExternalAuthority,
  type SastRuleBundleLifecycleTransition,
  type SastRuleBundleManifest,
  type SastRuleBundlePromotionApproval,
  type SastRuleBundlePromotionEvidence,
  type SastRuleBundleSupplyChainAttestation
} from '@aegisai/shared';
import { Prisma, type PrismaClient } from '@prisma/client';

import { PrismaService } from '../../src/prisma/prisma.service';
import { PrismaSastRuleBundleLifecycleStore } from '../../src/rule-governance/prisma-sast-rule-bundle-lifecycle.store';
import { PrismaSastRuleBundleManifestStore } from '../../src/rule-governance/prisma-sast-rule-bundle-manifest.store';
import { PrismaSastRuleBundleRollbackStore } from '../../src/rule-governance/prisma-sast-rule-bundle-rollback.store';
import { digestSastRuleBundleCanonical } from '../../src/rule-governance/sast-rule-bundle-canonical';
import { SastRuleBundleManifestService } from '../../src/rule-governance/sast-rule-bundle-manifest.service';
import {
  SastRuleBundleSupplyChainAuthority
} from '../../src/rule-governance/sast-rule-bundle-supply-chain.authority';
import { SastRuleBundleRollbackClock } from '../../src/rule-governance/sast-rule-bundle-rollback.clock';
import { SastRuleBundleRollbackService } from '../../src/rule-governance/sast-rule-bundle-rollback.service';
import { SastRuleBundleRollbackSignatureAuthority } from '../../src/rule-governance/sast-rule-bundle-rollback-signature.authority';
import type { PersistedVerifiedSastRuleBundle } from '../../src/rule-governance/sast-rule-bundle-manifest.store';

const RUN_PROBE = process.env.RUN_SAST_ROLLBACK_POSTGRES_PROBE === '1';
const describePostgresProbe = RUN_PROBE ? describe : describe.skip;

describePostgresProbe('T050 SAST rollback PostgreSQL 16 authority probe', () => {
  jest.setTimeout(60_000);

  const fixture = rollbackFixture();
  const prisma = new PrismaService();
  let connected = false;

  beforeAll(async () => {
    assertSafeProbeDatabase(process.env.DATABASE_URL);
    await prisma.$connect();
    connected = true;
    await cleanupFixture(prisma, fixture);
  });

  afterAll(async () => {
    if (connected) {
      await cleanupFixture(prisma, fixture);
      await prisma.$disconnect();
    }
  });

  it('commits one append-only rollback and rejects forged, stale, duplicate, and mutable authority', async () => {
    const manifestStore = new PrismaSastRuleBundleManifestStore(prisma);
    const manifestService = new SastRuleBundleManifestService(
      manifestStore,
      new AcceptingSupplyChainAuthority(fixture.attestedAt)
    );
    for (const verified of [
      fixture.older,
      fixture.baseline,
      fixture.candidate
    ]) {
      const persisted = await manifestService.registerVerifiedManifest(
        verified.manifest
      );
      expect(persisted).toMatchObject({
        manifest: { manifestId: verified.manifest.manifestId },
        attestation: {
          attestationDigest: verified.attestation.attestationDigest
        },
        replayed: false
      });
    }

    const lifecycleStore = new PrismaSastRuleBundleLifecycleStore(prisma);
    for (const evidence of [
      fixture.baselineEvidence,
      fixture.candidateEvidence
    ]) {
      await lifecycleStore.registerPromotionEvidence(evidence);
    }
    for (const approval of [
      ...fixture.baselineApprovals,
      ...fixture.candidateApprovals
    ]) {
      await lifecycleStore.registerPromotionApproval(approval);
    }
    await seedQualifiedLifecycle(prisma, fixture);

    const rollbackStore = new PrismaSastRuleBundleRollbackStore(prisma);
    const clock = new MutableRollbackClock(fixture.commandedAt);
    const service = new SastRuleBundleRollbackService(
      rollbackStore,
      manifestStore,
      lifecycleStore,
      new AcceptingRollbackSignatureAuthority(),
      clock
    );
    const commandResult = await service.registerCommand({
      version: 'sast-rule-bundle-rollback-request-v1',
      candidateManifestId: fixture.candidate.manifest.manifestId,
      suspendedTransitionId: fixture.candidateSuspended.transitionId,
      suspendedTransitionDigest: fixture.candidateSuspended.transitionDigest,
      incidentRef: reference('incident'),
      actorRef: fixture.actorRef,
      actorRole: 'SECURITY_ON_CALL',
      reasonRef: fixture.reasonRef,
      auditRef: fixture.auditRef,
      signatureRef: reference('rollback-signature'),
      provenanceRef: reference('rollback-provenance'),
      commandedAt: fixture.commandedAt
    });
    expect(commandResult.command.baselineManifestId).toBe(
      fixture.baseline.manifest.manifestId
    );
    expect(commandResult.command.baselineBundleDigest).toBe(
      fixture.candidateEvidence.rollbackTargetDigest
    );

    clock.value = fixture.securityApprovedAt;
    await service.registerApproval({
      commandId: commandResult.command.commandId,
      commandDigest: commandResult.command.commandDigest,
      role: 'SECURITY_ENGINEERING',
      approverRef: 'sast-approver://t050-probe/security',
      approvalRef: reference('rollback-security-approval'),
      approvedAt: fixture.securityApprovedAt
    });
    clock.value = fixture.platformApprovedAt;
    await service.registerApproval({
      commandId: commandResult.command.commandId,
      commandDigest: commandResult.command.commandDigest,
      role: 'SECURITY_OPERATIONS',
      approverRef: 'sast-approver://t050-probe/operations',
      approvalRef: reference('rollback-operations-approval'),
      approvedAt: fixture.platformApprovedAt
    });

    const forgedTransition = rollbackTransition(
      fixture,
      `sast-rule-bundle-rollback-receipt://authority/${digest('forged-receipt')}`,
      digest('forged-receipt')
    );
    await expect(
      prisma.sastRuleBundleLifecycleTransition.create({
        data: transitionData(forgedTransition)
      })
    ).rejects.toThrow(/rollback lifecycle authority receipt is unavailable/u);

    clock.value = fixture.requestedAt;
    const authorityReceipt = await service.authorizeLifecycleTransition({
      authority: 'ROLLBACK',
      manifestId: fixture.candidate.manifest.manifestId,
      manifestDigest: fixture.candidate.manifest.manifestDigest,
      bundleId: fixture.candidate.manifest.bundleId,
      bundleDigest: fixture.candidate.manifest.bundleDigest,
      fromState: 'SUSPENDED',
      toState: 'ROLLED_BACK',
      promotionEvidenceId: fixture.candidateEvidence.evidenceId,
      promotionEvidenceDigest: fixture.candidateEvidence.evidenceDigest,
      actorRef: fixture.actorRef,
      reasonRef: fixture.reasonRef,
      auditRef: fixture.auditRef,
      requestedAt: fixture.requestedAt
    });
    const transition = rollbackTransition(
      fixture,
      authorityReceipt.receiptRef,
      authorityReceipt.receiptDigest
    );

    await setLifecycleHeadState(
      prisma,
      fixture.baseline.manifest.manifestId,
      'RETIRED'
    );
    await expect(
      lifecycleStore.appendLifecycleTransition(transition)
    ).rejects.toThrow(/rollback baseline changed before lifecycle commit/u);
    await setLifecycleHeadState(
      prisma,
      fixture.baseline.manifest.manifestId,
      'ACTIVE'
    );

    await setLifecycleHeadState(
      prisma,
      fixture.candidate.manifest.manifestId,
      'ACTIVE'
    );
    await expect(
      lifecycleStore.appendLifecycleTransition(transition)
    ).rejects.toThrow(/rollback candidate changed before lifecycle commit/u);
    await setLifecycleHeadState(
      prisma,
      fixture.candidate.manifest.manifestId,
      'SUSPENDED'
    );

    const historicalCandidateTransitions =
      await prisma.sastRuleBundleLifecycleTransition.count({
        where: { manifestId: fixture.candidate.manifest.manifestId }
      });
    const historicalBaselineTransitions =
      await prisma.sastRuleBundleLifecycleTransition.count({
        where: { manifestId: fixture.baseline.manifest.manifestId }
      });
    const concurrent = await Promise.all([
      lifecycleStore.appendLifecycleTransition(transition),
      lifecycleStore.appendLifecycleTransition(transition)
    ]);
    expect(concurrent.map((result) => result.replayed).sort()).toEqual([
      false,
      true
    ]);

    const [candidateHead, baselineHead, receipt, candidateCount, baselineCount] =
      await Promise.all([
        prisma.sastRuleBundleLifecycleHead.findUniqueOrThrow({
          where: { manifestId: fixture.candidate.manifest.manifestId }
        }),
        prisma.sastRuleBundleLifecycleHead.findUniqueOrThrow({
          where: { manifestId: fixture.baseline.manifest.manifestId }
        }),
        prisma.sastRuleBundleRollbackReceipt.findUniqueOrThrow({
          where: { id: authorityReceipt.receiptRef }
        }),
        prisma.sastRuleBundleLifecycleTransition.count({
          where: { manifestId: fixture.candidate.manifest.manifestId }
        }),
        prisma.sastRuleBundleLifecycleTransition.count({
          where: { manifestId: fixture.baseline.manifest.manifestId }
        })
      ]);
    expect(candidateHead).toMatchObject({
      lifecycleState: 'ROLLED_BACK',
      transitionId: transition.transitionId,
      sequence: fixture.candidateSuspended.sequence + 1
    });
    expect(baselineHead).toMatchObject({
      lifecycleState: 'ACTIVE',
      transitionId: fixture.baselineActive.transitionId,
      transitionDigest: fixture.baselineActive.transitionDigest
    });
    expect(candidateCount).toBe(historicalCandidateTransitions + 1);
    expect(baselineCount).toBe(historicalBaselineTransitions);
    expect(receipt).toMatchObject({
      baselineManifestId: fixture.baseline.manifest.manifestId,
      baselineMutationAuthorized: false,
      historicalMutationAuthorized: false,
      scannerSetMutationAuthorized: false,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      scmWriteAuthority: false
    });

    await expect(
      prisma.sastRuleBundleRollbackReceipt.update({
        where: { id: receipt.id },
        data: { auditRef: reference('mutated-audit') }
      })
    ).rejects.toThrow(/append-only/u);

    for (const statement of [
      'TRUNCATE "SastRuleBundleRollbackCommand" CASCADE',
      'TRUNCATE "SastRuleBundleRollbackVerification" CASCADE',
      'TRUNCATE "SastRuleBundleRollbackApproval" CASCADE',
      'TRUNCATE "SastRuleBundleRollbackReceipt" CASCADE',
      'TRUNCATE "SastRuleBundleRollbackReceiptApproval" CASCADE'
    ]) {
      await expect(prisma.$executeRawUnsafe(statement)).rejects.toThrow(
        /append-only/u
      );
    }
  });
});

class AcceptingSupplyChainAuthority extends SastRuleBundleSupplyChainAuthority {
  constructor(private readonly verifiedAt: string) {
    super();
  }

  async verify(
    manifest: Readonly<SastRuleBundleManifest>
  ): Promise<SastRuleBundleSupplyChainAttestation> {
    const attestation = buildSastRuleBundleSupplyChainAttestation({
      manifest,
      verifiedAt: this.verifiedAt,
      digestCanonical: digestSastRuleBundleCanonical
    });
    if (!attestation) throw new Error('T050 probe attestation is invalid.');
    return attestation;
  }
}

class AcceptingRollbackSignatureAuthority extends SastRuleBundleRollbackSignatureAuthority {
  async verify(command: {
    signatureRef: string;
    provenanceRef: string;
  }) {
    return {
      signerIdentity: 'sast-signer://t050-probe/rollback',
      signatureRef: command.signatureRef,
      provenanceRef: command.provenanceRef,
      signatureVerified: true as const,
      provenanceVerified: true as const,
      trustedSigner: true as const,
      signatureBytesStored: false as const,
      provenancePayloadStored: false as const
    };
  }
}

class MutableRollbackClock extends SastRuleBundleRollbackClock {
  constructor(public value: string) {
    super();
  }

  now(): Date {
    return new Date(this.value);
  }
}

interface RollbackProbeFixture {
  attestedAt: string;
  commandedAt: string;
  securityApprovedAt: string;
  platformApprovedAt: string;
  requestedAt: string;
  actorRef: string;
  reasonRef: string;
  auditRef: string;
  older: PersistedVerifiedSastRuleBundle;
  baseline: PersistedVerifiedSastRuleBundle;
  candidate: PersistedVerifiedSastRuleBundle;
  baselineEvidence: SastRuleBundlePromotionEvidence;
  baselineApprovals: SastRuleBundlePromotionApproval[];
  candidateEvidence: SastRuleBundlePromotionEvidence;
  candidateApprovals: SastRuleBundlePromotionApproval[];
  baselineTransitions: SastRuleBundleLifecycleTransition[];
  candidateTransitions: SastRuleBundleLifecycleTransition[];
  baselineActive: SastRuleBundleLifecycleTransition;
  candidateSuspended: SastRuleBundleLifecycleTransition;
  suspensionReceiptRef: string;
  suspensionReceiptDigest: `sha256:${string}`;
}

function rollbackFixture(): RollbackProbeFixture {
  const attestedAt = '2026-08-19T00:05:00.000Z';
  const older = verifiedManifest(
    manifest('1.0.0', digest('older-bundle'), digest('ancient-bundle')),
    attestedAt
  );
  const baseline = verifiedManifest(
    manifest('2.0.0', digest('baseline-bundle'), older.manifest.bundleDigest),
    attestedAt
  );
  const candidate = verifiedManifest(
    manifest(
      '3.0.0',
      digest('candidate-bundle'),
      baseline.manifest.bundleDigest
    ),
    attestedAt
  );
  const baselineEvidence = promotionEvidence(
    baseline,
    older,
    'baseline',
    '2026-08-19T00:30:00.000Z'
  );
  const baselineApprovals = promotionApprovals(
    baselineEvidence,
    'baseline',
    ['2026-08-19T00:31:00.000Z', '2026-08-19T00:32:00.000Z']
  );
  const candidateEvidence = promotionEvidence(
    candidate,
    baseline,
    'candidate',
    '2026-08-19T01:00:00.000Z'
  );
  const candidateApprovals = promotionApprovals(
    candidateEvidence,
    'candidate',
    ['2026-08-19T01:01:00.000Z', '2026-08-19T01:02:00.000Z']
  );
  const baselineTransitions = lifecycleChain(
    baselineEvidence,
    baselineApprovals,
    ['2026-08-19T00:40:00.000Z', '2026-08-19T00:45:00.000Z', '2026-08-19T00:50:00.000Z'],
    null
  );
  const suspensionReceiptDigest = digest('emergency-suspension-receipt');
  const suspensionReceiptRef =
    `sast-kill-switch-suspension://authority/${suspensionReceiptDigest}`;
  const candidateTransitions = lifecycleChain(
    candidateEvidence,
    candidateApprovals,
    [
      '2026-08-19T01:05:00.000Z',
      '2026-08-19T01:10:00.000Z',
      '2026-08-19T01:15:00.000Z',
      '2026-08-19T01:20:00.000Z'
    ],
    { receiptRef: suspensionReceiptRef, receiptDigest: suspensionReceiptDigest }
  );
  const baselineActive = requiredTransition(baselineTransitions, 2);
  const candidateSuspended = requiredTransition(candidateTransitions, 3);
  return {
    attestedAt,
    commandedAt: '2026-08-19T01:30:00.000Z',
    securityApprovedAt: '2026-08-19T01:31:00.000Z',
    platformApprovedAt: '2026-08-19T01:32:00.000Z',
    requestedAt: '2026-08-19T01:33:00.000Z',
    actorRef: 'sast-actor://t050-probe/security-on-call',
    reasonRef: reference('rollback-reason'),
    auditRef: reference('rollback-audit'),
    older,
    baseline,
    candidate,
    baselineEvidence,
    baselineApprovals,
    candidateEvidence,
    candidateApprovals,
    baselineTransitions,
    candidateTransitions,
    baselineActive,
    candidateSuspended,
    suspensionReceiptRef,
    suspensionReceiptDigest
  };
}

function manifest(
  bundleVersion: string,
  bundleDigest: `sha256:${string}`,
  rollbackTargetDigest: `sha256:${string}`
): SastRuleBundleManifest {
  const built = buildSastRuleBundleManifest(
    {
      bundleId: 'sast-rule-bundle://opengrep/t050-probe',
      bundleVersion,
      lifecycleState: 'ACTIVE',
      scanner: 'OPENGREP',
      builtAt: '2026-08-19T00:00:00.000Z',
      sourceRevision: digest(`revision-${bundleVersion}`).slice(7),
      bundleDigest,
      members: [
        {
          memberId: `rules/t050/${bundleVersion}.yml`,
          digest: digest(`member-${bundleVersion}`)
        }
      ],
      rules: [
        {
          ruleId: 't050.rollback.fixture',
          ruleRevision: bundleVersion,
          ruleSemanticId: 'aegis.t050.rollback.fixture',
          metadataDigest: digest(`metadata-${bundleVersion}`)
        }
      ],
      compatibility: {
        scannerVersions: ['1.22.0'],
        scannerImageDigests: [digest('scanner-image')],
        wrapperDigests: [digest('wrapper')],
        schemaBundleDigests: [digest('schema')],
        normalizerBundleDigests: [digest('normalizer')],
        profileIds: ['JAVA_FAST_V1']
      },
      qualityEvidence: {
        goldenCorpusResultRef: reference(`golden-${bundleVersion}`),
        regressionCorpusResultRef: reference(`regression-${bundleVersion}`),
        maliciousCorpusResultRef: reference(`malicious-${bundleVersion}`),
        performanceCorpusResultRef: reference(`performance-${bundleVersion}`)
      },
      signerIdentity: 'sast-signer://t050-probe/rules',
      signatureRef: reference(`signature-${bundleVersion}`),
      provenanceRef: reference(`provenance-${bundleVersion}`),
      compatibilityRef: reference(`compatibility-${bundleVersion}`),
      rolloutPolicyRef: reference(`rollout-${bundleVersion}`),
      killSwitchNamespace: 'sast-kill-switch://rule-bundles/t050-probe',
      killSwitchRef: reference(`kill-switch-${bundleVersion}`),
      rollbackTargetDigest
    },
    digestSastRuleBundleCanonical
  );
  if (!built) throw new Error('T050 probe manifest is invalid.');
  return built;
}

function verifiedManifest(
  manifestValue: SastRuleBundleManifest,
  verifiedAt: string
): PersistedVerifiedSastRuleBundle {
  const attestation = buildSastRuleBundleSupplyChainAttestation({
    manifest: manifestValue,
    verifiedAt,
    digestCanonical: digestSastRuleBundleCanonical
  });
  if (!attestation) throw new Error('T050 probe attestation is invalid.');
  return { manifest: manifestValue, attestation, replayed: false };
}

function promotionEvidence(
  candidate: PersistedVerifiedSastRuleBundle,
  baseline: PersistedVerifiedSastRuleBundle,
  slug: string,
  measuredAt: string
): SastRuleBundlePromotionEvidence {
  const evidence = buildSastRuleBundlePromotionEvidence(
    {
      manifestId: candidate.manifest.manifestId,
      manifestDigest: candidate.manifest.manifestDigest,
      verificationId: candidate.attestation.verificationId,
      verificationDigest: candidate.attestation.attestationDigest,
      bundleId: candidate.manifest.bundleId,
      bundleDigest: candidate.manifest.bundleDigest,
      profileId: 'JAVA_FAST_V1',
      candidateAuthorRef: `sast-actor://t050-probe/${slug}-author`,
      baselineManifestId: baseline.manifest.manifestId,
      baselineManifestDigest: baseline.manifest.manifestDigest,
      baselineBundleDigest: baseline.manifest.bundleDigest,
      rollbackTargetDigest: candidate.manifest.rollbackTargetDigest,
      environmentRef: reference(`${slug}-environment`),
      corpusReferences: {
        goldenCorpusRef: reference(`${slug}-golden-corpus`),
        priorMustDetectCorpusRef: reference(`${slug}-prior-corpus`),
        maliciousCorpusRef: reference(`${slug}-malicious-corpus`),
        parserCorpusRef: reference(`${slug}-parser-corpus`),
        fingerprintCorpusRef: reference(`${slug}-fingerprint-corpus`),
        coverageCorpusRef: reference(`${slug}-coverage-corpus`),
        performanceCorpusRef: reference(`${slug}-performance-corpus`)
      },
      measurements: {
        positiveCases: 200,
        negativeCases: 200,
        performanceRuns: 30,
        goldenPassedCases: 400,
        goldenTotalCases: 400,
        priorMustDetectPassedCases: 200,
        priorMustDetectTotalCases: 200,
        mustDetectTruePositiveCases: 190,
        mustDetectExpectedCases: 200,
        criticalHighTruePositiveCases: 180,
        criticalHighReportedCases: 200,
        maliciousPassedCases: 40,
        maliciousTotalCases: 40,
        parserRejectedCases: 40,
        parserExpectedRejectCases: 40,
        fingerprintPassedCases: 40,
        fingerprintTotalCases: 40,
        coveragePassedCases: 40,
        coverageTotalCases: 40,
        falsePositiveIncreaseBasisPoints: 200,
        scannerFailureRateBasisPoints: 200,
        p95LatencyIncreaseBasisPoints: 2_000,
        candidateP95LatencyMilliseconds: 600_000,
        crossTenantEvents: 0,
        secretLeakEvents: 0,
        sandboxEscapeEvents: 0,
        stalePublicationEvents: 0
      },
      measuredAt
    },
    digestSastRuleBundleCanonical
  );
  if (!evidence) throw new Error('T050 probe evidence is invalid.');
  return evidence;
}

function promotionApprovals(
  evidence: SastRuleBundlePromotionEvidence,
  slug: string,
  approvedAt: readonly [string, string]
): SastRuleBundlePromotionApproval[] {
  return (['SECURITY_ENGINEERING', 'SCAN_PLATFORM'] as const).map(
    (role, index) => {
      const approval = buildSastRuleBundlePromotionApproval(
        {
          evidenceId: evidence.evidenceId,
          evidenceDigest: evidence.evidenceDigest,
          manifestId: evidence.manifestId,
          manifestDigest: evidence.manifestDigest,
          bundleDigest: evidence.bundleDigest,
          candidateAuthorRef: evidence.candidateAuthorRef,
          role,
          approverRef: `sast-approver://t050-probe/${slug}/${index}`,
          approvalRef: reference(`${slug}-promotion-approval-${index}`),
          approvedAt: approvedAt[index]
        },
        digestSastRuleBundleCanonical
      );
      if (!approval) throw new Error('T050 probe approval is invalid.');
      return approval;
    }
  );
}

function lifecycleChain(
  evidence: SastRuleBundlePromotionEvidence,
  approvals: readonly SastRuleBundlePromotionApproval[],
  transitionedAt: readonly [string, string, string] | readonly [string, string, string, string],
  suspension: {
    receiptRef: string;
    receiptDigest: `sha256:${string}`;
  } | null
): SastRuleBundleLifecycleTransition[] {
  const states: Array<
    [RuleBundleState, RuleBundleState, SastRuleBundleLifecycleExternalAuthority]
  > = [
    ['DRAFT', 'VALIDATED', 'NONE'],
    ['VALIDATED', 'CANARY', 'NONE'],
    ['CANARY', 'ACTIVE', 'CANARY_OBSERVATION']
  ];
  if (suspension) {
    states.push(['ACTIVE', 'SUSPENDED', 'EMERGENCY_SUSPENSION']);
  }
  const transitions: SastRuleBundleLifecycleTransition[] = [];
  states.forEach(([fromState, toState, externalAuthority], index) => {
    const previous = transitions.at(-1) ?? null;
    const authorityDigest =
      externalAuthority === 'CANARY_OBSERVATION'
        ? digest(`${evidence.evidenceId}-canary-authority`)
        : externalAuthority === 'EMERGENCY_SUSPENSION'
          ? (suspension?.receiptDigest ?? null)
          : null;
    const authorityRef =
      externalAuthority === 'CANARY_OBSERVATION' && authorityDigest
        ? `sast-canary://authority/${authorityDigest}`
        : externalAuthority === 'EMERGENCY_SUSPENSION'
          ? (suspension?.receiptRef ?? null)
          : null;
    const transition = buildSastRuleBundleLifecycleTransition(
      {
        manifestId: evidence.manifestId,
        manifestDigest: evidence.manifestDigest,
        bundleId: evidence.bundleId,
        bundleDigest: evidence.bundleDigest,
        sequence: index + 1,
        fromState,
        toState,
        previousTransitionId: previous?.transitionId ?? null,
        previousTransitionDigest: previous?.transitionDigest ?? null,
        promotionEvidenceId: evidence.evidenceId,
        promotionEvidenceDigest: evidence.evidenceDigest,
        candidateAuthorRef: evidence.candidateAuthorRef,
        approvals: approvals.map((approval) => ({
          approvalId: approval.approvalId,
          approvalDigest: approval.approvalDigest,
          role: approval.role,
          approverRef: approval.approverRef,
          approvedAt: approval.approvedAt
        })),
        externalAuthority: externalAuthority as SastRuleBundleLifecycleExternalAuthority,
        externalAuthorityReceiptRef: authorityRef,
        externalAuthorityReceiptDigest: authorityDigest,
        actorRef: 'sast-actor://t050-probe/lifecycle-controller',
        reasonRef: reference(`lifecycle-reason-${evidence.evidenceId}-${index}`),
        auditRef: reference(`lifecycle-audit-${evidence.evidenceId}-${index}`),
        transitionedAt: transitionedAt[index]
      },
      digestSastRuleBundleCanonical
    );
    if (!transition) throw new Error('T050 probe transition is invalid.');
    transitions.push(transition);
  });
  return transitions;
}

function rollbackTransition(
  fixture: RollbackProbeFixture,
  receiptRef: string,
  receiptDigest: `sha256:${string}`
): SastRuleBundleLifecycleTransition {
  const transition = buildSastRuleBundleLifecycleTransition(
    {
      manifestId: fixture.candidate.manifest.manifestId,
      manifestDigest: fixture.candidate.manifest.manifestDigest,
      bundleId: fixture.candidate.manifest.bundleId,
      bundleDigest: fixture.candidate.manifest.bundleDigest,
      sequence: fixture.candidateSuspended.sequence + 1,
      fromState: 'SUSPENDED',
      toState: 'ROLLED_BACK',
      previousTransitionId: fixture.candidateSuspended.transitionId,
      previousTransitionDigest: fixture.candidateSuspended.transitionDigest,
      promotionEvidenceId: fixture.candidateEvidence.evidenceId,
      promotionEvidenceDigest: fixture.candidateEvidence.evidenceDigest,
      candidateAuthorRef: fixture.candidateEvidence.candidateAuthorRef,
      approvals: fixture.candidateApprovals.map((approval) => ({
        approvalId: approval.approvalId,
        approvalDigest: approval.approvalDigest,
        role: approval.role,
        approverRef: approval.approverRef,
        approvedAt: approval.approvedAt
      })),
      externalAuthority: 'ROLLBACK',
      externalAuthorityReceiptRef: receiptRef,
      externalAuthorityReceiptDigest: receiptDigest,
      actorRef: fixture.actorRef,
      reasonRef: fixture.reasonRef,
      auditRef: fixture.auditRef,
      transitionedAt: fixture.requestedAt
    },
    digestSastRuleBundleCanonical
  );
  if (!transition) throw new Error('T050 probe rollback transition is invalid.');
  return transition;
}

async function seedQualifiedLifecycle(
  prisma: PrismaService,
  fixture: RollbackProbeFixture
): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await tx.$executeRawUnsafe('SET LOCAL session_replication_role = replica');
    for (const transition of [
      ...fixture.baselineTransitions,
      ...fixture.candidateTransitions
    ]) {
      await tx.sastRuleBundleLifecycleTransition.create({
        data: transitionData(transition)
      });
    }
    for (const transition of [
      fixture.baselineActive,
      fixture.candidateSuspended
    ]) {
      await tx.sastRuleBundleLifecycleHead.create({
        data: {
          manifestId: transition.manifestId,
          manifestDigest: transition.manifestDigest,
          bundleId: transition.bundleId,
          bundleDigest: transition.bundleDigest,
          transitionId: transition.transitionId,
          transitionDigest: transition.transitionDigest,
          sequence: transition.sequence,
          lifecycleState: transition.toState,
          promotionEvidenceId: transition.promotionEvidenceId,
          promotionEvidenceDigest: transition.promotionEvidenceDigest,
          approvalSetDigest: transition.approvalSetDigest,
          transitionedAt: new Date(transition.transitionedAt)
        }
      });
    }
    const candidateActive = requiredTransition(
      fixture.candidateTransitions,
      2
    );
    await tx.sastKillSwitchEmergencySuspensionReceipt.create({
      data: {
        id: fixture.suspensionReceiptRef,
        contractVersion: 'sast-kill-switch-emergency-suspension-v1',
        receiptDigest: fixture.suspensionReceiptDigest,
        manifestId: fixture.candidate.manifest.manifestId,
        manifestDigest: fixture.candidate.manifest.manifestDigest,
        bundleId: fixture.candidate.manifest.bundleId,
        bundleDigest: fixture.candidate.manifest.bundleDigest,
        fromState: 'ACTIVE',
        toState: 'SUSPENDED',
        lifecycleSequence: candidateActive.sequence,
        lifecycleTransitionId: candidateActive.transitionId,
        lifecycleTransitionDigest: candidateActive.transitionDigest,
        promotionEvidenceId: fixture.candidateEvidence.evidenceId,
        promotionEvidenceDigest: fixture.candidateEvidence.evidenceDigest,
        triggerSelectorKey: `sast-kill-switch-selector://${digest('selector').slice(7)}`,
        triggerDecisionId: `sast-kill-switch-decision://${digest('decision').slice(7)}`,
        triggerDecisionDigest: digest('decision'),
        activeDecisionCount: 1,
        activeDecisionSetDigest: digest('active-decision-set'),
        requestedAt: new Date(fixture.candidateSuspended.transitionedAt),
        verifiedAt: new Date(fixture.candidateSuspended.transitionedAt)
      }
    });
  });
}

function transitionData(
  transition: Readonly<SastRuleBundleLifecycleTransition>
): Prisma.SastRuleBundleLifecycleTransitionUncheckedCreateInput {
  return {
    id: transition.transitionId,
    contractVersion: transition.version,
    transitionDigest: transition.transitionDigest,
    manifestId: transition.manifestId,
    manifestDigest: transition.manifestDigest,
    bundleId: transition.bundleId,
    bundleDigest: transition.bundleDigest,
    sequence: transition.sequence,
    fromState: transition.fromState,
    toState: transition.toState,
    previousTransitionId: transition.previousTransitionId,
    previousTransitionDigest: transition.previousTransitionDigest,
    promotionEvidenceId: transition.promotionEvidenceId,
    promotionEvidenceDigest: transition.promotionEvidenceDigest,
    candidateAuthorRef: transition.candidateAuthorRef,
    approvalSetDigest: transition.approvalSetDigest,
    externalAuthority: transition.externalAuthority,
    externalAuthorityReceiptRef: transition.externalAuthorityReceiptRef,
    externalAuthorityReceiptDigest:
      transition.externalAuthorityReceiptDigest,
    actorRef: transition.actorRef,
    reasonRef: transition.reasonRef,
    auditRef: transition.auditRef,
    transitionedAt: new Date(transition.transitionedAt),
    source: transition.source,
    immutable: transition.immutable,
    customerInputAccepted: transition.customerInputAccepted,
    executableRuleContentStored: transition.executableRuleContentStored,
    repositoryContentStored: transition.repositoryContentStored,
    secretValueStored: transition.secretValueStored,
    approvals: {
      create: transition.approvals.map((approval, position) => ({
        position,
        approvalId: approval.approvalId,
        approvalDigest: approval.approvalDigest,
        role: approval.role,
        approverRef: approval.approverRef,
        approvedAt: new Date(approval.approvedAt)
      }))
    }
  };
}

async function setLifecycleHeadState(
  prisma: PrismaService,
  manifestId: string,
  lifecycleState: 'ACTIVE' | 'RETIRED' | 'SUSPENDED'
): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await tx.$executeRawUnsafe('SET LOCAL session_replication_role = replica');
    await tx.sastRuleBundleLifecycleHead.update({
      where: { manifestId },
      data: { lifecycleState }
    });
  });
}

async function cleanupFixture(
  prisma: PrismaClient,
  fixture: RollbackProbeFixture
): Promise<void> {
  const manifestIds = [
    fixture.candidate.manifest.manifestId,
    fixture.baseline.manifest.manifestId,
    fixture.older.manifest.manifestId
  ];
  const evidenceIds = [
    fixture.candidateEvidence.evidenceId,
    fixture.baselineEvidence.evidenceId
  ];
  await prisma.$transaction(async (tx) => {
    const commands = await tx.sastRuleBundleRollbackCommand.findMany({
      where: { candidateManifestId: { in: manifestIds } },
      select: { id: true }
    });
    const commandIds = commands.map(({ id }) => id);
    const transitions = await tx.sastRuleBundleLifecycleTransition.findMany({
      where: { manifestId: { in: manifestIds } },
      select: { id: true }
    });
    const transitionIds = transitions.map(({ id }) => id);
    const receipts = await tx.sastRuleBundleRollbackReceipt.findMany({
      where: { candidateManifestId: { in: manifestIds } },
      select: { id: true }
    });
    const receiptIds = receipts.map(({ id }) => id);

    await tx.$executeRawUnsafe('SET LOCAL session_replication_role = replica');
    await tx.sastRuleBundleRollbackReceiptApproval.deleteMany({
      where: {
        OR: [
          { commandId: { in: commandIds } },
          { receiptId: { in: receiptIds } }
        ]
      }
    });
    await tx.sastRuleBundleRollbackReceipt.deleteMany({
      where: { candidateManifestId: { in: manifestIds } }
    });
    await tx.sastRuleBundleRollbackApproval.deleteMany({
      where: { commandId: { in: commandIds } }
    });
    await tx.sastRuleBundleRollbackVerification.deleteMany({
      where: { commandId: { in: commandIds } }
    });
    await tx.sastRuleBundleRollbackCommand.deleteMany({
      where: { candidateManifestId: { in: manifestIds } }
    });
    await tx.sastRuleBundleLifecycleTransitionApproval.deleteMany({
      where: { transitionId: { in: transitionIds } }
    });
    await tx.sastRuleBundleLifecycleHead.deleteMany({
      where: { manifestId: { in: manifestIds } }
    });
    await tx.sastRuleBundleLifecycleTransition.deleteMany({
      where: { manifestId: { in: manifestIds } }
    });
    await tx.sastKillSwitchEmergencySuspensionReceipt.deleteMany({
      where: { id: fixture.suspensionReceiptRef }
    });
    await tx.sastRuleBundlePromotionApproval.deleteMany({
      where: { evidenceId: { in: evidenceIds } }
    });
    await tx.sastRuleBundlePromotionEvidence.deleteMany({
      where: { id: { in: evidenceIds } }
    });
    await tx.sastRuleBundleSupplyChainAttestation.deleteMany({
      where: { manifestId: { in: manifestIds } }
    });
    await tx.sastRuleBundleCompatibilityEntry.deleteMany({
      where: { manifestId: { in: manifestIds } }
    });
    await tx.sastRuleBundleManifestRule.deleteMany({
      where: { manifestId: { in: manifestIds } }
    });
    await tx.sastRuleBundleManifestMember.deleteMany({
      where: { manifestId: { in: manifestIds } }
    });
    await tx.sastRuleBundleManifest.deleteMany({
      where: { id: { in: manifestIds } }
    });
  });
}

function assertSafeProbeDatabase(databaseUrl: string | undefined): void {
  if (!databaseUrl) throw new Error('T050 PostgreSQL probe requires DATABASE_URL.');
  const parsed = new URL(databaseUrl);
  const database = parsed.pathname.replace(/^\//u, '');
  if (
    !['127.0.0.1', 'localhost'].includes(parsed.hostname) ||
    !['aegisai_ci', 'aegis_t050'].includes(database)
  ) {
    throw new Error(
      'T050 PostgreSQL probe is restricted to an explicit local disposable database.'
    );
  }
}

function requiredTransition(
  transitions: readonly SastRuleBundleLifecycleTransition[],
  index: number
): SastRuleBundleLifecycleTransition {
  const transition = transitions[index];
  if (!transition) throw new Error('T050 probe transition is missing.');
  return transition;
}

function reference(seed: string): string {
  return `sast-reference://t050-probe/${seed}/${digest(seed)}`;
}

function digest(seed: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(`t050-probe:${seed}`, 'utf8').digest('hex')}`;
}
