import { createHash } from 'node:crypto';
import {
  verifiedRuleBundleLifecycle,
  verifiedTenantRulePolicy
} from '../support/sast-scan-plan-fixtures';

import { ConflictException } from '@nestjs/common';
import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_FORBIDDEN_CAPABILITIES,
  SAST_SCAN_PROFILES,
  buildSastCanonicalScanKeyPreimage,
  isSastScanPlanValid,
  evaluateSastQueueAdmission,
  orderSastQueueCandidatesFairly,
  type SastQueuePolicySet,
  type SastQueueUsageSnapshot,
  type SastScanPlanningInput,
  type SastScanPlan,
  type PromotionVerifiedScannerSetDescriptor,
  type ScannerSetDescriptor,
  type VerifiedScannerSetDescriptor,
  type TrustedSastRepositoryMetadata
} from '@aegisai/shared';

import { ControlPlaneService } from '../../src/control-plane/control-plane.service';
import { SastPolicyEvaluationClock } from '../../src/control-plane/sast-policy-evaluation-clock.service';
import type { SastQueueReservationInput } from '../../src/control-plane/sast-queue-admission.store';
import { SastQueueAdmissionService } from '../../src/control-plane/sast-queue-admission.service';
import { SastScanPlannerService } from '../../src/control-plane/sast-scan-planner.service';
import {
  SastRuleBundleCompatibilityGate,
  SastRuleBundleCompatibilityGateError
} from '../../src/rule-governance/sast-rule-bundle-compatibility.gate';
import {
  SastRuleBundleLifecycleGate,
  SastRuleBundleLifecycleGateError
} from '../../src/rule-governance/sast-rule-bundle-lifecycle.gate';
import {
  SastTenantRulePolicyGate,
  SastTenantRulePolicyGateError,
  type SastTenantRulePolicyGateInput
} from '../../src/rule-governance/sast-tenant-rule-policy.gate';
import { InMemorySastQueueAdmissionStore } from '../support/in-memory-sast-queue-admission.store';
import { InMemoryControlPlaneScanRequestStore } from '../support/in-memory-control-plane-scan-request.store';

const digest = (character: string): `sha256:${string}` =>
  `sha256:${character.repeat(64)}`;

const signedArtifact = (character: string) => ({
  digest: digest(character),
  signatureRef: `signature://${character}`,
  provenanceRef: `provenance://${character}`
});

const ruleBundle = (scanner: 'OPENGREP' | 'TRIVY', character: string) => ({
  bundleId: `${scanner.toLowerCase()}-rules`,
  version: '1.0.0',
  state: 'ACTIVE' as const,
  digest: digest(character),
  manifestId: `sast-rule-bundle-manifest://${character.repeat(64)}`,
  manifestDigest: digest(character),
  verificationId: `sast-rule-bundle-verification://${character.repeat(64)}`,
  verificationDigest: digest(character),
  signatureRef: `signature://rules/${scanner}`,
  provenanceRef: `provenance://rules/${scanner}`,
  compatibilityRef: `compatibility://rules/${scanner}`,
  rolloutPolicyRef: `rollout://rules/${scanner}`,
  killSwitchRef: `kill-switch://rules/${scanner}`,
  rollbackTargetDigest: digest(character === 'f' ? 'e' : 'f'),
  scanner,
  source: 'PLATFORM_MANAGED' as const,
  immutable: true as const,
  customerExecutableConfigAllowed: false as const,
  rules: [
    {
      ruleId: `${scanner.toLowerCase()}.fixture`,
      ruleRevision: '1.0.0',
      ruleSemanticId: `${scanner.toLowerCase()}.fixture`,
      metadataDigest: digest(character)
    }
  ]
});

const scannerRuntime = (
  scanner: 'OPENGREP' | 'TRIVY' | 'SYFT',
  character: string,
  wrapperCharacter: string
) => ({
  ...signedArtifact(character),
  scanner,
  version: '1.0.0',
  sbomRef: `sbom://${scanner}`,
  wrapper: signedArtifact(wrapperCharacter)
});

const buildScannerSet = (): ScannerSetDescriptor => ({
  scannerSetVersion: 'scanner-set-1',
  scannerSetDigest: digest('1'),
  signatureRef: 'signature://scanner-set-1',
  provenanceRef: 'provenance://scanner-set-1',
  scanners: {
    OPENGREP: scannerRuntime('OPENGREP', 'a', 'd'),
    TRIVY: scannerRuntime('TRIVY', 'b', 'e'),
    SYFT: scannerRuntime('SYFT', 'c', 'f')
  },
  ruleBundles: [ruleBundle('OPENGREP', '7'), ruleBundle('TRIVY', '8')],
  vulnerabilityDatabase: {
    ...signedArtifact('9'),
    databaseVersion: '2026-07-22',
    publishedAt: '2026-07-22T00:00:00Z'
  },
  schemaBundle: signedArtifact('0'),
  normalizerBundle: signedArtifact('6'),
  sbomSchema: 'CYCLONEDX_JSON',
  rollbackRef: 'rollback://scanner-set-0'
});

const verifiedRuleBundle = (
  scanner: 'OPENGREP' | 'TRIVY',
  character: string
) => ({
  ...ruleBundle(scanner, character),
  compatibilityReceiptId: `sast-rule-bundle-compatibility://${character.repeat(64)}`,
  compatibilityReceiptDigest: digest(character),
  lifecycle: verifiedRuleBundleLifecycle(`${scanner.toLowerCase()}-${character}`)
});

const buildVerifiedScannerSet = (
  scannerSet: ScannerSetDescriptor = buildScannerSet()
): PromotionVerifiedScannerSetDescriptor => ({
  ...scannerSet,
  ruleBundles: scannerSet.ruleBundles.map((bundle) => ({
    ...bundle,
    compatibilityReceiptId: `sast-rule-bundle-compatibility://${bundle.digest.slice('sha256:'.length)}`,
    compatibilityReceiptDigest: bundle.manifestDigest,
    lifecycle: verifiedRuleBundleLifecycle(bundle.scanner.toLowerCase())
  }))
});

class AcceptingRuleBundleCompatibilityGate extends SastRuleBundleCompatibilityGate {
  async verifyScannerSet(input: {
    scannerSet: Readonly<ScannerSetDescriptor>;
  }): Promise<VerifiedScannerSetDescriptor> {
    return buildVerifiedScannerSet(structuredClone(input.scannerSet));
  }
}

class AcceptingRuleBundleLifecycleGate extends SastRuleBundleLifecycleGate {
  async verifyScannerSet(input: {
    scannerSet: Readonly<VerifiedScannerSetDescriptor>;
  }): Promise<PromotionVerifiedScannerSetDescriptor> {
    return {
      ...structuredClone(input.scannerSet),
      ruleBundles: input.scannerSet.ruleBundles.map((bundle) => ({
        ...structuredClone(bundle),
        lifecycle: verifiedRuleBundleLifecycle(bundle.scanner.toLowerCase())
      }))
    };
  }
}

class AcceptingTenantRulePolicyGate extends SastTenantRulePolicyGate {
  async resolve(input: { policyVersion: string }) {
    return verifiedTenantRulePolicy(input.policyVersion);
  }
}

class CapturingTenantRulePolicyGate extends SastTenantRulePolicyGate {
  lastInput: SastTenantRulePolicyGateInput | undefined;

  async resolve(input: SastTenantRulePolicyGateInput) {
    this.lastInput = structuredClone(input);
    return verifiedTenantRulePolicy(input.policyVersion);
  }
}

const fixedPolicyEvaluationClock = (
  value = '2026-07-22T01:00:00.000Z'
): SastPolicyEvaluationClock => ({
  now: () => new Date(value)
});

const queuePolicy: SastQueuePolicySet = {
  policyVersion: 'queue-policy-1',
  digest: digest('e'),
  signatureRef: 'signature://queue-policy-1',
  provenanceRef: 'provenance://queue-policy-1',
  fairnessStrategy: 'TENANT_ROUND_ROBIN',
  lanes: {
    FAST: {
      lane: 'FAST',
      queueName: 'scan.fast.v1',
      maxActivePerTenant: 2,
      maxQueuedPerTenant: 10,
      maxDailyAdmissionsPerTenant: 100,
      maxActivePerRepository: 1,
      minimumRepositoryIntervalSeconds: 60,
      maxQueuedInLane: 1000,
      capacityRetrySeconds: 30
    },
    DEEP: {
      lane: 'DEEP',
      queueName: 'scan.deep.v1',
      maxActivePerTenant: 1,
      maxQueuedPerTenant: 2,
      maxDailyAdmissionsPerTenant: 10,
      maxActivePerRepository: 1,
      minimumRepositoryIntervalSeconds: 3600,
      maxQueuedInLane: 100,
      capacityRetrySeconds: 300
    }
  }
};

const buildQueueUsage = (
  repositoryBindingId: string,
  lane: 'FAST' | 'DEEP'
): SastQueueUsageSnapshot => ({
  snapshotVersion: 0,
  tenantId: 'tenant-1',
  repositoryBindingId,
  lane,
  dailyWindowStartedAt: '2026-07-22T00:00:00Z',
  activeForTenant: 0,
  queuedForTenant: 0,
  admittedTodayForTenant: 0,
  activeForRepository: 0,
  queuedInLane: 0
});

const buildMetadata = (
  repositoryBindingId: string,
  languages: string[] = ['JAVA']
): TrustedSastRepositoryMetadata => ({
  repositoryBindingId,
  fixedCommitSha: 'a'.repeat(40),
  inventoryDigest: digest('2'),
  attestationRef: 'attestation://inventory-1',
  collectedAt: '2026-07-22T00:00:00Z',
  sourceLanguages: languages.map((language) => ({
    language,
    sourceFileCount: 10,
    sourceBytes: 100_000
  })),
  manifestNames: ['pom.xml'],
  repositoryBytes: 1_000_000,
  selectedBytes: 500_000,
  fileCount: 100,
  maxSingleFileBytes: 100_000,
  maxPathDepth: 8
});

const buildReservationPlan = (input: {
  scanRequestId: string;
  canonicalScanKey: `sha256:${string}`;
  tenantId: string;
  repositoryBindingId: string;
  createdAt: string;
}): SastScanPlan => ({
  tenantId: input.tenantId,
  scanRequestId: input.scanRequestId,
  canonicalScanKey: input.canonicalScanKey,
  profile: SAST_SCAN_PROFILES.JAVA_FAST_V1,
  profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
  policyVersion: 'policy-1',
  tenantRulePolicy: verifiedTenantRulePolicy('policy-1'),
  repositoryState: {
    repositoryBindingId: input.repositoryBindingId,
    fixedCommitSha: 'a'.repeat(40),
    targetRef: 'refs/heads/main',
    inventoryDigest: digest('2'),
    attestationRef: 'attestation://inventory-1',
    shallowFetchPreferred: true,
    submodulesEnabled: false,
    lfsObjectsFetched: false
  },
  scannerSet: buildVerifiedScannerSet(),
  isolationClass: 'HARDENED',
  resultIngressRef: `result-ingress://${input.tenantId}/${input.scanRequestId}`,
  evidenceOutputRef: `evidence-output://${input.tenantId}/${input.scanRequestId}`,
  auditSinkRef: `audit-sink://${input.tenantId}/${input.scanRequestId}`,
  forbiddenCapabilities: [...SAST_FORBIDDEN_CAPABILITIES],
  createdAt: new Date(input.createdAt).toISOString()
});

const buildDispatchReservationInput = (input: {
  scanRequestId: string;
  digestCharacter: string;
  requestedAt: string;
  dailyWindowStartedAt: string;
  snapshotVersion?: number;
  activeForTenant?: number;
  queuedForTenant?: number;
  admittedTodayForTenant?: number;
  activeForRepository?: number;
  queuedInLane?: number;
  lastRepositoryAdmissionAt?: string;
}): SastQueueReservationInput => {
  const tenantId = 'tenant-dispatch';
  const repositoryBindingId = 'repository-dispatch';
  const canonicalScanKey = digest(input.digestCharacter);

  return {
    scanRequestId: input.scanRequestId,
    canonicalScanKey,
    lane: 'FAST',
    tenantId,
    repositoryBindingId,
    requestedAt: input.requestedAt,
    policySet: queuePolicy,
    plan: buildReservationPlan({
      scanRequestId: input.scanRequestId,
      canonicalScanKey,
      tenantId,
      repositoryBindingId,
      createdAt: input.requestedAt
    }),
    planningContext: {
      profileId: 'JAVA_FAST_V1',
      coverageClaim: 'LANGUAGE_SAST_COMPLETE',
      reasonCodes: []
    },
    usage: {
      snapshotVersion: input.snapshotVersion ?? 0,
      tenantId,
      repositoryBindingId,
      lane: 'FAST',
      dailyWindowStartedAt: input.dailyWindowStartedAt,
      activeForTenant: input.activeForTenant ?? 0,
      queuedForTenant: input.queuedForTenant ?? 0,
      admittedTodayForTenant: input.admittedTodayForTenant ?? 0,
      activeForRepository: input.activeForRepository ?? 0,
      queuedInLane: input.queuedInLane ?? 0,
      lastRepositoryAdmissionAt: input.lastRepositoryAdmissionAt
    }
  };
};

async function createHarness(
  lane: 'FAST' | 'DEEP' = 'FAST',
  ruleBundleCompatibilityGate: SastRuleBundleCompatibilityGate =
    new AcceptingRuleBundleCompatibilityGate(),
  tenantRulePolicyGate: SastTenantRulePolicyGate =
    new AcceptingTenantRulePolicyGate(),
  policyEvaluationClock: SastPolicyEvaluationClock =
    fixedPolicyEvaluationClock(),
  ruleBundleLifecycleGate: SastRuleBundleLifecycleGate =
    new AcceptingRuleBundleLifecycleGate()
) {
  const scanRequestStore = new InMemoryControlPlaneScanRequestStore();
  const queueStore = new InMemorySastQueueAdmissionStore();
  const controlPlane = new ControlPlaneService(
    null as never,
    null as never,
    null as never,
    scanRequestStore
  );

  const queueAdmission = new SastQueueAdmissionService(
    queueStore
  );
  await controlPlane.installIntegration(
    {
      tenantId: 'tenant-1',
      externalInstallationId: 'installation-1',
      repoReadPrincipalId: 'repo-read-1',
      repositories: [
        {
          providerRepoId: 'repository-remote-1',
          fullName: 'acme/orders',
          defaultBranch: 'main',
          isPrivate: true
        }
      ]
    },
    { provider: 'GITHUB', integrationType: 'GITHUB_APP' }
  );
  const repositoryBindingId = (await controlPlane.listRepositoryBindings('tenant-1'))[0].id;
  const scanRequest = await controlPlane.createScanRequest({
    tenantId: 'tenant-1',
    repositoryBindingId,
    lane,
    targetRef: lane === 'FAST' ? 'refs/pull/7/head' : 'refs/heads/main',
    commitSha: 'a'.repeat(40),
    policyVersion: 'policy-1',
    scannerSetVersion: 'scanner-set-1'
  });

  return {
    controlPlane,
    scanRequestStore,
    queueStore,
    queueAdmission,
    ruleBundleCompatibilityGate,
    tenantRulePolicyGate,
    ruleBundleLifecycleGate,
    policyEvaluationClock,
    planner: new SastScanPlannerService(
      controlPlane,
      queueAdmission,
      ruleBundleCompatibilityGate,
      ruleBundleLifecycleGate,
      tenantRulePolicyGate,
      policyEvaluationClock
    ),
    repositoryBindingId,
    scanRequest
  };
}

function buildPlanningInput(
  repositoryBindingId: string,
  scanRequestId: string,
  overrides: Partial<SastScanPlanningInput> = {}
): SastScanPlanningInput {
  return {
    tenantId: 'tenant-1',
    scanRequestId,
    repositoryMetadata: buildMetadata(repositoryBindingId),
    profilePolicy: {
      policyVersion: 'policy-1',
      allowedProfileIds: ['JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1'],
      requireLanguageSpecificSast: false
    },
    scannerSet: buildScannerSet(),
    queuePolicySet: queuePolicy,
    queueUsage: buildQueueUsage(repositoryBindingId, 'FAST'),
    requestedAt: '2026-07-22T01:00:00Z',
    ...overrides
  };
}

describe('SastScanPlannerService', () => {
  it.each([
    ['MANIFEST_UNVERIFIED', 'RULE_BUNDLE_MANIFEST_UNVERIFIED'],
    ['MANIFEST_MISMATCH', 'RULE_BUNDLE_MANIFEST_MISMATCH'],
    [
      'COMPATIBILITY_UNSUPPORTED',
      'RULE_BUNDLE_COMPATIBILITY_UNSUPPORTED'
    ],
    [
      'VERIFICATION_UNAVAILABLE',
      'RULE_BUNDLE_VERIFICATION_UNAVAILABLE'
    ]
  ] as const)(
    'fails closed before queue reservation for %s',
    async (gateReason, planningReason) => {
      const gate = new (class extends SastRuleBundleCompatibilityGate {
        async verifyScannerSet(): Promise<VerifiedScannerSetDescriptor> {
          throw new SastRuleBundleCompatibilityGateError(gateReason);
        }
      })();
      const harness = await createHarness('FAST', gate);
      const reserve = jest.spyOn(
        harness.queueAdmission,
        'reserveWithContext'
      );

      const result = await harness.planner.plan(
        buildPlanningInput(
          harness.repositoryBindingId,
          harness.scanRequest.id
        )
      );

      expect(result).toEqual({
        planning: expect.objectContaining({
          state: 'REJECTED',
          reasonCodes: [planningReason]
        })
      });
      expect(reserve).not.toHaveBeenCalled();
    }
  );

  it.each([
    [
      'PROMOTION_EVIDENCE_UNVERIFIED',
      'RULE_BUNDLE_PROMOTION_EVIDENCE_UNVERIFIED'
    ],
    [
      'PROMOTION_APPROVAL_INVALID',
      'RULE_BUNDLE_PROMOTION_APPROVAL_INVALID'
    ],
    [
      'LIFECYCLE_STATE_NOT_SELECTABLE',
      'RULE_BUNDLE_LIFECYCLE_NOT_SELECTABLE'
    ],
    ['LIFECYCLE_STATE_STALE', 'RULE_BUNDLE_LIFECYCLE_STALE'],
    [
      'LIFECYCLE_AUTHORITY_UNAVAILABLE',
      'RULE_BUNDLE_LIFECYCLE_AUTHORITY_UNAVAILABLE'
    ],
    [
      'LIFECYCLE_STORE_UNAVAILABLE',
      'RULE_BUNDLE_LIFECYCLE_STORE_UNAVAILABLE'
    ]
  ] as const)(
    'fails closed before tenant policy and queue reservation for lifecycle %s',
    async (gateReason, planningReason) => {
      const lifecycleGate = new (class extends SastRuleBundleLifecycleGate {
        async verifyScannerSet(): Promise<never> {
          throw new SastRuleBundleLifecycleGateError(gateReason);
        }
      })();
      const tenantGate = new AcceptingTenantRulePolicyGate();
      const tenantResolve = jest.spyOn(tenantGate, 'resolve');
      const harness = await createHarness(
        'FAST',
        new AcceptingRuleBundleCompatibilityGate(),
        tenantGate,
        fixedPolicyEvaluationClock(),
        lifecycleGate
      );
      const reserve = jest.spyOn(
        harness.queueAdmission,
        'reserveWithContext'
      );

      const result = await harness.planner.plan(
        buildPlanningInput(
          harness.repositoryBindingId,
          harness.scanRequest.id
        )
      );

      expect(result.planning).toMatchObject({
        state: 'REJECTED',
        reasonCodes: [planningReason]
      });
      expect(tenantResolve).not.toHaveBeenCalled();
      expect(reserve).not.toHaveBeenCalled();
    }
  );

  it.each([
    ['RULE_METADATA_UNVERIFIED', 'RULE_METADATA_UNVERIFIED'],
    ['RULE_METADATA_MISMATCH', 'RULE_METADATA_MISMATCH'],
    ['TENANT_POLICY_INVALID', 'TENANT_RULE_POLICY_INVALID'],
    ['POLICY_STORE_UNAVAILABLE', 'TENANT_RULE_POLICY_UNAVAILABLE']
  ] as const)(
    'fails closed before queue reservation for tenant policy %s',
    async (gateReason, planningReason) => {
      const gate = new (class extends SastTenantRulePolicyGate {
        async resolve(): Promise<never> {
          throw new SastTenantRulePolicyGateError(gateReason);
        }
      })();
      const harness = await createHarness(
        'FAST',
        new AcceptingRuleBundleCompatibilityGate(),
        gate
      );
      const reserve = jest.spyOn(
        harness.queueAdmission,
        'reserveWithContext'
      );

      const result = await harness.planner.plan(
        buildPlanningInput(
          harness.repositoryBindingId,
          harness.scanRequest.id
        )
      );

      expect(result).toEqual({
        planning: expect.objectContaining({
          state: 'REJECTED',
          reasonCodes: [planningReason]
        })
      });
      expect(reserve).not.toHaveBeenCalled();
    }
  );

  it.each(['2026-07-22T01:00:00Z', '2099-12-31T23:59:59Z'])(
    'uses the trusted service clock for policy windows instead of requestedAt %s',
    async (requestedAt) => {
      const gate = new CapturingTenantRulePolicyGate();
      const clock = fixedPolicyEvaluationClock('2026-08-14T06:20:30.123Z');
      const harness = await createHarness(
        'FAST',
        new AcceptingRuleBundleCompatibilityGate(),
        gate,
        clock
      );

      await harness.planner.plan(
        buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id, {
          requestedAt
        })
      );

      expect(gate.lastInput?.evaluatedAt).toBe('2026-08-14T06:20:30.123Z');
      expect(gate.lastInput?.evaluatedAt).not.toBe(
        new Date(requestedAt).toISOString()
      );
      expect(gate.lastInput?.scannerSet.ruleBundles).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            lifecycle: expect.objectContaining({ lifecycleState: 'ACTIVE' })
          })
        ])
      );
    }
  );

  it.each([
    ['throwing', { now: () => { throw new Error('clock unavailable'); } }],
    ['invalid', fixedPolicyEvaluationClock('invalid')]
  ] as const)('fails closed before queue reservation for a %s policy clock', async (_label, clock) => {
    const gate = new CapturingTenantRulePolicyGate();
    const harness = await createHarness(
      'FAST',
      new AcceptingRuleBundleCompatibilityGate(),
      gate,
      clock
    );
    const reserve = jest.spyOn(harness.queueAdmission, 'reserveWithContext');

    const result = await harness.planner.plan(
      buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id)
    );

    expect(result.planning).toMatchObject({
      state: 'REJECTED',
      reasonCodes: ['TENANT_RULE_POLICY_UNAVAILABLE']
    });
    expect(gate.lastInput).toBeUndefined();
    expect(reserve).not.toHaveBeenCalled();
  });

  it('selects the Java Fast profile and records an immutable admitted plan', async () => {
    const harness = await createHarness('FAST');
    const input = buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id);

    const first = await harness.planner.plan(input);
    const second = await harness.planner.plan(input);
    const laterRetry = await harness.planner.plan({
      ...input,
      requestedAt: '2026-07-22T01:05:00Z'
    });

    expect(first).toEqual(second);
    expect(first).toEqual(laterRetry);
    expect(first.planning).toMatchObject({
      state: 'ADMITTED',
      profileId: 'JAVA_FAST_V1',
      coverageClaim: 'LANGUAGE_SAST_COMPLETE',
      queueName: 'scan.fast.v1',
      queuePolicyVersion: 'queue-policy-1',
      queuePolicyDigest: digest('e'),
      reasonCodes: []
    });
    expect(first.planning.canonicalScanKey).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(first.plan).toBeDefined();
    expect(isSastScanPlanValid(first.plan!)).toBe(true);
    expect(Object.isFrozen(first.plan)).toBe(true);
    expect(Object.isFrozen(first.plan?.profile)).toBe(true);
    expect(Object.isFrozen(first.plan?.scannerSet)).toBe(true);
    expect(Object.isFrozen(first.plan?.scannerSet.ruleBundles)).toBe(true);
    expect(Object.isFrozen(first.plan?.tenantRulePolicy)).toBe(true);
    expect(first.plan).toMatchObject({
      tenantId: 'tenant-1',
      scanRequestId: harness.scanRequest.id,
      isolationClass: 'HARDENED',
      tenantRulePolicy: verifiedTenantRulePolicy('policy-1'),
      repositoryState: {
        repositoryBindingId: harness.repositoryBindingId,
        fixedCommitSha: 'a'.repeat(40),
        inventoryDigest: digest('2'),
        attestationRef: 'attestation://inventory-1',
        shallowFetchPreferred: true,
        submodulesEnabled: false,
        lfsObjectsFetched: false
      },
      createdAt: '2026-07-22T01:00:00.000Z'
    });
    expect(first.plan?.scannerSet).not.toBe(input.scannerSet);
    const plannedScannerDigest = first.plan?.scannerSet.scanners.OPENGREP.digest;
    input.scannerSet.scanners.OPENGREP.digest = digest('4');
    expect(first.plan?.scannerSet.scanners.OPENGREP.digest).toBe(plannedScannerDigest);

    await expect(
      harness.planner.plan({
        ...input,
        repositoryMetadata: { ...input.repositoryMetadata, inventoryDigest: digest('3') }
      })
    ).rejects.toThrow('immutable');

    expect(
      await harness.controlPlane.getScanRequest('tenant-1', harness.scanRequest.id)
    ).toMatchObject({
      status: 'QUEUED',
      sastPlanning: first.planning
    });
  });

  it('reloads the durable scan request and exact admitted plan after service restart', async () => {
    const harness = await createHarness('FAST');
    const input = buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id);
    const first = await harness.planner.plan(input);

    const restartedControlPlane = new ControlPlaneService(
      null as never,
      null as never,
      null as never,
      harness.scanRequestStore
    );
    const restartedQueue = new SastQueueAdmissionService(harness.queueStore);
    const restartedPlanner = new SastScanPlannerService(
      restartedControlPlane,
      restartedQueue,
      harness.ruleBundleCompatibilityGate,
      harness.ruleBundleLifecycleGate,
      harness.tenantRulePolicyGate,
      harness.policyEvaluationClock
    );
    await expect(restartedControlPlane.listIntegrations('tenant-1')).resolves.toHaveLength(1);
    await expect(
      restartedControlPlane.listRepositoryBindings('tenant-1')
    ).resolves.toEqual([
      expect.objectContaining({ id: harness.repositoryBindingId })
    ]);
    const postRestartRequest = await restartedControlPlane.createScanRequest({
      tenantId: 'tenant-1',
      repositoryBindingId: harness.repositoryBindingId,
      lane: 'FAST',
      targetRef: 'refs/pull/8/head',
      commitSha: 'b'.repeat(40),
      policyVersion: 'policy-1',
      scannerSetVersion: 'scanner-set-1'
    });
    expect(postRestartRequest.repositoryBindingId).toBe(harness.repositoryBindingId);

    const replay = await restartedPlanner.plan({
      ...input,
      requestedAt: '2026-07-22T01:05:00Z'
    });

    expect(replay).toEqual(first);
    expect(
      await restartedControlPlane.getScanRequest('tenant-1', harness.scanRequest.id)
    ).toMatchObject({ status: 'QUEUED', sastPlanning: first.planning });

    const claim = await restartedQueue.claimNextForDispatch({
      lane: 'FAST',
      dailyWindowStartedAt: '2026-07-22T00:00:00Z',
      workerId: 'restart-dispatcher',
      claimedAt: '2026-07-22T01:06:00Z',
      leaseSeconds: 30
    });
    expect(claim?.plan).toEqual(first.plan);
    expect(Object.isFrozen(claim?.plan)).toBe(true);
  });

  it('matches the production store conflict contract for revoked repository context', async () => {
    const harness = await createHarness('FAST');
    const [integration] = await harness.scanRequestStore.listIntegrations('tenant-1');
    const [repositoryBinding] = await harness.scanRequestStore.listRepositoryBindings('tenant-1');

    await harness.scanRequestStore.revokeIntegration('tenant-1', integration.id);

    await expect(
      harness.scanRequestStore.createOrGet({
        scanRequest: harness.scanRequest,
        integration,
        repositoryBinding
      })
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('selects Java Deep or limited Common Deep without overstating language coverage', async () => {
    const javaHarness = await createHarness('DEEP');
    const java = await javaHarness.planner.plan(
      buildPlanningInput(javaHarness.repositoryBindingId, javaHarness.scanRequest.id, {
        queueUsage: buildQueueUsage(javaHarness.repositoryBindingId, 'DEEP')
      })
    );
    expect(java.planning).toMatchObject({
      state: 'ADMITTED',
      profileId: 'JAVA_DEEP_V1',
      coverageClaim: 'LANGUAGE_SAST_COMPLETE',
      queueName: 'scan.deep.v1'
    });

    const commonHarness = await createHarness('DEEP');
    const common = await commonHarness.planner.plan(
      buildPlanningInput(commonHarness.repositoryBindingId, commonHarness.scanRequest.id, {
        repositoryMetadata: buildMetadata(commonHarness.repositoryBindingId, ['PYTHON']),
        queueUsage: buildQueueUsage(commonHarness.repositoryBindingId, 'DEEP')
      })
    );
    expect(common.planning).toMatchObject({
      state: 'ADMITTED',
      profileId: 'COMMON_DEEP_V1',
      coverageClaim: 'COMMON_STATIC_COVERAGE_ONLY',
      reasonCodes: ['LANGUAGE_SPECIFIC_SAST_UNAVAILABLE']
    });
    expect(common.plan?.profile.aiAdvisoryEligible).toBe(false);
  });

  it('fails closed for unsupported Fast languages, polyglot scope, and policy mismatch', async () => {
    const fastHarness = await createHarness('FAST');
    const unsupported = await fastHarness.planner.plan(
      buildPlanningInput(fastHarness.repositoryBindingId, fastHarness.scanRequest.id, {
        repositoryMetadata: buildMetadata(fastHarness.repositoryBindingId, ['PYTHON'])
      })
    );
    expect(unsupported.planning.reasonCodes).toEqual(['UNSUPPORTED_LANGUAGE_FOR_FAST']);
    expect(unsupported.plan).toBeUndefined();

    const polyglotHarness = await createHarness('DEEP');
    const polyglot = await polyglotHarness.planner.plan(
      buildPlanningInput(polyglotHarness.repositoryBindingId, polyglotHarness.scanRequest.id, {
        repositoryMetadata: buildMetadata(polyglotHarness.repositoryBindingId, ['JAVA', 'KOTLIN']),
        queueUsage: buildQueueUsage(polyglotHarness.repositoryBindingId, 'DEEP')
      })
    );
    expect(polyglot.planning.reasonCodes).toEqual(['UNSUPPORTED_POLYGLOT_PROFILE']);

    const policyHarness = await createHarness('DEEP');
    const policyMismatch = await policyHarness.planner.plan(
      buildPlanningInput(policyHarness.repositoryBindingId, policyHarness.scanRequest.id, {
        profilePolicy: {
          policyVersion: 'policy-other',
          allowedProfileIds: ['JAVA_DEEP_V1'],
          requireLanguageSpecificSast: true
        },
        queueUsage: buildQueueUsage(policyHarness.repositoryBindingId, 'DEEP')
      })
    );
    expect(policyMismatch.planning.reasonCodes).toEqual([
      'PROFILE_POLICY_VERSION_MISMATCH'
    ]);

    const futureMetadataHarness = await createHarness('FAST');
    const futureMetadata = await futureMetadataHarness.planner.plan(
      buildPlanningInput(
        futureMetadataHarness.repositoryBindingId,
        futureMetadataHarness.scanRequest.id,
        {
          repositoryMetadata: {
            ...buildMetadata(futureMetadataHarness.repositoryBindingId),
            collectedAt: '2026-07-22T02:00:00Z'
          }
        }
      )
    );
    expect(futureMetadata.planning.reasonCodes).toEqual(['TRUSTED_METADATA_INVALID']);

    const invalidTimestampHarness = await createHarness('FAST');
    await expect(
      invalidTimestampHarness.planner.plan(
        buildPlanningInput(
          invalidTimestampHarness.repositoryBindingId,
          invalidTimestampHarness.scanRequest.id,
          { requestedAt: 'not-a-timestamp' }
        )
      )
    ).rejects.toThrow('requestedAt must be a valid UTC timestamp');
  });

  it('exposes every exceeded profile limit as a user-visible rejected state', async () => {
    const harness = await createHarness('FAST');
    const metadata = buildMetadata(harness.repositoryBindingId);
    const result = await harness.planner.plan(
      buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id, {
        repositoryMetadata: {
          ...metadata,
          repositoryBytes: 1_073_741_825,
          selectedBytes: 268_435_457,
          fileCount: 25_001,
          maxSingleFileBytes: 2_097_153,
          maxPathDepth: 65
        }
      })
    );

    expect(result.planning).toMatchObject({
      state: 'REJECTED',
      profileId: 'JAVA_FAST_V1',
      reasonCodes: [
        'REPOSITORY_BYTES_LIMIT_EXCEEDED',
        'SELECTED_BYTES_LIMIT_EXCEEDED',
        'FILE_COUNT_LIMIT_EXCEEDED',
        'SINGLE_FILE_BYTES_LIMIT_EXCEEDED',
        'PATH_DEPTH_LIMIT_EXCEEDED'
      ]
    });
    expect(
      await harness.controlPlane.getScanRequest('tenant-1', harness.scanRequest.id)
    ).toMatchObject({ status: 'FAILED', sastPlanning: result.planning });
  });

  it('fails closed for malformed language signals and invalid snapshot sentinels', async () => {
    const malformedMetadataHarness = await createHarness('FAST');
    const malformedMetadata = buildMetadata(malformedMetadataHarness.repositoryBindingId);
    const malformedResult = await malformedMetadataHarness.planner.plan(
      buildPlanningInput(
        malformedMetadataHarness.repositoryBindingId,
        malformedMetadataHarness.scanRequest.id,
        {
          repositoryMetadata: {
            ...malformedMetadata,
            sourceLanguages: [null] as never
          }
        }
      )
    );
    expect(malformedResult.planning).toMatchObject({
      state: 'REJECTED',
      reasonCodes: ['TRUSTED_METADATA_INVALID']
    });

    const invalidUsageHarness = await createHarness('FAST');
    const invalidUsage = buildQueueUsage(invalidUsageHarness.repositoryBindingId, 'FAST');
    const invalidUsageResult = await invalidUsageHarness.planner.plan(
      buildPlanningInput(
        invalidUsageHarness.repositoryBindingId,
        invalidUsageHarness.scanRequest.id,
        {
          queueUsage: {
            ...invalidUsage,
            snapshotVersion: Number.MAX_SAFE_INTEGER,
            queuedForTenant: queuePolicy.lanes.FAST.maxQueuedPerTenant,
            queuedInLane: queuePolicy.lanes.FAST.maxQueuedPerTenant
          }
        }
      )
    );
    expect(invalidUsageResult.planning).toMatchObject({
      state: 'REJECTED',
      reasonCodes: ['QUEUE_USAGE_INVALID']
    });
  });

  it('binds every execution artifact digest into the canonical scan key', async () => {
    const harness = await createHarness('FAST');
    const baseInput = buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id);
    const baselineResult = await harness.planner.plan(baseInput);
    const baseline = baselineResult.planning.canonicalScanKey;
    const baseCanonicalInput = {
      tenantId: 'tenant-1',
      repositoryBindingId: harness.repositoryBindingId,
      lane: 'FAST' as const,
      targetRef: harness.scanRequest.targetRef,
      fixedCommitSha: harness.scanRequest.commitSha,
      inventoryDigest: baseInput.repositoryMetadata.inventoryDigest,
      attestationRef: baseInput.repositoryMetadata.attestationRef,
      policyVersion: harness.scanRequest.policyVersion,
      profile: baselineResult.plan!.profile,
      profileDigest: baselineResult.plan!.profileDigest,
      scannerSet: baselineResult.plan!.scannerSet,
      tenantRulePolicy: baselineResult.plan!.tenantRulePolicy,
      isolationClass: baselineResult.plan!.isolationClass
    };
    const keyFor = (
      scannerSet: PromotionVerifiedScannerSetDescriptor,
      inventoryDigest = baseCanonicalInput.inventoryDigest,
      attestationRef = baseCanonicalInput.attestationRef
    ): `sha256:${string}` =>
      `sha256:${createHash('sha256')
        .update(
          buildSastCanonicalScanKeyPreimage({
            ...baseCanonicalInput,
            scannerSet,
            inventoryDigest,
            attestationRef
          }),
          'utf8'
        )
        .digest('hex')}`;
    expect(keyFor(baselineResult.plan!.scannerSet)).toBe(baseline);
    const variants: PromotionVerifiedScannerSetDescriptor[] = [
      { ...baselineResult.plan!.scannerSet, scannerSetDigest: digest('2') },
      {
        ...baselineResult.plan!.scannerSet,
        ruleBundles: [
          verifiedRuleBundle('OPENGREP', '3'),
          verifiedRuleBundle('TRIVY', '8')
        ]
      },
      {
        ...baselineResult.plan!.scannerSet,
        ruleBundles: baselineResult.plan!.scannerSet.ruleBundles.map(
          (bundle, index) =>
            index === 0
              ? {
                  ...bundle,
                  lifecycle: {
                    ...bundle.lifecycle,
                    lifecycleTransitionId:
                      `sast-rule-bundle-lifecycle-transition://${'a'.repeat(64)}`,
                    lifecycleTransitionDigest: digest('a')
                  }
                }
              : bundle
        )
      },
      {
        ...baselineResult.plan!.scannerSet,
        vulnerabilityDatabase: {
          ...baselineResult.plan!.scannerSet.vulnerabilityDatabase,
          digest: digest('4')
        }
      },
      { ...baselineResult.plan!.scannerSet, schemaBundle: signedArtifact('5') },
      { ...baselineResult.plan!.scannerSet, normalizerBundle: signedArtifact('7') },
      {
        ...baselineResult.plan!.scannerSet,
        scanners: {
          ...baselineResult.plan!.scannerSet.scanners,
          OPENGREP: {
            ...baselineResult.plan!.scannerSet.scanners.OPENGREP,
            wrapper: signedArtifact('8')
          }
        }
      }
    ];

    const keys = variants.map((scannerSet) => keyFor(scannerSet));
    expect(keys.every((key) => key !== baseline)).toBe(true);
    expect(new Set(keys).size).toBe(keys.length);

    const receiptOnlyScannerSet: PromotionVerifiedScannerSetDescriptor = {
      ...baselineResult.plan!.scannerSet,
      ruleBundles: baselineResult.plan!.scannerSet.ruleBundles.map(
        (bundle, index) =>
          index === 0
            ? {
                ...bundle,
                lifecycle: {
                  ...bundle.lifecycle,
                  selectionReceiptId:
                    `sast-rule-bundle-lifecycle-selection://${'b'.repeat(64)}`,
                  selectionReceiptDigest: digest('b')
                }
              }
            : bundle
      )
    };
    expect(keyFor(receiptOnlyScannerSet)).toBe(baseline);

    const inventoryKey = keyFor(
      baselineResult.plan!.scannerSet,
      digest('3')
    );
    expect(inventoryKey).not.toBe(baseline);
    const attestationKey = keyFor(
      baselineResult.plan!.scannerSet,
      baseCanonicalInput.inventoryDigest,
      'attestation://inventory-2'
    );
    expect(attestationKey).not.toBe(baseline);
  });

  it('defers capacity-limited work with the lane queue and retry condition', async () => {
    const harness = await createHarness('DEEP');
    const result = await harness.planner.plan(
      buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id, {
        queueUsage: {
          ...buildQueueUsage(harness.repositoryBindingId, 'DEEP'),
          activeForTenant: queuePolicy.lanes.DEEP.maxActivePerTenant
        }
      })
    );

    expect(result.planning).toMatchObject({
      state: 'DEFERRED',
      profileId: 'JAVA_DEEP_V1',
      queueName: 'scan.deep.v1',
      reasonCodes: ['TENANT_CONCURRENCY_LIMIT'],
      retryAfterSeconds: 300
    });
    expect(result.plan).toBeDefined();
    expect(
      (await harness.controlPlane.getScanRequest('tenant-1', harness.scanRequest.id)).status
    ).toBe('PLANNING');
  });

  it('records a fail-closed retry reason without discarding a deferred canonical identity', async () => {
    const harness = await createHarness('DEEP');
    const deferred = await harness.planner.plan(
      buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id, {
        queueUsage: {
          ...buildQueueUsage(harness.repositoryBindingId, 'DEEP'),
          activeForTenant: queuePolicy.lanes.DEEP.maxActivePerTenant
        }
      })
    );
    expect(deferred.planning.canonicalScanKey).toBeDefined();

    const rejected = await harness.planner.plan(
      buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id, {
        profilePolicy: {
          policyVersion: 'policy-rotated',
          allowedProfileIds: ['JAVA_DEEP_V1'],
          requireLanguageSpecificSast: true
        },
        queueUsage: buildQueueUsage(harness.repositoryBindingId, 'DEEP')
      })
    );
    expect(rejected.planning).toMatchObject({
      state: 'REJECTED',
      canonicalScanKey: deferred.planning.canonicalScanKey,
      reasonCodes: ['PROFILE_POLICY_VERSION_MISMATCH']
    });
  });

  it('rejects missing required scanner assets before queue admission', async () => {
    const harness = await createHarness('FAST');
    const scannerSet = buildScannerSet();
    const result = await harness.planner.plan(
      buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id, {
        scannerSet: {
          ...scannerSet,
          scanners: {
            TRIVY: scannerSet.scanners.TRIVY,
            SYFT: scannerSet.scanners.SYFT
          } as ScannerSetDescriptor['scanners']
        }
      })
    );

    expect(result.planning.reasonCodes).toEqual(
      expect.arrayContaining(['REQUIRED_SCANNER_MISSING', 'SCANNER_SET_INVALID'])
    );
    expect(result.plan).toBeUndefined();
  });

  it('orders one lane by deterministic tenant round-robin fairness', () => {
    const ordered = orderSastQueueCandidatesFairly(
      'FAST',
      [
        { lane: 'FAST', tenantId: 'tenant-a', scanRequestId: 'a-1', enqueuedAt: '2026-07-22T00:00:00Z' },
        { lane: 'FAST', tenantId: 'tenant-a', scanRequestId: 'a-2', enqueuedAt: '2026-07-22T00:00:01Z' },
        { lane: 'FAST', tenantId: 'tenant-a', scanRequestId: 'a-3', enqueuedAt: '2026-07-22T00:00:02Z' },
        { lane: 'FAST', tenantId: 'tenant-b', scanRequestId: 'b-1', enqueuedAt: '2026-07-22T00:00:03Z' },
        { lane: 'FAST', tenantId: 'tenant-b', scanRequestId: 'b-2', enqueuedAt: '2026-07-22T00:00:04Z' },
        { lane: 'DEEP', tenantId: 'tenant-c', scanRequestId: 'c-1', enqueuedAt: '2026-07-22T00:00:00Z' }
      ],
      'tenant-a'
    );

    expect(ordered.map((candidate) => candidate.scanRequestId)).toEqual([
      'b-1',
      'a-1',
      'b-2',
      'a-2',
      'a-3'
    ]);
  });

  it('shares atomic reservations across service replicas and canonical UTC encodings', async () => {
    const store = new InMemorySastQueueAdmissionStore();
    const firstReplica = new SastQueueAdmissionService(store);
    const secondReplica = new SastQueueAdmissionService(store);
    const baseInput: SastQueueReservationInput = {
      scanRequestId: 'scan-a',
      canonicalScanKey: digest('a'),
      lane: 'FAST',
      tenantId: 'tenant-a',
      repositoryBindingId: 'repository-a',
      requestedAt: '2026-07-22T01:00:00Z',
      policySet: queuePolicy,
      plan: buildReservationPlan({
        scanRequestId: 'scan-a',
        canonicalScanKey: digest('a'),
        tenantId: 'tenant-a',
        repositoryBindingId: 'repository-a',
        createdAt: '2026-07-22T01:00:00Z'
      }),
      planningContext: {
        profileId: 'JAVA_FAST_V1',
        coverageClaim: 'LANGUAGE_SAST_COMPLETE',
        reasonCodes: []
      },
      usage: {
        snapshotVersion: 0,
        tenantId: 'tenant-a',
        repositoryBindingId: 'repository-a',
        lane: 'FAST',
        dailyWindowStartedAt: '2026-07-22T00:00:00Z',
        activeForTenant: 0,
        queuedForTenant: 0,
        admittedTodayForTenant: 0,
        activeForRepository: 0,
        queuedInLane: 0
      }
    };

    const [first, concurrent] = await Promise.all([
      firstReplica.reserve(baseInput),
      secondReplica.reserve({
        ...baseInput,
        scanRequestId: 'scan-b',
        canonicalScanKey: digest('b'),
        repositoryBindingId: 'repository-b',
        plan: buildReservationPlan({
          scanRequestId: 'scan-b',
          canonicalScanKey: digest('b'),
          tenantId: 'tenant-a',
          repositoryBindingId: 'repository-b',
          createdAt: '2026-07-22T01:00:00Z'
        }),
        usage: {
          ...baseInput.usage,
          repositoryBindingId: 'repository-b',
          dailyWindowStartedAt: '2026-07-22T00:00:00.000Z'
        }
      })
    ]);

    expect([first.state, concurrent.state].sort()).toEqual(['ADMITTED', 'DEFERRED']);
    expect([first, concurrent].find((decision) => decision.state === 'DEFERRED')).toMatchObject({
      reasonCodes: ['QUEUE_USAGE_STALE']
    });

    const restartedReplica = new SastQueueAdmissionService(store);
    const replay = await restartedReplica.reserve(baseInput);
    expect(replay).toEqual(first);
    const replayContext = await restartedReplica.reserveWithContext({
      ...baseInput,
      requestedAt: '2026-07-22T01:05:00Z'
    });
    expect(replayContext).toMatchObject({
      decision: first,
      admittedAt: '2026-07-22T01:00:00.000Z'
    });
  });

  it('claims admitted work with a transactional tenant round-robin cursor', async () => {
    const service = new SastQueueAdmissionService(new InMemorySastQueueAdmissionStore());
    const reservationInput = (
      scanRequestId: string,
      tenantId: string,
      repositoryBindingId: string,
      requestedAt: string,
      snapshotVersion: number,
      queuedForTenant: number,
      admittedTodayForTenant: number,
      queuedInLane: number,
      digestCharacter: string
    ): SastQueueReservationInput => ({
      scanRequestId,
      canonicalScanKey: digest(digestCharacter),
      lane: 'FAST',
      tenantId,
      repositoryBindingId,
      requestedAt,
      policySet: queuePolicy,
      plan: buildReservationPlan({
        scanRequestId,
        canonicalScanKey: digest(digestCharacter),
        tenantId,
        repositoryBindingId,
        createdAt: requestedAt
      }),
      planningContext: {
        profileId: 'JAVA_FAST_V1',
        coverageClaim: 'LANGUAGE_SAST_COMPLETE',
        reasonCodes: []
      },
      usage: {
        snapshotVersion,
        tenantId,
        repositoryBindingId,
        lane: 'FAST',
        dailyWindowStartedAt: '2026-07-22T00:00:00Z',
        activeForTenant: 0,
        queuedForTenant,
        admittedTodayForTenant,
        activeForRepository: 0,
        queuedInLane
      }
    });

    expect(
      (
        await service.reserve(
          reservationInput('a-1', 'tenant-a', 'repository-a-1', '2026-07-22T01:00:00Z', 0, 0, 0, 0, '1')
        )
      ).state
    ).toBe('ADMITTED');
    expect(
      (
        await service.reserve(
          reservationInput('a-2', 'tenant-a', 'repository-a-2', '2026-07-22T01:00:01Z', 1, 1, 1, 1, '2')
        )
      ).state
    ).toBe('ADMITTED');
    expect(
      (
        await service.reserve(
          reservationInput('b-1', 'tenant-b', 'repository-b-1', '2026-07-22T01:00:02Z', 2, 0, 0, 2, '3')
        )
      ).state
    ).toBe('ADMITTED');

    const claimInput = {
      lane: 'FAST' as const,
      dailyWindowStartedAt: '2026-07-22T00:00:00.000Z',
      workerId: 'dispatcher-1',
      claimedAt: '2026-07-22T01:01:00Z',
      leaseSeconds: 30
    };
    const first = await service.claimNextForDispatch(claimInput);
    expect(first?.scanRequestId).toBe('a-1');
    expect(first?.plan.canonicalScanKey).toBe(digest('1'));
    expect(Object.isFrozen(first?.plan)).toBe(true);
    expect(
      await service.acknowledgeDispatch({
        scanRequestId: first!.scanRequestId,
        workerId: claimInput.workerId,
        acknowledgedAt: '2026-07-22T01:01:01Z'
      })
    ).toBe(true);

    const second = await service.claimNextForDispatch({
      ...claimInput,
      claimedAt: '2026-07-22T01:01:02Z'
    });
    expect(second?.scanRequestId).toBe('b-1');
  });

  it('drains the oldest pending lane ledger after a UTC-day rollover', async () => {
    const service = new SastQueueAdmissionService(new InMemorySastQueueAdmissionStore());
    const reservation = buildDispatchReservationInput({
      scanRequestId: 'rollover-1',
      digestCharacter: 'a',
      requestedAt: '2026-07-22T23:59:00Z',
      dailyWindowStartedAt: '2026-07-22T00:00:00Z'
    });

    expect((await service.reserve(reservation)).state).toBe('ADMITTED');
    const claim = await service.claimNextForDispatch({
      lane: 'FAST',
      dailyWindowStartedAt: '2026-07-23T00:00:00Z',
      workerId: 'rollover-worker',
      claimedAt: '2026-07-23T00:01:00Z',
      leaseSeconds: 30
    });

    expect(claim?.scanRequestId).toBe(reservation.scanRequestId);
    expect(claim?.plan).toEqual(reservation.plan);
  });

  it('keeps live queue counters global while resetting only the UTC daily budget', async () => {
    const service = new SastQueueAdmissionService(new InMemorySastQueueAdmissionStore());
    const first = buildDispatchReservationInput({
      scanRequestId: 'cross-day-live-1',
      digestCharacter: 'd',
      requestedAt: '2026-07-22T23:58:00Z',
      dailyWindowStartedAt: '2026-07-22T00:00:00Z'
    });
    expect((await service.reserve(first)).state).toBe('ADMITTED');

    const falseQueuedSnapshot = buildDispatchReservationInput({
      scanRequestId: 'cross-day-live-2',
      digestCharacter: 'e',
      requestedAt: '2026-07-23T00:01:00Z',
      dailyWindowStartedAt: '2026-07-23T00:00:00Z',
      snapshotVersion: 1,
      queuedInLane: 1,
      lastRepositoryAdmissionAt: '2026-07-22T23:58:00Z'
    });
    expect(await service.reserve(falseQueuedSnapshot)).toMatchObject({
      state: 'DEFERRED',
      reasonCodes: ['QUEUE_USAGE_STALE']
    });

    const claim = await service.claimNextForDispatch({
      lane: 'FAST',
      dailyWindowStartedAt: '2026-07-23T00:00:00Z',
      workerId: 'cross-day-worker',
      claimedAt: '2026-07-23T00:01:10Z',
      leaseSeconds: 30
    });
    expect(claim?.scanRequestId).toBe(first.scanRequestId);
    expect(
      await service.acknowledgeDispatch({
        scanRequestId: first.scanRequestId,
        workerId: 'cross-day-worker',
        acknowledgedAt: '2026-07-23T00:01:11Z'
      })
    ).toBe(true);

    const falseActiveSnapshot = buildDispatchReservationInput({
      scanRequestId: 'cross-day-live-2',
      digestCharacter: 'e',
      requestedAt: '2026-07-23T00:02:00Z',
      dailyWindowStartedAt: '2026-07-23T00:00:00Z',
      snapshotVersion: 2,
      lastRepositoryAdmissionAt: '2026-07-22T23:58:00Z'
    });
    expect(await service.reserve(falseActiveSnapshot)).toMatchObject({
      state: 'DEFERRED',
      reasonCodes: ['QUEUE_USAGE_STALE']
    });

    expect(
      await service.completeDispatch({
        scanRequestId: first.scanRequestId,
        workerId: 'cross-day-worker',
        completedAt: '2026-07-23T00:02:10Z',
        terminalStatus: 'COMPLETED'
      })
    ).toBe(true);

    const releasedSnapshot = buildDispatchReservationInput({
      scanRequestId: 'cross-day-live-2',
      digestCharacter: 'e',
      requestedAt: '2026-07-23T00:03:00Z',
      dailyWindowStartedAt: '2026-07-23T00:00:00Z',
      snapshotVersion: 3,
      lastRepositoryAdmissionAt: '2026-07-22T23:58:00Z'
    });
    expect((await service.reserve(releasedSnapshot)).state).toBe('ADMITTED');
  });

  it('fails an unacknowledged reservation after two expired dispatch leases', async () => {
    const service = new SastQueueAdmissionService(new InMemorySastQueueAdmissionStore());
    const first = buildDispatchReservationInput({
      scanRequestId: 'exhausted-1',
      digestCharacter: 'b',
      requestedAt: '2026-07-22T01:00:00Z',
      dailyWindowStartedAt: '2026-07-22T00:00:00Z'
    });
    expect((await service.reserve(first)).state).toBe('ADMITTED');

    expect(
      (
        await service.claimNextForDispatch({
          lane: 'FAST',
          dailyWindowStartedAt: '2026-07-22T00:00:00Z',
          workerId: 'retry-worker-1',
          claimedAt: '2026-07-22T01:01:00Z',
          leaseSeconds: 10
        })
      )?.scanRequestId
    ).toBe(first.scanRequestId);
    expect(
      (
        await service.claimNextForDispatch({
          lane: 'FAST',
          dailyWindowStartedAt: '2026-07-22T00:00:00Z',
          workerId: 'retry-worker-2',
          claimedAt: '2026-07-22T01:01:11Z',
          leaseSeconds: 10
        })
      )?.scanRequestId
    ).toBe(first.scanRequestId);

    await expect(
      service.claimNextForDispatch({
        lane: 'FAST',
        dailyWindowStartedAt: '2026-07-22T00:00:00Z',
        workerId: 'retry-worker-3',
        claimedAt: '2026-07-22T01:01:22Z',
        leaseSeconds: 10
      })
    ).resolves.toBeNull();
    await expect(
      service.acknowledgeDispatch({
        scanRequestId: first.scanRequestId,
        workerId: 'retry-worker-2',
        acknowledgedAt: '2026-07-22T01:01:22Z'
      })
    ).resolves.toBe(false);

    const replacement = buildDispatchReservationInput({
      scanRequestId: 'exhausted-2',
      digestCharacter: 'c',
      requestedAt: '2026-07-22T01:02:00Z',
      dailyWindowStartedAt: '2026-07-22T00:00:00Z',
      snapshotVersion: 2,
      admittedTodayForTenant: 1,
      lastRepositoryAdmissionAt: '2026-07-22T01:00:00Z'
    });
    expect((await service.reserve(replacement)).state).toBe('ADMITTED');
  });

  it('reconciles queued and active counters across dispatch and completion', async () => {
    const service = new SastQueueAdmissionService(new InMemorySastQueueAdmissionStore());
    const firstInput: SastQueueReservationInput = {
      scanRequestId: 'lifecycle-1',
      canonicalScanKey: digest('4'),
      lane: 'FAST',
      tenantId: 'tenant-lifecycle',
      repositoryBindingId: 'repository-lifecycle',
      requestedAt: '2026-07-22T01:00:00Z',
      policySet: queuePolicy,
      plan: buildReservationPlan({
        scanRequestId: 'lifecycle-1',
        canonicalScanKey: digest('4'),
        tenantId: 'tenant-lifecycle',
        repositoryBindingId: 'repository-lifecycle',
        createdAt: '2026-07-22T01:00:00Z'
      }),
      planningContext: {
        profileId: 'JAVA_FAST_V1',
        coverageClaim: 'LANGUAGE_SAST_COMPLETE',
        reasonCodes: []
      },
      usage: {
        snapshotVersion: 0,
        tenantId: 'tenant-lifecycle',
        repositoryBindingId: 'repository-lifecycle',
        lane: 'FAST',
        dailyWindowStartedAt: '2026-07-22T00:00:00Z',
        activeForTenant: 0,
        queuedForTenant: 0,
        admittedTodayForTenant: 0,
        activeForRepository: 0,
        queuedInLane: 0
      }
    };

    expect((await service.reserve(firstInput)).state).toBe('ADMITTED');
    const claim = await service.claimNextForDispatch({
      lane: 'FAST',
      dailyWindowStartedAt: '2026-07-22T00:00:00Z',
      workerId: 'worker-lifecycle',
      claimedAt: '2026-07-22T01:01:00Z',
      leaseSeconds: 30
    });
    expect(claim?.plan).toEqual(firstInput.plan);
    expect(
      await service.acknowledgeDispatch({
        scanRequestId: firstInput.scanRequestId,
        workerId: 'worker-lifecycle',
        acknowledgedAt: '2026-07-22T01:01:01Z'
      })
    ).toBe(true);
    expect(
      await service.completeDispatch({
        scanRequestId: firstInput.scanRequestId,
        workerId: 'worker-lifecycle',
        completedAt: '2026-07-22T01:01:02Z',
        terminalStatus: 'COMPLETED'
      })
    ).toBe(true);

    const secondInput: SastQueueReservationInput = {
      ...firstInput,
      scanRequestId: 'lifecycle-2',
      canonicalScanKey: digest('5'),
      requestedAt: '2026-07-22T01:02:00Z',
      plan: buildReservationPlan({
        scanRequestId: 'lifecycle-2',
        canonicalScanKey: digest('5'),
        tenantId: 'tenant-lifecycle',
        repositoryBindingId: 'repository-lifecycle',
        createdAt: '2026-07-22T01:02:00Z'
      }),
      usage: {
        ...firstInput.usage,
        snapshotVersion: 3,
        admittedTodayForTenant: 1,
        lastRepositoryAdmissionAt: '2026-07-22T01:00:00.000Z'
      }
    };
    expect((await service.reserve(secondInput)).state).toBe('ADMITTED');
  });

  it('returns explicit retryable outcomes for every queue quota boundary', () => {
    const repositoryBindingId = 'repository-1';
    const baseUsage = buildQueueUsage(repositoryBindingId, 'FAST');
    const cases: Array<{
      usage: SastQueueUsageSnapshot;
      reasonCode: string;
      retryAfterSeconds: number;
    }> = [
      {
        usage: { ...baseUsage, activeForRepository: 1, activeForTenant: 1 },
        reasonCode: 'REPOSITORY_CONCURRENCY_LIMIT',
        retryAfterSeconds: 30
      },
      {
        usage: { ...baseUsage, activeForTenant: 2 },
        reasonCode: 'TENANT_CONCURRENCY_LIMIT',
        retryAfterSeconds: 30
      },
      {
        usage: { ...baseUsage, queuedForTenant: 10, queuedInLane: 10 },
        reasonCode: 'TENANT_QUEUED_LIMIT',
        retryAfterSeconds: 30
      },
      {
        usage: { ...baseUsage, admittedTodayForTenant: 100 },
        reasonCode: 'TENANT_DAILY_BUDGET_EXHAUSTED',
        retryAfterSeconds: 82_800
      },
      {
        usage: { ...baseUsage, queuedInLane: 1000 },
        reasonCode: 'LANE_QUEUE_CAPACITY_EXHAUSTED',
        retryAfterSeconds: 30
      },
      {
        usage: { ...baseUsage, lastRepositoryAdmissionAt: '2026-07-22T00:59:30Z' },
        reasonCode: 'REPOSITORY_FREQUENCY_LIMIT',
        retryAfterSeconds: 30
      }
    ];

    for (const testCase of cases) {
      expect(
        evaluateSastQueueAdmission({
          lane: 'FAST',
          tenantId: 'tenant-1',
          repositoryBindingId,
          requestedAt: '2026-07-22T01:00:00Z',
          policySet: queuePolicy,
          usage: testCase.usage
        })
      ).toMatchObject({
        state: 'DEFERRED',
        queueName: 'scan.fast.v1',
        queuePolicyVersion: 'queue-policy-1',
        queuePolicyDigest: digest('e'),
        reasonCodes: [testCase.reasonCode],
        retryAfterSeconds: testCase.retryAfterSeconds
      });
    }

    expect(
      evaluateSastQueueAdmission({
        lane: 'FAST',
        tenantId: 'tenant-1',
        repositoryBindingId,
        requestedAt: '2026-07-22T01:00:00Z',
        policySet: queuePolicy,
        usage: { ...baseUsage, tenantId: 'tenant-other' }
      })
    ).toEqual({
      state: 'REJECTED',
      queuePolicyVersion: 'queue-policy-1',
      queuePolicyDigest: digest('e'),
      reasonCodes: ['QUEUE_USAGE_INVALID']
    });

    expect(
      evaluateSastQueueAdmission({
        lane: 'FAST',
        tenantId: 'tenant-1',
        repositoryBindingId,
        requestedAt: '2026-07-22T01:00:00Z',
        policySet: queuePolicy,
        usage: { ...baseUsage, activeForRepository: 1, activeForTenant: 0 }
      })
    ).toMatchObject({ state: 'REJECTED', reasonCodes: ['QUEUE_USAGE_INVALID'] });
  });

  it('atomically reserves queue capacity and defers a replayed usage snapshot', async () => {
    const harness = await createHarness('FAST');
    const firstInput = buildPlanningInput(
      harness.repositoryBindingId,
      harness.scanRequest.id
    );
    expect((await harness.planner.plan(firstInput)).planning.state).toBe('ADMITTED');

    const secondScanRequest = await harness.controlPlane.createScanRequest({
      tenantId: 'tenant-1',
      repositoryBindingId: harness.repositoryBindingId,
      lane: 'FAST',
      targetRef: 'refs/pull/8/head',
      commitSha: 'a'.repeat(40),
      policyVersion: 'policy-1',
      scannerSetVersion: 'scanner-set-1'
    });
    const staleInput = buildPlanningInput(
      harness.repositoryBindingId,
      secondScanRequest.id,
      {
        requestedAt: '2026-07-22T01:00:01Z',
        queueUsage: {
          ...buildQueueUsage(harness.repositoryBindingId, 'FAST'),
          dailyWindowStartedAt: '2026-07-22T00:00:00.000Z'
        }
      }
    );
    const staleResult = await harness.planner.plan(staleInput);
    expect(staleResult.planning).toMatchObject({
      state: 'DEFERRED',
      reasonCodes: ['QUEUE_USAGE_STALE'],
      retryAfterSeconds: 30
    });

    const refreshedResult = await harness.planner.plan({
      ...staleInput,
      requestedAt: '2026-07-22T01:01:00Z',
      queueUsage: {
        ...staleInput.queueUsage,
        snapshotVersion: 1,
        queuedForTenant: 1,
        admittedTodayForTenant: 1,
        queuedInLane: 1,
        lastRepositoryAdmissionAt: '2026-07-22T01:00:00Z'
      }
    });
    expect(refreshedResult.planning).toMatchObject({
      state: 'ADMITTED',
      reasonCodes: []
    });
  });

  it('does not let late planning rewrite a running scan', async () => {
    const harness = await createHarness('FAST');
    await harness.controlPlane.updateScanRequestStatus(
      'tenant-1',
      harness.scanRequest.id,
      'RUNNING'
    );
    await expect(
      harness.controlPlane.updateScanRequestStatus(
        'tenant-1',
        harness.scanRequest.id,
        'QUEUED'
      )
    ).rejects.toThrow('cannot transition from RUNNING to QUEUED');

    await expect(
      harness.planner.plan(
        buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id)
      )
    ).rejects.toThrow('cannot rewrite a terminal or running scan');
    expect(
      await harness.controlPlane.getScanRequest('tenant-1', harness.scanRequest.id)
    ).toMatchObject({ status: 'RUNNING', sastPlanning: undefined });

    const nextScanRequest = await harness.controlPlane.createScanRequest({
      tenantId: 'tenant-1',
      repositoryBindingId: harness.repositoryBindingId,
      lane: 'FAST',
      targetRef: 'refs/pull/9/head',
      commitSha: 'a'.repeat(40),
      policyVersion: 'policy-1',
      scannerSetVersion: 'scanner-set-1'
    });
    expect(
      (
        await harness.planner.plan(
          buildPlanningInput(harness.repositoryBindingId, nextScanRequest.id)
        )
      ).planning.state
    ).toBe('ADMITTED');
  });
});
