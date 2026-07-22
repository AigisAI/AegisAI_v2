import { createHash } from 'node:crypto';

import {
  buildSastCanonicalScanKeyPreimage,
  isSastScanPlanValid,
  evaluateSastQueueAdmission,
  orderSastQueueCandidatesFairly,
  type SastQueuePolicySet,
  type SastQueueUsageSnapshot,
  type SastScanPlanningInput,
  type ScannerSetDescriptor,
  type TrustedSastRepositoryMetadata
} from '@aegisai/shared';

import { ControlPlaneService } from '../../src/control-plane/control-plane.service';
import type { SastQueueReservationInput } from '../../src/control-plane/sast-queue-admission.store';
import { SastQueueAdmissionService } from '../../src/control-plane/sast-queue-admission.service';
import { SastScanPlannerService } from '../../src/control-plane/sast-scan-planner.service';
import { InMemorySastQueueAdmissionStore } from '../support/in-memory-sast-queue-admission.store';

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
  signatureRef: `signature://rules/${scanner}`,
  provenanceRef: `provenance://rules/${scanner}`,
  compatibilityRef: `compatibility://rules/${scanner}`,
  rolloutPolicyRef: `rollout://rules/${scanner}`,
  killSwitchRef: `kill-switch://rules/${scanner}`,
  scanner,
  source: 'PLATFORM_MANAGED' as const,
  immutable: true as const,
  customerExecutableConfigAllowed: false as const
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

function createHarness(lane: 'FAST' | 'DEEP' = 'FAST') {
  const controlPlane = new ControlPlaneService(null as never, null as never, null as never);
  const queueAdmission = new SastQueueAdmissionService(
    new InMemorySastQueueAdmissionStore()
  );
  controlPlane.installIntegration(
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
  const repositoryBindingId = controlPlane.listRepositoryBindings('tenant-1')[0].id;
  const scanRequest = controlPlane.createScanRequest({
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
    queueAdmission,
    planner: new SastScanPlannerService(controlPlane, queueAdmission),
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
  it('selects the Java Fast profile and records an immutable admitted plan', async () => {
    const harness = createHarness('FAST');
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
    expect(first.plan).toMatchObject({
      tenantId: 'tenant-1',
      scanRequestId: harness.scanRequest.id,
      isolationClass: 'HARDENED',
      repositoryState: {
        repositoryBindingId: harness.repositoryBindingId,
        fixedCommitSha: 'a'.repeat(40),
        inventoryDigest: digest('2'),
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
      harness.controlPlane.getScanRequest('tenant-1', harness.scanRequest.id)
    ).toMatchObject({
      status: 'QUEUED',
      sastPlanning: first.planning
    });
  });

  it('selects Java Deep or limited Common Deep without overstating language coverage', async () => {
    const javaHarness = createHarness('DEEP');
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

    const commonHarness = createHarness('DEEP');
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
    const fastHarness = createHarness('FAST');
    const unsupported = await fastHarness.planner.plan(
      buildPlanningInput(fastHarness.repositoryBindingId, fastHarness.scanRequest.id, {
        repositoryMetadata: buildMetadata(fastHarness.repositoryBindingId, ['PYTHON'])
      })
    );
    expect(unsupported.planning.reasonCodes).toEqual(['UNSUPPORTED_LANGUAGE_FOR_FAST']);
    expect(unsupported.plan).toBeUndefined();

    const polyglotHarness = createHarness('DEEP');
    const polyglot = await polyglotHarness.planner.plan(
      buildPlanningInput(polyglotHarness.repositoryBindingId, polyglotHarness.scanRequest.id, {
        repositoryMetadata: buildMetadata(polyglotHarness.repositoryBindingId, ['JAVA', 'KOTLIN']),
        queueUsage: buildQueueUsage(polyglotHarness.repositoryBindingId, 'DEEP')
      })
    );
    expect(polyglot.planning.reasonCodes).toEqual(['UNSUPPORTED_POLYGLOT_PROFILE']);

    const policyHarness = createHarness('DEEP');
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

    const futureMetadataHarness = createHarness('FAST');
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

    const invalidTimestampHarness = createHarness('FAST');
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
    const harness = createHarness('FAST');
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
      harness.controlPlane.getScanRequest('tenant-1', harness.scanRequest.id)
    ).toMatchObject({ status: 'FAILED', sastPlanning: result.planning });
  });

  it('fails closed for malformed language signals and invalid snapshot sentinels', async () => {
    const malformedMetadataHarness = createHarness('FAST');
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

    const invalidUsageHarness = createHarness('FAST');
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
    const harness = createHarness('FAST');
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
      policyVersion: harness.scanRequest.policyVersion,
      profile: baselineResult.plan!.profile,
      profileDigest: baselineResult.plan!.profileDigest,
      scannerSet: baseInput.scannerSet,
      isolationClass: baselineResult.plan!.isolationClass
    };
    const keyFor = (
      scannerSet: ScannerSetDescriptor,
      inventoryDigest = baseCanonicalInput.inventoryDigest
    ): `sha256:${string}` =>
      `sha256:${createHash('sha256')
        .update(
          buildSastCanonicalScanKeyPreimage({
            ...baseCanonicalInput,
            scannerSet,
            inventoryDigest
          }),
          'utf8'
        )
        .digest('hex')}`;
    expect(keyFor(baseInput.scannerSet)).toBe(baseline);
    const variants: ScannerSetDescriptor[] = [
      { ...baseInput.scannerSet, scannerSetDigest: digest('2') },
      {
        ...baseInput.scannerSet,
        ruleBundles: [ruleBundle('OPENGREP', '3'), ruleBundle('TRIVY', '8')]
      },
      {
        ...baseInput.scannerSet,
        vulnerabilityDatabase: {
          ...baseInput.scannerSet.vulnerabilityDatabase,
          digest: digest('4')
        }
      },
      { ...baseInput.scannerSet, schemaBundle: signedArtifact('5') },
      { ...baseInput.scannerSet, normalizerBundle: signedArtifact('7') },
      {
        ...baseInput.scannerSet,
        scanners: {
          ...baseInput.scannerSet.scanners,
          OPENGREP: {
            ...baseInput.scannerSet.scanners.OPENGREP,
            wrapper: signedArtifact('8')
          }
        }
      }
    ];

    const keys = variants.map((scannerSet) => keyFor(scannerSet));
    expect(keys.every((key) => key !== baseline)).toBe(true);
    expect(new Set(keys).size).toBe(keys.length);

    const inventoryKey = keyFor(baseInput.scannerSet, digest('3'));
    expect(inventoryKey).not.toBe(baseline);
  });

  it('defers capacity-limited work with the lane queue and retry condition', async () => {
    const harness = createHarness('DEEP');
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
      harness.controlPlane.getScanRequest('tenant-1', harness.scanRequest.id).status
    ).toBe('PLANNING');
  });

  it('records a fail-closed retry reason without discarding a deferred canonical identity', async () => {
    const harness = createHarness('DEEP');
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
    const harness = createHarness('FAST');
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
    const harness = createHarness('FAST');
    const firstInput = buildPlanningInput(
      harness.repositoryBindingId,
      harness.scanRequest.id
    );
    expect((await harness.planner.plan(firstInput)).planning.state).toBe('ADMITTED');

    const secondScanRequest = harness.controlPlane.createScanRequest({
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
    const harness = createHarness('FAST');
    harness.scanRequest.status = 'RUNNING';

    await expect(
      harness.planner.plan(
        buildPlanningInput(harness.repositoryBindingId, harness.scanRequest.id)
      )
    ).rejects.toThrow('cannot rewrite a terminal or running scan');
    expect(harness.scanRequest.status).toBe('RUNNING');
    expect(harness.scanRequest.sastPlanning).toBeUndefined();

    const nextScanRequest = harness.controlPlane.createScanRequest({
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
