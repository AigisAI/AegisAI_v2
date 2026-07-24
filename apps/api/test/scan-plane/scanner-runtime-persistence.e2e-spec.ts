import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { UnavailableScannerSandboxRuntimeProvider } from '../../src/scan-plane/scanner-sandbox-runtime.provider';

describe('Scanner runtime persistence and deployment contract', () => {
  it('persists attempt-bound scanner and destruction metadata with database completion guards', () => {
    const schema = readFileSync(
      resolve(__dirname, '../../prisma/schema.prisma'),
      'utf8'
    );
    const migration = readFileSync(
      resolve(
        __dirname,
        '../../prisma/migrations/20260724150000_sast_scanner_runtime_lifecycle/migration.sql'
      ),
      'utf8'
    );

    expect(schema).toMatch(/model SastScanAttempt \{/);
    expect(schema).toMatch(/@@unique\(\[scanRequestId, attemptNumber\]\)/);
    expect(schema).toMatch(
      /@@unique\(\[id, tenantId\], map: "SastScanAttempt_id_tenantId_key"\)/
    );
    expect(schema).toMatch(/cleanupEvidenceDigest\s+String\?/);
    expect(schema).toMatch(/finalAuditEventId\s+String\?/);
    expect(schema).toMatch(/attemptDeadlineAt\s+DateTime/);
    expect(schema).toMatch(/scannerWorkspaceInventoryDigest\s+String\?/);
    expect(schema).toMatch(/resourceMetadata\s+Json\?/);
    expect(schema).toMatch(/artifactMetadata\s+Json\?/);
    expect(schema).toMatch(/@@unique\(\[attemptId, scanner\]\)/);

    expect(migration).toContain(
      'CONSTRAINT "SastScanAttempt_attempt_number_check"'
    );
    expect(migration).toContain(
      'CONSTRAINT "SastScanAttempt_deadline_check"'
    );
    expect(migration).toContain(
      'CONSTRAINT "SastScanAttempt_completed_cleanup_check"'
    );
    expect(migration).toContain(
      'CONSTRAINT "SastScanAttempt_retry_eligibility_check"'
    );
    expect(migration).toContain(
      'CONSTRAINT "SastScanAttempt_lifecycle_state_check"'
    );
    expect(migration).toContain(
      'CREATE UNIQUE INDEX "SastScanAttempt_one_active_per_scan_key"'
    );
    expect(migration).toContain(
      `WHERE "stage" IN ('VALIDATING', 'SCANNING', 'CLEANUP_PENDING')`
    );
    expect(migration).toContain(
      'CREATE INDEX "SastScanAttempt_stage_attemptDeadlineAt_idx"'
    );
    expect(migration).toContain(
      '"cleanupEvidence" IS NOT NULL'
    );
    expect(migration).toContain(
      '"finalAuditEventId" IS NOT NULL'
    );
    for (const condition of [
      'credentialRevokedAndWiped',
      'scannerProcessesTerminated',
      'writableVolumesDestroyed',
      'microVmTerminated',
      'resultIngressClosed'
    ]) {
      expect(migration).toContain(
        `'{observation,${condition}}' = 'true'`
      );
    }
    expect(migration).toContain(
      'CONSTRAINT "ScannerRun_exit_code_check"'
    );
    expect(migration).toContain(
      'CONSTRAINT "ScannerRun_runtime_metadata_check"'
    );
    expect(migration).toContain(
      `("artifactMetadata" ->> 'byteSize')::numeric > 0`
    );
    expect(migration).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY "ScannerRun_attemptId_scanner_key"'
    );
    expect(migration).toContain(
      'CREATE INDEX CONCURRENTLY "AuditEvent_attemptId_idx"'
    );
    expect(migration).toContain(
      'VALIDATE CONSTRAINT "ScannerRun_runtime_metadata_check"'
    );
    expect(migration).toContain(
      'VALIDATE CONSTRAINT "AuditEvent_attempt_scope_fkey"'
    );
    expect(migration).toContain(
      'CONSTRAINT "ScannerRun_attempt_scope_fkey"'
    );
    expect(migration).toContain(
      'FOREIGN KEY ("attemptId", "tenantId", "repositoryBindingId", "scanRequestId")'
    );
    expect(migration).toContain(
      'CONSTRAINT "AuditEvent_attempt_scope_fkey"'
    );
    expect(migration).toContain(
      'FOREIGN KEY ("attemptId", "tenantId")'
    );
    expect(migration).toContain(
      'CONSTRAINT "SastScanAttempt_finalAuditEventId_fkey"'
    );
    expect(migration).toContain(
      'FOREIGN KEY ("finalAuditEventId", "id", "tenantId")'
    );
    expect(migration).toContain(
      'REFERENCES "AuditEvent"("id", "attemptId", "tenantId")'
    );
    expect(migration).toMatch(/OR COALESCE\(/);
  });

  it('keeps the deployment contract non-root, offline, bounded, and mock-free', () => {
    const contract = JSON.parse(
      readFileSync(
        resolve(
          __dirname,
          '../../../../deploy/scanner-sandbox/provisioning-contract.json'
        ),
        'utf8'
      )
    ) as Record<string, unknown>;

    expect(contract).toMatchObject({
      sandboxProvider: 'MICROVM',
      networkEgressPolicy: 'PHASE_BOUND_DENY_BY_DEFAULT',
      networkEgressPhases: {
        REPOSITORY_FETCH: {
          allowedDestinationPolicy: 'BOUND_SCM_HOST_ONLY',
          boundHostSource: 'SIGNED_REPOSITORY_BINDING',
          unboundPublicInternetEgressAllowed: false
        },
        SCANNER_EXECUTION: {
          allowedDestinationPolicy:
            'RESULT_INGRESS_AND_TELEMETRY_ONLY',
          boundScmHostAllowed: false
        }
      },
      publicInternetEgressAllowed: false,
      cloudMetadataAccessAllowed: false,
      runtimeAssetUpdateAllowed: false,
      ttlSeconds: 3960,
      ttlPolicy: {
        source: 'SIGNED_PROFILE',
        maximumExecutionSeconds: 3600,
        cleanupGraceSeconds: 60,
        hardMaximumSeconds: 3960
      },
      executionBoundary: {
        runAsNonRoot: true,
        readOnlyRootFilesystem: true,
        readOnlyRepositoryMount: '/workspace/repository',
        privateWritableOutputMount: '/workspace/output',
        workingDirectory: '/workspace/output',
        shellInterpolationAllowed: false,
        customerArgumentsAllowed: false,
        customerEnvironmentAllowed: false,
        customerExecutableConfigAllowed: false,
        customerSuppressionConfigAllowed: false,
        repositoryToolConfigDiscoveryAllowed: false,
        signedAttemptNumberRequired: true,
        signedAttemptDeadlineRequired: true,
        signedAttemptDeadlinePersistenceRequired: true,
        providerAbortSignalRequired: true,
        resourceLimitsSource: 'SIGNED_PROFILE',
        cleanupTimeoutSeconds: 60,
        orphanedAttemptReconciliationRequired: true,
        orphanedAttemptReconciliationIntervalMilliseconds: 10_000
      },
      scannerInputBoundary: {
        deepScanMount: '/workspace/repository',
        fastScanMountTemplate:
          '/workspace/selected/<preflight-inventory-sha256>',
        fastScanMaterializer: 'PLATFORM_OWNED',
        fastScanSelectionSource: 'ATTESTED_PATH_ALLOWLIST',
        fastScanContentBinding: 'PREFLIGHT_INVENTORY_DIGEST',
        fastScanReadOnly: true,
        fastScanUnselectedEntriesAllowed: false,
        scannerReceivesRepositoryRootForFastScan: false,
        preScannerProjectionAttestationRequired: true,
        projectionMismatchPolicy: 'FAIL_CLOSED'
      },
      productionMockAnalysisAllowed: false,
      scannerEntrypoints: {
        OPENGREP: {
          repositoryIgnoreFilesAllowed: false,
          inlineNosemSuppressionAllowed: false,
          versionCheckAllowed: false
        },
        TRIVY: {
          configPathSource: 'PINNED_WRAPPER_DIGEST',
          repositoryIgnoreFilesAllowed: false,
          suppressedResultsMustBeEmitted: true,
          timeoutSource: 'SIGNED_PROFILE'
        },
        SYFT: {
          configPathSource: 'PINNED_WRAPPER_DIGEST',
          repositoryConfigDiscoveryAllowed: false,
          archiveExpansionAllowed: false,
          packageManagerOrCompilerInvocationAllowed: false
        }
      },
      defaultRuntimeProvider: {
        mode: 'FAIL_CLOSED_UNTIL_LIVE_MICROVM_ADAPTER_INSTALLED'
      }
    });
  });

  it('fails closed when no live microVM adapter is installed', async () => {
    const provider = new UnavailableScannerSandboxRuntimeProvider();

    await expect(
      provider.readRepositoryManifest()
    ).rejects.toMatchObject({
      failureClass: 'RETRYABLE_INFRASTRUCTURE',
      reasonCode: 'SCANNER_SANDBOX_PROVIDER_UNAVAILABLE',
      retryAllowed: true
    });
  });
});
