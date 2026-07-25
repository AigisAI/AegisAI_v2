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
    const onlineSchema = readFileSync(
      resolve(
        __dirname,
        '../../scripts/apply-online-sast-runtime-schema.mjs'
      ),
      'utf8'
    );
    const ingressMigration = readFileSync(
      resolve(
        __dirname,
        '../../prisma/migrations/20260724180000_sast_artifact_ingress/migration.sql'
      ),
      'utf8'
    );
    const validationMigration = readFileSync(
      resolve(
        __dirname,
        '../../prisma/migrations/20260724210000_sast_artifact_validation/migration.sql'
      ),
      'utf8'
    );
    const packageJson = JSON.parse(
      readFileSync(resolve(__dirname, '../../package.json'), 'utf8')
    ) as {
      scripts: Record<string, string>;
    };

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
    expect(schema).toMatch(/schemaBundleDigest\s+String\?/);
    expect(schema).toMatch(/normalizerBundleDigest\s+String\?/);
    expect(schema).toMatch(/@@unique\(\[attemptId, scanner\]\)/);
    expect(schema).toMatch(/model SastArtifactIngestion \{/);
    expect(schema).toMatch(
      /scannerRunId\s+String\s+@unique/
    );
    expect(schema).toMatch(
      /status\s+SastArtifactIngestionStatus\s+@default\(RECEIVING\)/
    );
    expect(schema).toMatch(/envelope\s+Json\?/);

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
    expect(onlineSchema).toContain(
      "name: 'ScannerRun_exit_code_check'"
    );
    expect(onlineSchema).toContain(
      "name: 'ScannerRun_runtime_metadata_v3_check'"
    );
    expect(onlineSchema).toContain(
      `"artifactSchemaVersion" = '2.1.0'`
    );
    expect(onlineSchema).toContain(
      `"artifactSchemaVersion" = '2'`
    );
    expect(onlineSchema).toContain(
      `"artifactSchemaVersion" = '1.6'`
    );
    expect(onlineSchema).toContain(
      `"schemaBundleDigest" IS NULL`
    );
    expect(validationMigration).toContain(
      'ADD COLUMN "schemaBundleDigest" TEXT'
    );
    expect(validationMigration).toContain(
      'ADD COLUMN "normalizerBundleDigest" TEXT'
    );
    expect(validationMigration).toContain(
      'ADD COLUMN "envelope" JSONB'
    );
    expect(onlineSchema).toContain(
      `("artifactMetadata" ->> 'byteSize')::numeric > 0`
    );
    expect(onlineSchema).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "ScannerRun_attemptId_scanner_key"'
    );
    expect(onlineSchema).toContain(
      'CREATE INDEX CONCURRENTLY IF NOT EXISTS "AuditEvent_attemptId_idx"'
    );
    expect(onlineSchema).toContain('VALIDATE CONSTRAINT');
    expect(onlineSchema).toContain(
      "name: 'ScannerRun_attempt_scope_fkey'"
    );
    expect(onlineSchema).toContain(
      'FOREIGN KEY ("attemptId", "tenantId", "repositoryBindingId", "scanRequestId")'
    );
    expect(onlineSchema).toContain(
      "name: 'AuditEvent_attempt_scope_fkey'"
    );
    expect(onlineSchema).toContain(
      'FOREIGN KEY ("attemptId", "tenantId")'
    );
    expect(onlineSchema).toContain(
      "name: 'SastScanAttempt_finalAuditEventId_fkey'"
    );
    expect(onlineSchema).toContain(
      'FOREIGN KEY ("finalAuditEventId", "id", "tenantId")'
    );
    expect(onlineSchema).toContain(
      'REFERENCES "AuditEvent"("id", "attemptId", "tenantId")'
    );
    expect(onlineSchema).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "ScannerRun_ingress_scope_key"'
    );
    expect(onlineSchema).toContain(
      "name: 'SastArtifactIngestion_scanner_run_scope_fkey'"
    );
    expect(ingressMigration).toContain(
      'CONSTRAINT "SastArtifactIngestion_identity_check"'
    );
    expect(ingressMigration).toContain(
      'CONSTRAINT "SastArtifactIngestion_lifecycle_check"'
    );
    expect(ingressMigration).not.toContain(
      'DROP CONSTRAINT IF EXISTS "ScannerRun_runtime_metadata_check"'
    );
    expect(onlineSchema).toContain(
      "name: 'ScannerRun_runtime_metadata_v2_check'"
    );
    expect(onlineSchema).toContain(
      "replacement: 'ScannerRun_runtime_metadata_v3_check'"
    );
    expect(onlineSchema).toContain(
      'superseded constraint removed:'
    );
    expect(ingressMigration).not.toMatch(
      /^\s*CREATE (?:UNIQUE )?INDEX CONCURRENTLY/m
    );
    expect(validationMigration).not.toMatch(
      /^\s*CREATE (?:UNIQUE )?INDEX CONCURRENTLY/m
    );
    expect(onlineSchema).toMatch(/OR COALESCE\(/);
    expect(onlineSchema).toContain(' NOT VALID');
    expect(onlineSchema).toContain('DROP INDEX CONCURRENTLY IF EXISTS');
    expect(migration).not.toMatch(
      /^\s*CREATE (?:UNIQUE )?INDEX CONCURRENTLY/m
    );
    expect(packageJson.scripts['prisma:migrate:deploy']).toBe(
      'prisma migrate deploy --schema prisma/schema.prisma && corepack pnpm prisma:online-schema'
    );
    expect(packageJson.scripts['prisma:online-schema']).toBe(
      'node scripts/apply-online-sast-runtime-schema.mjs'
    );
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
      resultIngress: {
        method: 'PUT',
        mediaType: 'application/octet-stream',
        directAuthorizedMtlsRequired: true,
        singleSpiffeUriSanRequired: true,
        lowercaseSpiffeTrustDomainRequired: true,
        spiffePathSegmentPattern: '[A-Za-z0-9._-]+',
        spiffePercentEncodingAllowed: false,
        spiffeRelativePathSegmentsAllowed: false,
        forwardedIdentityHeadersTrusted: false,
        attemptStageRequired: 'SCANNING',
        scannerRunStatusRequired: 'RUNNING',
        oneImmutableObjectPerScannerRun: true,
        readRouteAllowed: false,
        responseObjectKeyAllowed: false,
        acceptedTransportState: 'PENDING_VALIDATION',
        defaultObjectStoreProvider:
          'FAIL_CLOSED_UNTIL_DATA_SECURITY_ADAPTER_INSTALLED',
        artifactValidation: {
          version: 'sast-artifact-validation-v1',
          mode: 'STREAMING_BOUNDED_TEE',
          maximumJsonDepth: 64,
          maximumObjectKeys: 4096,
          maximumStringBytes: 4096,
          maximumCoordinateAttestationLines: 5_000_000,
          transportChunkInvariant: true,
          duplicateKeysAllowed: false,
          utf8BomAllowed: false,
          schemas: {
            OPENGREP_SARIF: '2.1.0',
            TRIVY_JSON: '2',
            CYCLONEDX_JSON: '1.6'
          },
          exactScannerArtifactRefBindingRequired: true,
          pinnedEnumsRequired: true,
          independentTransportAndValidatorDigestRequired: true,
          coordinateAttestationRequiredForLocations: true,
          defaultCoordinateAttestationProvider: 'FAIL_CLOSED',
          deterministicReasonOrderingRequired: true,
          rawPayloadInValidationMetadataAllowed: false,
          finalDispositionOwner: 'T031_QUARANTINE'
        }
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
