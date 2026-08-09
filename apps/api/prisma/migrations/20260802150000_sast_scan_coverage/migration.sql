-- Applying this migration alone does not create the two existing-table scope
-- indexes or their dependent coverage-record foreign keys. Run
-- apps/api/scripts/apply-online-sast-runtime-schema.mjs afterward to create
-- "SastArtifactDispositionDecision_coverage_scope_key" and
-- "SastFindingCorrelationSource_coverage_scope_key" concurrently, then add
-- and validate the scanner, ingestion, disposition, and correlation-source
-- scope foreign keys on "SastScannerCoverageRecord". The scanner and ingestion
-- keys depend on indexes that are also owned by the mandatory online step.

CREATE TYPE "SastScanCoverageState" AS ENUM (
  'PENDING',
  'COMPLETE',
  'PARTIAL',
  'FAILED'
);

CREATE TABLE "SastScanCoverageDecision" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "correlationBatchId" TEXT NOT NULL,
  "lifecycleContextKey" TEXT NOT NULL,
  "targetRef" TEXT NOT NULL,
  "commitSha" TEXT NOT NULL,
  "lane" "ScanLane" NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "canonicalScanKey" TEXT NOT NULL,
  "planDigest" TEXT NOT NULL,
  "scannerSetDigest" TEXT NOT NULL,
  "correlationSourceSetDigest" TEXT NOT NULL,
  "state" "SastScanCoverageState" NOT NULL,
  "requiredScanners" JSONB NOT NULL,
  "optionalScanners" JSONB NOT NULL,
  "missingRequiredScanners" JSONB NOT NULL,
  "pendingRequiredScanners" JSONB NOT NULL,
  "failedRequiredScanners" JSONB NOT NULL,
  "achievedRequiredCapabilities" JSONB NOT NULL,
  "missingRequiredCapabilities" JSONB NOT NULL,
  "duplicateScanners" JSONB NOT NULL,
  "optionalIncompleteScanners" JSONB NOT NULL,
  "reasonCodes" JSONB NOT NULL,
  "recordsDigest" TEXT NOT NULL,
  "authority" JSONB NOT NULL,
  "decision" JSONB NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "decidedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastScanCoverageDecision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastScanCoverageDecision_contract_check" CHECK (
    "id" ~ '^sast-coverage://[a-f0-9]{64}$'
    AND "correlationBatchId" ~ '^finding-correlation://[a-f0-9]{64}$'
    AND "lifecycleContextKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "commitSha" ~ '^[a-f0-9]{40}([a-f0-9]{24})?$'
    AND "profileId" IN ('JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1')
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "canonicalScanKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "planDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "scannerSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "correlationSourceSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "recordsDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "decisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND jsonb_typeof("requiredScanners") = 'array'
    AND jsonb_typeof("optionalScanners") = 'array'
    AND jsonb_typeof("missingRequiredScanners") = 'array'
    AND jsonb_typeof("pendingRequiredScanners") = 'array'
    AND jsonb_typeof("failedRequiredScanners") = 'array'
    AND jsonb_typeof("achievedRequiredCapabilities") = 'array'
    AND jsonb_typeof("missingRequiredCapabilities") = 'array'
    AND jsonb_typeof("duplicateScanners") = 'array'
    AND jsonb_typeof("optionalIncompleteScanners") = 'array'
    AND jsonb_typeof("reasonCodes") = 'array'
    AND jsonb_typeof("decision") = 'object'
    AND "authority" = '{
      "coverageCalculationAuthority": true,
      "scannerExecutionAuthority": false,
      "artifactAcceptanceAuthority": false,
      "correlationAuthority": false,
      "lifecycleAuthority": false,
      "evidenceAuthority": false,
      "policyAuthority": false,
      "publicationAuthority": false,
      "aiPayloadEligible": false
    }'::jsonb
  )
);

CREATE TABLE "SastScannerCoverageRecord" (
  "id" TEXT NOT NULL,
  "coverageDecisionId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "correlationBatchId" TEXT NOT NULL,
  "scannerRunId" TEXT,
  "artifactIngestionId" TEXT,
  "dispositionDecisionId" TEXT,
  "correlationSourceId" TEXT,
  "scanner" "ScannerKind" NOT NULL,
  "required" BOOLEAN NOT NULL,
  "executionStatus" TEXT NOT NULL,
  "authoritativeCapabilities" JSONB NOT NULL,
  "requiredCapabilities" JSONB NOT NULL,
  "achievedCapabilities" JSONB NOT NULL,
  "scannerVersion" TEXT,
  "scannerImageDigest" TEXT,
  "wrapperDigest" TEXT,
  "ruleBundleDigest" TEXT,
  "vulnerabilityDatabaseDigest" TEXT,
  "schemaBundleDigest" TEXT,
  "normalizerBundleDigest" TEXT,
  "artifactEnvelopeDigest" TEXT,
  "artifactDigest" TEXT,
  "dispositionDecisionDigest" TEXT,
  "observationBatchId" TEXT,
  "correlationSourceBindingDigest" TEXT,
  "artifactAccepted" BOOLEAN NOT NULL,
  "normalizationEligible" BOOLEAN NOT NULL,
  "findingObservationRequired" BOOLEAN NOT NULL,
  "findingObservationClosed" BOOLEAN NOT NULL,
  "reasonCodes" JSONB NOT NULL,
  "record" JSONB NOT NULL,
  "recordDigest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastScannerCoverageRecord_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastScannerCoverageRecord_contract_check" CHECK (
    "id" ~ '^sast-scanner-coverage://[a-f0-9]{64}$'
    AND "coverageDecisionId" ~ '^sast-coverage://[a-f0-9]{64}$'
    AND "correlationBatchId" ~ '^finding-correlation://[a-f0-9]{64}$'
    AND "scanner" IN ('OPENGREP', 'TRIVY', 'SYFT')
    AND "executionStatus" IN (
      'NOT_STARTED', 'PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED',
      'TIMED_OUT', 'QUARANTINED', 'SKIPPED_BY_POLICY', 'KILLED'
    )
    AND jsonb_typeof("authoritativeCapabilities") = 'array'
    AND jsonb_typeof("requiredCapabilities") = 'array'
    AND jsonb_typeof("achievedCapabilities") = 'array'
    AND jsonb_typeof("reasonCodes") = 'array'
    AND jsonb_typeof("record") = 'object'
    AND "recordDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND ("scannerImageDigest" IS NULL OR "scannerImageDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND ("wrapperDigest" IS NULL OR "wrapperDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND ("ruleBundleDigest" IS NULL OR "ruleBundleDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND ("vulnerabilityDatabaseDigest" IS NULL OR "vulnerabilityDatabaseDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND ("schemaBundleDigest" IS NULL OR "schemaBundleDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND ("normalizerBundleDigest" IS NULL OR "normalizerBundleDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND ("artifactEnvelopeDigest" IS NULL OR "artifactEnvelopeDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND ("artifactDigest" IS NULL OR "artifactDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND ("dispositionDecisionDigest" IS NULL OR "dispositionDecisionDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND ("observationBatchId" IS NULL OR "observationBatchId" ~ '^finding-observation://[a-f0-9]{64}$')
    AND ("correlationSourceBindingDigest" IS NULL OR "correlationSourceBindingDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND (
      ("executionStatus" = 'NOT_STARTED'
        AND "scannerRunId" IS NULL
        AND "artifactIngestionId" IS NULL
        AND "dispositionDecisionId" IS NULL
        AND "correlationSourceId" IS NULL)
      OR ("executionStatus" <> 'NOT_STARTED' AND "scannerRunId" IS NOT NULL)
    )
    AND (
      "artifactIngestionId" IS NOT NULL
      OR (
        "artifactEnvelopeDigest" IS NULL
        AND "artifactDigest" IS NULL
        AND "dispositionDecisionId" IS NULL
        AND "dispositionDecisionDigest" IS NULL
        AND "artifactAccepted" = false
        AND "normalizationEligible" = false
      )
    )
    AND (
      "dispositionDecisionId" IS NOT NULL
      OR "dispositionDecisionDigest" IS NULL
    )
    AND (
      "correlationSourceId" IS NOT NULL
      OR (
        "observationBatchId" IS NULL
        AND "correlationSourceBindingDigest" IS NULL
      )
    )
  )
);

CREATE TABLE "SastExternalPublicationDecision" (
  "id" TEXT NOT NULL,
  "coverageDecisionId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "coverageState" "SastScanCoverageState" NOT NULL,
  "externalCommentAllowed" BOOLEAN NOT NULL DEFAULT false,
  "blockingStatusAllowed" BOOLEAN NOT NULL DEFAULT false,
  "aiAdvisoryAllowed" BOOLEAN NOT NULL DEFAULT false,
  "lifecycleMutationAllowed" BOOLEAN NOT NULL DEFAULT false,
  "latestTargetAuthority" TEXT NOT NULL,
  "staleStatus" TEXT NOT NULL,
  "comparabilityStatus" TEXT NOT NULL,
  "reasonCodes" JSONB NOT NULL,
  "decision" JSONB NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "decidedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastExternalPublicationDecision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastExternalPublicationDecision_contract_check" CHECK (
    "id" ~ '^sast-publication://[a-f0-9]{64}$'
    AND "coverageDecisionId" ~ '^sast-coverage://[a-f0-9]{64}$'
    AND "externalCommentAllowed" = false
    AND "blockingStatusAllowed" = false
    AND "aiAdvisoryAllowed" = false
    AND "lifecycleMutationAllowed" = false
    AND "latestTargetAuthority" = 'UNAVAILABLE'
    AND "staleStatus" = 'UNKNOWN'
    AND "comparabilityStatus" = 'UNKNOWN'
    AND jsonb_typeof("reasonCodes") = 'array'
    AND "reasonCodes" @> '[
      "LATEST_TARGET_AUTHORITY_UNAVAILABLE",
      "EXTERNAL_PUBLICATION_FAIL_CLOSED"
    ]'::jsonb
    AND jsonb_typeof("decision") = 'object'
    AND "decisionDigest" ~ '^sha256:[a-f0-9]{64}$'
  )
);

CREATE UNIQUE INDEX "SastScanCoverageDecision_correlationBatchId_key"
  ON "SastScanCoverageDecision"("correlationBatchId");
CREATE UNIQUE INDEX "SastScanCoverageDecision_decisionDigest_key"
  ON "SastScanCoverageDecision"("decisionDigest");
CREATE UNIQUE INDEX "SastScanCoverageDecision_scope_key"
  ON "SastScanCoverageDecision"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId"
  );
CREATE UNIQUE INDEX "SastScanCoverageDecision_record_scope_key"
  ON "SastScanCoverageDecision"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId",
    "correlationBatchId"
  );
CREATE UNIQUE INDEX "SastScanCoverageDecision_correlation_scope_key"
  ON "SastScanCoverageDecision"(
    "correlationBatchId", "tenantId", "repositoryBindingId", "scanRequestId",
    "attemptId"
  );
CREATE UNIQUE INDEX "SastScanCoverageDecision_attempt_key"
  ON "SastScanCoverageDecision"(
    "tenantId", "repositoryBindingId", "scanRequestId", "attemptId"
  );
CREATE INDEX "SastScanCoverageDecision_context_decided_idx"
  ON "SastScanCoverageDecision"(
    "tenantId", "repositoryBindingId", "lifecycleContextKey", "decidedAt"
  );
CREATE INDEX "SastScanCoverageDecision_state_decided_idx"
  ON "SastScanCoverageDecision"("state", "decidedAt");

CREATE UNIQUE INDEX "SastScannerCoverageRecord_recordDigest_key"
  ON "SastScannerCoverageRecord"("recordDigest");
CREATE UNIQUE INDEX "SastScannerCoverageRecord_decision_scanner_key"
  ON "SastScannerCoverageRecord"("coverageDecisionId", "scanner");
CREATE INDEX "SastScannerCoverageRecord_scope_status_idx"
  ON "SastScannerCoverageRecord"(
    "tenantId", "scanRequestId", "scanner", "executionStatus"
  );
CREATE INDEX "SastScannerCoverageRecord_scannerRunId_idx"
  ON "SastScannerCoverageRecord"("scannerRunId");
CREATE INDEX "SastScannerCoverageRecord_artifactIngestionId_idx"
  ON "SastScannerCoverageRecord"("artifactIngestionId");
CREATE INDEX "SastScannerCoverageRecord_dispositionDecisionId_idx"
  ON "SastScannerCoverageRecord"("dispositionDecisionId");
CREATE INDEX "SastScannerCoverageRecord_correlationSourceId_idx"
  ON "SastScannerCoverageRecord"("correlationSourceId");

CREATE UNIQUE INDEX "SastExternalPublicationDecision_coverageDecisionId_key"
  ON "SastExternalPublicationDecision"("coverageDecisionId");
CREATE UNIQUE INDEX "SastExternalPublicationDecision_decisionDigest_key"
  ON "SastExternalPublicationDecision"("decisionDigest");
CREATE UNIQUE INDEX "SastExternalPublicationDecision_coverage_scope_key"
  ON "SastExternalPublicationDecision"(
    "coverageDecisionId", "tenantId", "repositoryBindingId", "scanRequestId",
    "attemptId"
  );
CREATE INDEX "SastExternalPublicationDecision_scope_decided_idx"
  ON "SastExternalPublicationDecision"(
    "tenantId", "repositoryBindingId", "decidedAt"
  );

ALTER TABLE "SastScanCoverageDecision"
  ADD CONSTRAINT "SastScanCoverageDecision_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanCoverageDecision"
  ADD CONSTRAINT "SastScanCoverageDecision_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanCoverageDecision"
  ADD CONSTRAINT "SastScanCoverageDecision_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanCoverageDecision"
  ADD CONSTRAINT "SastScanCoverageDecision_attempt_scope_fkey"
  FOREIGN KEY ("attemptId", "tenantId", "repositoryBindingId", "scanRequestId")
  REFERENCES "SastScanAttempt"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId"
  ) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanCoverageDecision"
  ADD CONSTRAINT "SastScanCoverageDecision_correlation_scope_fkey"
  FOREIGN KEY (
    "correlationBatchId", "tenantId", "repositoryBindingId", "scanRequestId",
    "attemptId"
  ) REFERENCES "SastFindingCorrelationBatch"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId"
  ) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastScannerCoverageRecord"
  ADD CONSTRAINT "SastScannerCoverageRecord_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScannerCoverageRecord"
  ADD CONSTRAINT "SastScannerCoverageRecord_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScannerCoverageRecord"
  ADD CONSTRAINT "SastScannerCoverageRecord_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScannerCoverageRecord"
  ADD CONSTRAINT "SastScannerCoverageRecord_attempt_scope_fkey"
  FOREIGN KEY ("attemptId", "tenantId", "repositoryBindingId", "scanRequestId")
  REFERENCES "SastScanAttempt"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId"
  ) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScannerCoverageRecord"
  ADD CONSTRAINT "SastScannerCoverageRecord_decision_scope_fkey"
  FOREIGN KEY (
    "coverageDecisionId", "tenantId", "repositoryBindingId", "scanRequestId",
    "attemptId", "correlationBatchId"
  ) REFERENCES "SastScanCoverageDecision"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId",
    "correlationBatchId"
  ) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastExternalPublicationDecision"
  ADD CONSTRAINT "SastExternalPublicationDecision_coverage_scope_fkey"
  FOREIGN KEY (
    "coverageDecisionId", "tenantId", "repositoryBindingId", "scanRequestId",
    "attemptId"
  ) REFERENCES "SastScanCoverageDecision"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId"
  ) ON DELETE CASCADE ON UPDATE CASCADE;
