CREATE TYPE "SastFindingCapability" AS ENUM (
  'SAST',
  'SECRET_DETECTION',
  'DEPENDENCY_VULNERABILITY',
  'IAC_MISCONFIGURATION'
);

CREATE TYPE "SastFindingLifecycleStatus" AS ENUM (
  'OPEN',
  'FIXED'
);

CREATE TYPE "SastFindingLifecycleEventKind" AS ENUM (
  'CREATED',
  'RENAMED',
  'FIXED',
  'REOPENED'
);

-- Rolling compatibility: legacy finding writers can continue writing rows
-- without T037 metadata. The mandatory online-schema step installs and
-- validates the conditional metadata constraint and scope index.
ALTER TABLE "NormalizedFinding"
  ALTER COLUMN "filePath" DROP NOT NULL,
  ALTER COLUMN "lineStart" DROP NOT NULL,
  ADD COLUMN "sastCapability" "SastFindingCapability",
  ADD COLUMN "sastFingerprintVersion" TEXT,
  ADD COLUMN "sastStableFingerprint" TEXT,
  ADD COLUMN "sastFingerprintDecisionDigest" TEXT,
  ADD COLUMN "sastLineageId" TEXT,
  ADD COLUMN "sastObservationBatchId" TEXT,
  ADD COLUMN "sastOccurrenceOrdinal" INTEGER;

CREATE TABLE "SastFindingLineage" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "capability" "SastFindingCapability" NOT NULL,
  "fingerprintVersion" TEXT NOT NULL,
  "firstStableFingerprint" TEXT NOT NULL,
  "firstObservedAt" TIMESTAMP(3) NOT NULL,
  "lastObservedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "SastFindingLineage_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingLineage_identity_check" CHECK (
    "id" ~ '^finding-lineage://[a-f0-9]{64}$'
    AND "fingerprintVersion" = 'sast-fingerprint-v1'
    AND "firstStableFingerprint" ~ '^sha256:[a-f0-9]{64}$'
    AND "lastObservedAt" >= "firstObservedAt"
  )
);

CREATE TABLE "SastFindingIdentityAlias" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "lineageId" TEXT NOT NULL,
  "capability" "SastFindingCapability" NOT NULL,
  "fingerprintVersion" TEXT NOT NULL,
  "stableFingerprint" TEXT NOT NULL,
  "normalizedPath" TEXT NOT NULL,
  "renameAttestationDigest" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastFindingIdentityAlias_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingIdentityAlias_identity_check" CHECK (
    "id" ~ '^finding-alias://[a-f0-9]{64}$'
    AND "fingerprintVersion" = 'sast-fingerprint-v1'
    AND "stableFingerprint" ~ '^sha256:[a-f0-9]{64}$'
    AND octet_length("normalizedPath") <= 4096
    AND "normalizedPath" !~ '[[:cntrl:]]'
    AND (
      "normalizedPath" = ''
      OR (
        "normalizedPath" NOT LIKE '/%'
        AND "normalizedPath" !~ '^[A-Za-z]:'
        AND strpos("normalizedPath", chr(92)) = 0
        AND "normalizedPath" NOT LIKE '%//%'
        AND "normalizedPath" !~ '(^|/)[.]{1,2}(/|$)'
      )
    )
    AND (
      "renameAttestationDigest" IS NULL
      OR "renameAttestationDigest" ~ '^sha256:[a-f0-9]{64}$'
    )
  )
);

CREATE TABLE "SastFindingObservationBatch" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "scannerRunId" TEXT NOT NULL,
  "lifecycleContextKey" TEXT NOT NULL,
  "targetRef" TEXT NOT NULL,
  "commitSha" TEXT NOT NULL,
  "lane" "ScanLane" NOT NULL,
  "scanner" "ScannerKind" NOT NULL,
  "capabilities" JSONB NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "canonicalScanKey" TEXT NOT NULL,
  "planDigest" TEXT NOT NULL,
  "sourceIdentityBatchDigest" TEXT NOT NULL,
  "renameAttestationDigest" TEXT,
  "findingCount" INTEGER NOT NULL,
  "distinctFingerprintCount" INTEGER NOT NULL,
  "createdLineageCount" INTEGER NOT NULL,
  "exactMatchCount" INTEGER NOT NULL,
  "renamedMatchCount" INTEGER NOT NULL,
  "observedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastFindingObservationBatch_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingObservationBatch_contract_check" CHECK (
    "id" ~ '^finding-observation://[a-f0-9]{64}$'
    AND "lifecycleContextKey" ~ '^sha256:[a-f0-9]{64}$'
    AND octet_length("targetRef") BETWEEN 1 AND 2048
    AND "targetRef" !~ '[[:cntrl:]]'
    AND "commitSha" ~ '^[a-f0-9]{40}([a-f0-9]{24})?$'
    AND "scanner" IN ('OPENGREP', 'TRIVY')
    AND "profileId" IN (
      'JAVA_FAST_V1',
      'JAVA_DEEP_V1',
      'COMMON_DEEP_V1'
    )
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "canonicalScanKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "planDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "sourceIdentityBatchDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND (
      "renameAttestationDigest" IS NULL
      OR "renameAttestationDigest" ~ '^sha256:[a-f0-9]{64}$'
    )
    AND jsonb_typeof("capabilities") = 'array'
    AND jsonb_array_length("capabilities") BETWEEN 0 AND 4
    AND "capabilities" <@ '[
      "SAST",
      "SECRET_DETECTION",
      "DEPENDENCY_VULNERABILITY",
      "IAC_MISCONFIGURATION"
    ]'::jsonb
    AND "findingCount" BETWEEN 0 AND 25000
    AND "distinctFingerprintCount" BETWEEN 0 AND "findingCount"
    AND "createdLineageCount" >= 0
    AND "exactMatchCount" >= 0
    AND "renamedMatchCount" >= 0
    AND "createdLineageCount" + "exactMatchCount" + "renamedMatchCount"
      = "distinctFingerprintCount"
  )
);

CREATE TABLE "SastFindingOccurrence" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "scannerRunId" TEXT NOT NULL,
  "observationBatchId" TEXT NOT NULL,
  "lineageId" TEXT NOT NULL,
  "normalizedFindingId" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "capability" "SastFindingCapability" NOT NULL,
  "fingerprintVersion" TEXT NOT NULL,
  "stableFingerprint" TEXT NOT NULL,
  "fingerprintDecisionDigest" TEXT NOT NULL,
  "sourceFinding" JSONB NOT NULL,
  "observedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastFindingOccurrence_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingOccurrence_contract_check" CHECK (
    "id" ~ '^finding-occurrence://[a-f0-9]{64}$'
    AND "lineageId" ~ '^finding-lineage://[a-f0-9]{64}$'
    AND "ordinal" BETWEEN 0 AND 24999
    AND "fingerprintVersion" = 'sast-fingerprint-v1'
    AND "stableFingerprint" ~ '^sha256:[a-f0-9]{64}$'
    AND "fingerprintDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND jsonb_typeof("sourceFinding") = 'object'
    AND COALESCE(
      (
        jsonb_typeof("sourceFinding" -> 'fingerprint') = 'object'
        AND "sourceFinding" ->> 'capability' = "capability"::text
        AND "sourceFinding" #>> '{fingerprint,version}'
          = "fingerprintVersion"
        AND "sourceFinding" #>> '{fingerprint,stableFingerprint}'
          = "stableFingerprint"
        AND "sourceFinding" #>> '{fingerprint,decisionDigest}'
          = "fingerprintDecisionDigest"
        AND "sourceFinding" ->> 'durablePersistenceAllowed' = 'true'
      ),
      false
    )
  )
);

CREATE TABLE "SastFindingLifecycleState" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "lineageId" TEXT NOT NULL,
  "lifecycleContextKey" TEXT NOT NULL,
  "targetRef" TEXT NOT NULL,
  "status" "SastFindingLifecycleStatus" NOT NULL DEFAULT 'OPEN',
  "revision" INTEGER NOT NULL DEFAULT 1,
  "lastObservedBatchId" TEXT,
  "lastObservedScanRequestId" TEXT,
  "lastObservedCommitSha" TEXT,
  "lastObservedAt" TIMESTAMP(3),
  "lastReconciliationSequence" INTEGER NOT NULL DEFAULT 0,
  "fixedAt" TIMESTAMP(3),
  "reopenedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "SastFindingLifecycleState_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingLifecycleState_contract_check" CHECK (
    "id" ~ '^finding-state://[a-f0-9]{64}$'
    AND "lineageId" ~ '^finding-lineage://[a-f0-9]{64}$'
    AND "lifecycleContextKey" ~ '^sha256:[a-f0-9]{64}$'
    AND octet_length("targetRef") BETWEEN 1 AND 2048
    AND "targetRef" !~ '[[:cntrl:]]'
    AND "revision" >= 1
    AND "lastReconciliationSequence" >= 0
    AND (
      (
        "lastObservedBatchId" IS NULL
        AND "lastObservedScanRequestId" IS NULL
        AND "lastObservedCommitSha" IS NULL
        AND "lastObservedAt" IS NULL
      )
      OR (
        "lastObservedBatchId" ~ '^finding-observation://[a-f0-9]{64}$'
        AND char_length("lastObservedScanRequestId") BETWEEN 1 AND 2048
        AND "lastObservedCommitSha" ~ '^[a-f0-9]{40}([a-f0-9]{24})?$'
        AND "lastObservedAt" IS NOT NULL
      )
    )
    AND (
      ("status" = 'OPEN' AND "fixedAt" IS NULL)
      OR ("status" = 'FIXED' AND "fixedAt" IS NOT NULL)
    )
  )
);

CREATE TABLE "SastFindingLifecycleReconciliation" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "lifecycleContextKey" TEXT NOT NULL,
  "sequence" INTEGER NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "coverageDecision" JSONB NOT NULL,
  "coverageDecisionDigest" TEXT NOT NULL,
  "eligibleLineageCount" INTEGER NOT NULL,
  "observedLineageCount" INTEGER NOT NULL,
  "fixedCount" INTEGER NOT NULL,
  "reopenedCount" INTEGER NOT NULL,
  "unchangedOpenCount" INTEGER NOT NULL,
  "unchangedFixedCount" INTEGER NOT NULL,
  "reconciledAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastFindingLifecycleReconciliation_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingLifecycleReconciliation_contract_check" CHECK (
    "id" ~ '^finding-reconciliation://[a-f0-9]{64}$'
    AND "lifecycleContextKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "sequence" > 0
    AND "profileId" IN (
      'JAVA_FAST_V1',
      'JAVA_DEEP_V1',
      'COMMON_DEEP_V1'
    )
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "coverageDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND jsonb_typeof("coverageDecision") = 'object'
    AND COALESCE(
      (
        "coverageDecision" ->> 'version'
          = 'sast-finding-lifecycle-coverage-v1'
        AND "coverageDecision" ->> 'tenantId' = "tenantId"
        AND "coverageDecision" ->> 'repositoryBindingId'
          = "repositoryBindingId"
        AND "coverageDecision" ->> 'scanRequestId' = "scanRequestId"
        AND "coverageDecision" ->> 'attemptId' = "attemptId"
        AND "coverageDecision" ->> 'lifecycleContextKey'
          = "lifecycleContextKey"
        AND "coverageDecision" ->> 'profileId' = "profileId"
        AND "coverageDecision" ->> 'profileDigest' = "profileDigest"
        AND "coverageDecision" ->> 'state' = 'COMPLETE'
        AND "coverageDecision" ->> 'stale' = 'false'
        AND "coverageDecision" ->> 'comparable' = 'true'
        AND ("coverageDecision" ->> 'sequence')::integer = "sequence"
        AND "coverageDecision" ->> 'decisionDigest'
          = "coverageDecisionDigest"
        AND jsonb_typeof(
          "coverageDecision" -> 'eligibleLineageIds'
        ) = 'array'
        AND jsonb_array_length(
          "coverageDecision" -> 'eligibleLineageIds'
        ) = "eligibleLineageCount"
        AND jsonb_typeof(
          "coverageDecision" -> 'expectedObservationBatchDigests'
        ) = 'array'
        AND jsonb_array_length(
          "coverageDecision" -> 'expectedObservationBatchDigests'
        ) BETWEEN 1 AND 16
      ),
      false
    )
    AND "eligibleLineageCount" BETWEEN 0 AND 25000
    AND "observedLineageCount" BETWEEN 0 AND "eligibleLineageCount"
    AND "fixedCount" >= 0
    AND "reopenedCount" >= 0
    AND "unchangedOpenCount" >= 0
    AND "unchangedFixedCount" >= 0
    AND "fixedCount" + "reopenedCount"
      + "unchangedOpenCount" + "unchangedFixedCount"
      = "eligibleLineageCount"
    AND "reopenedCount" + "unchangedOpenCount"
      = "observedLineageCount"
    AND "fixedCount" + "unchangedFixedCount"
      = "eligibleLineageCount" - "observedLineageCount"
  )
);

CREATE TABLE "SastFindingLifecycleEvent" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "lineageId" TEXT NOT NULL,
  "lifecycleStateId" TEXT NOT NULL,
  "lifecycleContextKey" TEXT NOT NULL,
  "kind" "SastFindingLifecycleEventKind" NOT NULL,
  "previousStatus" "SastFindingLifecycleStatus",
  "nextStatus" "SastFindingLifecycleStatus" NOT NULL,
  "revision" INTEGER NOT NULL,
  "observationBatchId" TEXT,
  "reconciliationId" TEXT,
  "renameAttestationDigest" TEXT,
  "occurredAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastFindingLifecycleEvent_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingLifecycleEvent_transition_check" CHECK (
    "id" ~ '^finding-event://[a-f0-9]{64}$'
    AND "lineageId" ~ '^finding-lineage://[a-f0-9]{64}$'
    AND "lifecycleStateId" ~ '^finding-state://[a-f0-9]{64}$'
    AND "lifecycleContextKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "revision" >= 1
    AND (
      (
        "kind" = 'CREATED'
        AND "revision" = 1
        AND "previousStatus" IS NULL
        AND "nextStatus" = 'OPEN'
        AND "observationBatchId" IS NOT NULL
        AND "reconciliationId" IS NULL
        AND "renameAttestationDigest" IS NULL
      )
      OR (
        "kind" = 'RENAMED'
        AND "revision" > 1
        AND "previousStatus" = "nextStatus"
        AND "observationBatchId" IS NOT NULL
        AND "reconciliationId" IS NULL
        AND "renameAttestationDigest" ~ '^sha256:[a-f0-9]{64}$'
      )
      OR (
        "kind" = 'FIXED'
        AND "revision" > 1
        AND "previousStatus" = 'OPEN'
        AND "nextStatus" = 'FIXED'
        AND "observationBatchId" IS NULL
        AND "reconciliationId" IS NOT NULL
        AND "renameAttestationDigest" IS NULL
      )
      OR (
        "kind" = 'REOPENED'
        AND "revision" > 1
        AND "previousStatus" = 'FIXED'
        AND "nextStatus" = 'OPEN'
        AND "observationBatchId" IS NULL
        AND "reconciliationId" IS NOT NULL
        AND "renameAttestationDigest" IS NULL
      )
    )
    AND (
      "observationBatchId" IS NULL
      OR "observationBatchId" ~ '^finding-observation://[a-f0-9]{64}$'
    )
    AND (
      "reconciliationId" IS NULL
      OR "reconciliationId" ~ '^finding-reconciliation://[a-f0-9]{64}$'
    )
  )
);

CREATE UNIQUE INDEX "SastFindingLineage_scope_key"
  ON "SastFindingLineage"("id", "tenantId", "repositoryBindingId");
CREATE UNIQUE INDEX "SastFindingLineage_identity_scope_key"
  ON "SastFindingLineage"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "capability",
    "fingerprintVersion"
  );
CREATE INDEX "SastFindingLineage_tenantId_repositoryBindingId_capability_idx"
  ON "SastFindingLineage"("tenantId", "repositoryBindingId", "capability");
CREATE INDEX "SastFindingLineage_lastObservedAt_idx"
  ON "SastFindingLineage"("lastObservedAt");

CREATE UNIQUE INDEX "SastFindingIdentityAlias_fingerprint_key"
  ON "SastFindingIdentityAlias"(
    "tenantId",
    "repositoryBindingId",
    "capability",
    "fingerprintVersion",
    "stableFingerprint"
  );
CREATE INDEX "SastFindingIdentityAlias_lineageId_idx"
  ON "SastFindingIdentityAlias"("lineageId");
CREATE INDEX "SastFindingIdentityAlias_renameAttestationDigest_idx"
  ON "SastFindingIdentityAlias"("renameAttestationDigest");

CREATE UNIQUE INDEX "SastFindingObservationBatch_source_digest_key"
  ON "SastFindingObservationBatch"("tenantId", "sourceIdentityBatchDigest");
CREATE UNIQUE INDEX "SastFindingObservationBatch_scanner_run_key"
  ON "SastFindingObservationBatch"("tenantId", "scannerRunId");
CREATE UNIQUE INDEX "SastFindingObservationBatch_event_scope_key"
  ON "SastFindingObservationBatch"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey"
  );
CREATE UNIQUE INDEX "SastFindingObservationBatch_scope_key"
  ON "SastFindingObservationBatch"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId",
    "scannerRunId"
  );
CREATE INDEX "SastFindingObservationBatch_context_observed_idx"
  ON "SastFindingObservationBatch"(
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey",
    "observedAt"
  );
CREATE INDEX "SastFindingObservationBatch_scanRequestId_idx"
  ON "SastFindingObservationBatch"("scanRequestId");

CREATE UNIQUE INDEX "SastFindingOccurrence_normalizedFindingId_key"
  ON "SastFindingOccurrence"("normalizedFindingId");
CREATE UNIQUE INDEX "SastFindingOccurrence_batch_ordinal_key"
  ON "SastFindingOccurrence"("observationBatchId", "ordinal");
CREATE UNIQUE INDEX "SastFindingOccurrence_normalized_scope_key"
  ON "SastFindingOccurrence"(
    "normalizedFindingId",
    "tenantId",
    "scanRequestId",
    "scannerRunId"
  );
CREATE INDEX "SastFindingOccurrence_lineage_observed_idx"
  ON "SastFindingOccurrence"(
    "tenantId",
    "repositoryBindingId",
    "lineageId",
    "observedAt"
  );
CREATE INDEX "SastFindingOccurrence_scanRequestId_capability_idx"
  ON "SastFindingOccurrence"("scanRequestId", "capability");

CREATE UNIQUE INDEX "SastFindingLifecycleState_context_lineage_key"
  ON "SastFindingLifecycleState"(
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey",
    "lineageId"
  );
CREATE UNIQUE INDEX "SastFindingLifecycleState_scope_key"
  ON "SastFindingLifecycleState"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "lineageId",
    "lifecycleContextKey"
  );
CREATE INDEX "SastFindingLifecycleState_context_status_idx"
  ON "SastFindingLifecycleState"(
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey",
    "status"
  );

CREATE UNIQUE INDEX "SastFindingLifecycleReconciliation_decision_digest_key"
  ON "SastFindingLifecycleReconciliation"("coverageDecisionDigest");
CREATE UNIQUE INDEX "SastFindingLifecycleReconciliation_event_scope_key"
  ON "SastFindingLifecycleReconciliation"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey"
  );
CREATE UNIQUE INDEX "SastFindingLifecycleReconciliation_context_sequence_key"
  ON "SastFindingLifecycleReconciliation"(
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey",
    "sequence"
  );
CREATE INDEX "SastFindingLifecycleReconciliation_scanRequestId_idx"
  ON "SastFindingLifecycleReconciliation"("scanRequestId");
CREATE INDEX "SastFindingLifecycleReconciliation_reconciledAt_idx"
  ON "SastFindingLifecycleReconciliation"("reconciledAt");

CREATE UNIQUE INDEX "SastFindingLifecycleEvent_state_revision_key"
  ON "SastFindingLifecycleEvent"("lifecycleStateId", "revision");
CREATE INDEX "SastFindingLifecycleEvent_context_occurred_idx"
  ON "SastFindingLifecycleEvent"(
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey",
    "occurredAt"
  );
CREATE INDEX "SastFindingLifecycleEvent_observationBatchId_idx"
  ON "SastFindingLifecycleEvent"("observationBatchId");
CREATE INDEX "SastFindingLifecycleEvent_reconciliationId_idx"
  ON "SastFindingLifecycleEvent"("reconciliationId");

ALTER TABLE "SastFindingLineage"
  ADD CONSTRAINT "SastFindingLineage_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLineage_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastFindingIdentityAlias"
  ADD CONSTRAINT "SastFindingIdentityAlias_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingIdentityAlias_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingIdentityAlias_lineage_scope_fkey"
  FOREIGN KEY (
    "lineageId",
    "tenantId",
    "repositoryBindingId",
    "capability",
    "fingerprintVersion"
  )
  REFERENCES "SastFindingLineage"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "capability",
    "fingerprintVersion"
  )
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastFindingObservationBatch"
  ADD CONSTRAINT "SastFindingObservationBatch_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingObservationBatch_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingObservationBatch_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingObservationBatch_attempt_scope_fkey"
  FOREIGN KEY ("attemptId", "tenantId", "repositoryBindingId", "scanRequestId")
  REFERENCES "SastScanAttempt"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId"
  )
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastFindingOccurrence"
  ADD CONSTRAINT "SastFindingOccurrence_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingOccurrence_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingOccurrence_batch_scope_fkey"
  FOREIGN KEY (
    "observationBatchId",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId",
    "scannerRunId"
  )
  REFERENCES "SastFindingObservationBatch"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId",
    "scannerRunId"
  )
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingOccurrence_lineage_scope_fkey"
  FOREIGN KEY (
    "lineageId",
    "tenantId",
    "repositoryBindingId",
    "capability",
    "fingerprintVersion"
  )
  REFERENCES "SastFindingLineage"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "capability",
    "fingerprintVersion"
  )
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastFindingLifecycleState"
  ADD CONSTRAINT "SastFindingLifecycleState_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLifecycleState_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLifecycleState_lineage_scope_fkey"
  FOREIGN KEY ("lineageId", "tenantId", "repositoryBindingId")
  REFERENCES "SastFindingLineage"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastFindingLifecycleReconciliation"
  ADD CONSTRAINT "SastFindingLifecycleReconciliation_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLifecycleReconciliation_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLifecycleReconciliation_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLifecycleReconciliation_attempt_scope_fkey"
  FOREIGN KEY ("attemptId", "tenantId", "repositoryBindingId", "scanRequestId")
  REFERENCES "SastScanAttempt"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId"
  )
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastFindingLifecycleEvent"
  ADD CONSTRAINT "SastFindingLifecycleEvent_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLifecycleEvent_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLifecycleEvent_lineage_scope_fkey"
  FOREIGN KEY ("lineageId", "tenantId", "repositoryBindingId")
  REFERENCES "SastFindingLineage"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLifecycleEvent_state_scope_fkey"
  FOREIGN KEY (
    "lifecycleStateId",
    "tenantId",
    "repositoryBindingId",
    "lineageId",
    "lifecycleContextKey"
  )
  REFERENCES "SastFindingLifecycleState"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "lineageId",
    "lifecycleContextKey"
  )
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLifecycleEvent_observation_scope_fkey"
  FOREIGN KEY (
    "observationBatchId",
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey"
  )
  REFERENCES "SastFindingObservationBatch"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey"
  )
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "SastFindingLifecycleEvent_reconciliation_scope_fkey"
  FOREIGN KEY (
    "reconciliationId",
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey"
  )
  REFERENCES "SastFindingLifecycleReconciliation"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey"
  )
  ON DELETE CASCADE ON UPDATE CASCADE;

-- The scanner-run and normalized-finding scope keys are installed
-- concurrently by prisma:online-schema. Their dependent foreign keys are
-- added NOT VALID and validated there as well.
