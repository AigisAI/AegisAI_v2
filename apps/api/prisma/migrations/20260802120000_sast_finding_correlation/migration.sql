-- Applying this migration alone does not create the occurrence-scope foreign
-- keys. Run apps/api/scripts/apply-online-sast-runtime-schema.mjs afterward to
-- create "SastFindingOccurrence_correlation_scope_key" plus
-- "SastFindingCorrelationEdge_source_occurrence_scope_fkey",
-- "SastFindingCorrelationEdge_target_occurrence_scope_fkey", and
-- "SastFindingCorrelationProvenance_occurrence_scope_fkey".

CREATE TYPE "SastFindingCorrelationKind" AS ENUM (
  'EXACT_FINGERPRINT',
  'SAME_DEPENDENCY_CVE',
  'SUPPORTING_EVIDENCE',
  'POSSIBLE_OVERLAP'
);

CREATE TYPE "SastFindingCorrelationAuthorityLevel" AS ENUM (
  'AUTHORITATIVE',
  'SUPPORTING_ONLY'
);

CREATE TYPE "SastFindingCorrelationProvenanceSide" AS ENUM (
  'SOURCE',
  'TARGET'
);

CREATE TABLE "SastFindingCorrelationBatch" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "lifecycleContextKey" TEXT NOT NULL,
  "targetRef" TEXT NOT NULL,
  "commitSha" TEXT NOT NULL,
  "lane" "ScanLane" NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "canonicalScanKey" TEXT NOT NULL,
  "planDigest" TEXT NOT NULL,
  "sourceSetDigest" TEXT NOT NULL,
  "sourceBatchCount" INTEGER NOT NULL,
  "occurrenceCount" INTEGER NOT NULL,
  "edgeCount" INTEGER NOT NULL,
  "exactFingerprintCount" INTEGER NOT NULL,
  "sameDependencyCveCount" INTEGER NOT NULL,
  "supportingEvidenceCount" INTEGER NOT NULL,
  "possibleOverlapCount" INTEGER NOT NULL,
  "correlatedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastFindingCorrelationBatch_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingCorrelationBatch_contract_check" CHECK (
    "id" ~ '^finding-correlation://[a-f0-9]{64}$'
    AND "lifecycleContextKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "commitSha" ~ '^[a-f0-9]{40}([a-f0-9]{24})?$'
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "canonicalScanKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "planDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "sourceSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "sourceBatchCount" BETWEEN 1 AND 16
    AND "occurrenceCount" BETWEEN 0 AND 25000
    AND "edgeCount" BETWEEN 0 AND 100000
    AND "exactFingerprintCount" >= 0
    AND "sameDependencyCveCount" >= 0
    AND "supportingEvidenceCount" >= 0
    AND "possibleOverlapCount" >= 0
    AND "exactFingerprintCount"
      + "sameDependencyCveCount"
      + "supportingEvidenceCount"
      + "possibleOverlapCount" = "edgeCount"
  )
);

CREATE TABLE "SastFindingCorrelationSource" (
  "id" TEXT NOT NULL,
  "correlationBatchId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "observationBatchId" TEXT NOT NULL,
  "scannerRunId" TEXT NOT NULL,
  "scanner" "ScannerKind" NOT NULL,
  "capabilities" JSONB NOT NULL,
  "sourceIdentityBatchDigest" TEXT NOT NULL,
  "sourceBindingDigest" TEXT NOT NULL,
  "lifecycleContextKey" TEXT NOT NULL,
  "findingCount" INTEGER NOT NULL,
  "occurrenceCount" INTEGER NOT NULL,
  "observedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastFindingCorrelationSource_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingCorrelationSource_contract_check" CHECK (
    "id" ~ '^finding-correlation-source://[a-f0-9]{64}$'
    AND "correlationBatchId" ~ '^finding-correlation://[a-f0-9]{64}$'
    AND "observationBatchId" ~ '^finding-observation://[a-f0-9]{64}$'
    AND "scanner" IN ('OPENGREP', 'TRIVY')
    AND jsonb_typeof("capabilities") = 'array'
    AND "sourceIdentityBatchDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "sourceBindingDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "lifecycleContextKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "findingCount" BETWEEN 0 AND 25000
    AND "occurrenceCount" = "findingCount"
  )
);

CREATE TABLE "SastFindingCorrelationEdge" (
  "id" TEXT NOT NULL,
  "correlationBatchId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "kind" "SastFindingCorrelationKind" NOT NULL,
  "sourceOccurrenceId" TEXT NOT NULL,
  "targetOccurrenceId" TEXT NOT NULL,
  "basisDigests" JSONB NOT NULL,
  "confidenceBasisPoints" INTEGER NOT NULL,
  "sourceProvenanceDigest" TEXT NOT NULL,
  "targetProvenanceDigest" TEXT NOT NULL,
  "safety" JSONB NOT NULL,
  "decidedAt" TIMESTAMP(3) NOT NULL,
  "edgeDigest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastFindingCorrelationEdge_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingCorrelationEdge_contract_check" CHECK (
    "id" ~ '^finding-correlation-edge://[a-f0-9]{64}$'
    AND "correlationBatchId" ~ '^finding-correlation://[a-f0-9]{64}$'
    AND "sourceOccurrenceId" ~ '^finding-occurrence://[a-f0-9]{64}$'
    AND "targetOccurrenceId" ~ '^finding-occurrence://[a-f0-9]{64}$'
    AND "sourceOccurrenceId" < "targetOccurrenceId"
    AND jsonb_typeof("basisDigests") = 'array'
    AND jsonb_array_length("basisDigests") BETWEEN 1 AND 256
    AND "sourceProvenanceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "targetProvenanceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "edgeDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND (
      ("kind" IN ('EXACT_FINGERPRINT', 'SAME_DEPENDENCY_CVE')
        AND "confidenceBasisPoints" = 10000)
      OR ("kind" = 'SUPPORTING_EVIDENCE'
        AND "confidenceBasisPoints" = 8000)
      OR ("kind" = 'POSSIBLE_OVERLAP'
        AND "confidenceBasisPoints" = 5000)
    )
    AND "safety" = '{
      "findingMergeAllowed": false,
      "severityInheritanceAllowed": false,
      "lifecycleInheritanceAllowed": false,
      "policyInheritanceAllowed": false,
      "coverageInheritanceAllowed": false,
      "occurrenceProvenancePreserved": true
    }'::jsonb
  )
);

CREATE TABLE "SastFindingCorrelationProvenance" (
  "id" TEXT NOT NULL,
  "correlationEdgeId" TEXT NOT NULL,
  "correlationBatchId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "side" "SastFindingCorrelationProvenanceSide" NOT NULL,
  "occurrenceId" TEXT NOT NULL,
  "observationBatchId" TEXT NOT NULL,
  "lineageId" TEXT NOT NULL,
  "normalizedFindingId" TEXT NOT NULL,
  "scannerRunId" TEXT NOT NULL,
  "scanner" "ScannerKind" NOT NULL,
  "capability" "SastFindingCapability" NOT NULL,
  "authorityLevel" "SastFindingCorrelationAuthorityLevel" NOT NULL,
  "severity" "Severity" NOT NULL,
  "fingerprintVersion" TEXT NOT NULL,
  "stableFingerprint" TEXT NOT NULL,
  "fingerprintDecisionDigest" TEXT NOT NULL,
  "sourceFindingDigest" TEXT NOT NULL,
  "scannerVersion" TEXT NOT NULL,
  "scannerImageDigest" TEXT NOT NULL,
  "ruleId" TEXT NOT NULL,
  "ruleRevision" TEXT NOT NULL,
  "ruleBundleDigest" TEXT NOT NULL,
  "artifactDigest" TEXT NOT NULL,
  "vulnerabilityDatabaseDigest" TEXT,
  "provenanceDigest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastFindingCorrelationProvenance_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastFindingCorrelationProvenance_contract_check" CHECK (
    "id" ~ '^finding-correlation-provenance://[a-f0-9]{64}$'
    AND "correlationEdgeId" ~ '^finding-correlation-edge://[a-f0-9]{64}$'
    AND "correlationBatchId" ~ '^finding-correlation://[a-f0-9]{64}$'
    AND "occurrenceId" ~ '^finding-occurrence://[a-f0-9]{64}$'
    AND "observationBatchId" ~ '^finding-observation://[a-f0-9]{64}$'
    AND "lineageId" ~ '^finding-lineage://[a-f0-9]{64}$'
    AND "normalizedFindingId" ~ '^normalized-finding://[a-f0-9]{64}$'
    AND "scanner" IN ('OPENGREP', 'TRIVY')
    AND "fingerprintVersion" = 'sast-fingerprint-v1'
    AND "stableFingerprint" ~ '^sha256:[a-f0-9]{64}$'
    AND "fingerprintDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "sourceFindingDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "scannerImageDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "ruleBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "artifactDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "provenanceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND (
      ("scanner" = 'TRIVY'
        AND "vulnerabilityDatabaseDigest" ~ '^sha256:[a-f0-9]{64}$')
      OR ("scanner" = 'OPENGREP'
        AND "vulnerabilityDatabaseDigest" IS NULL)
    )
  )
);

CREATE UNIQUE INDEX "SastFindingCorrelationBatch_scope_key"
  ON "SastFindingCorrelationBatch"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId"
  );
CREATE UNIQUE INDEX "SastFindingCorrelationBatch_attempt_context_key"
  ON "SastFindingCorrelationBatch"(
    "tenantId", "repositoryBindingId", "scanRequestId", "attemptId",
    "lifecycleContextKey"
  );
CREATE UNIQUE INDEX "SastFindingCorrelationBatch_source_set_key"
  ON "SastFindingCorrelationBatch"("tenantId", "sourceSetDigest");
CREATE INDEX "SastFindingCorrelationBatch_context_correlated_idx"
  ON "SastFindingCorrelationBatch"(
    "tenantId", "repositoryBindingId", "lifecycleContextKey", "correlatedAt"
  );

CREATE UNIQUE INDEX "SastFindingCorrelationSource_batch_observation_key"
  ON "SastFindingCorrelationSource"(
    "correlationBatchId", "observationBatchId"
  );
CREATE UNIQUE INDEX "SastFindingCorrelationSource_binding_key"
  ON "SastFindingCorrelationSource"("tenantId", "sourceBindingDigest");
CREATE INDEX "SastFindingCorrelationSource_observationBatchId_idx"
  ON "SastFindingCorrelationSource"("observationBatchId");

CREATE UNIQUE INDEX "SastFindingCorrelationEdge_edgeDigest_key"
  ON "SastFindingCorrelationEdge"("edgeDigest");
CREATE UNIQUE INDEX "SastFindingCorrelationEdge_pair_key"
  ON "SastFindingCorrelationEdge"(
    "correlationBatchId", "sourceOccurrenceId", "targetOccurrenceId"
  );
CREATE UNIQUE INDEX "SastFindingCorrelationEdge_batch_edge_key"
  ON "SastFindingCorrelationEdge"("id", "correlationBatchId");
CREATE INDEX "SastFindingCorrelationEdge_scope_kind_idx"
  ON "SastFindingCorrelationEdge"(
    "tenantId", "repositoryBindingId", "scanRequestId", "kind"
  );
CREATE INDEX "SastFindingCorrelationEdge_sourceOccurrenceId_idx"
  ON "SastFindingCorrelationEdge"("sourceOccurrenceId");
CREATE INDEX "SastFindingCorrelationEdge_targetOccurrenceId_idx"
  ON "SastFindingCorrelationEdge"("targetOccurrenceId");

CREATE UNIQUE INDEX "SastFindingCorrelationProvenance_edge_side_key"
  ON "SastFindingCorrelationProvenance"("correlationEdgeId", "side");
CREATE INDEX "SastFindingCorrelationProvenance_occurrenceId_idx"
  ON "SastFindingCorrelationProvenance"("occurrenceId");
CREATE INDEX "SastFindingCorrelationProvenance_provenanceDigest_idx"
  ON "SastFindingCorrelationProvenance"("provenanceDigest");

ALTER TABLE "SastFindingCorrelationBatch"
  ADD CONSTRAINT "SastFindingCorrelationBatch_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastFindingCorrelationBatch"
  ADD CONSTRAINT "SastFindingCorrelationBatch_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastFindingCorrelationBatch"
  ADD CONSTRAINT "SastFindingCorrelationBatch_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastFindingCorrelationBatch"
  ADD CONSTRAINT "SastFindingCorrelationBatch_attempt_scope_fkey"
  FOREIGN KEY (
    "attemptId", "tenantId", "repositoryBindingId", "scanRequestId"
  ) REFERENCES "SastScanAttempt"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId"
  ) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastFindingCorrelationSource"
  ADD CONSTRAINT "SastFindingCorrelationSource_batch_scope_fkey"
  FOREIGN KEY (
    "correlationBatchId", "tenantId", "repositoryBindingId",
    "scanRequestId", "attemptId"
  ) REFERENCES "SastFindingCorrelationBatch"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId"
  ) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastFindingCorrelationSource"
  ADD CONSTRAINT "SastFindingCorrelationSource_observation_scope_fkey"
  FOREIGN KEY (
    "observationBatchId", "tenantId", "repositoryBindingId",
    "scanRequestId", "attemptId", "scannerRunId"
  ) REFERENCES "SastFindingObservationBatch"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId",
    "scannerRunId"
  ) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastFindingCorrelationEdge"
  ADD CONSTRAINT "SastFindingCorrelationEdge_batch_scope_fkey"
  FOREIGN KEY (
    "correlationBatchId", "tenantId", "repositoryBindingId",
    "scanRequestId", "attemptId"
  ) REFERENCES "SastFindingCorrelationBatch"(
    "id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId"
  ) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastFindingCorrelationProvenance"
  ADD CONSTRAINT "SastFindingCorrelationProvenance_edge_scope_fkey"
  FOREIGN KEY ("correlationEdgeId", "correlationBatchId")
  REFERENCES "SastFindingCorrelationEdge"("id", "correlationBatchId")
  ON DELETE CASCADE ON UPDATE CASCADE;
