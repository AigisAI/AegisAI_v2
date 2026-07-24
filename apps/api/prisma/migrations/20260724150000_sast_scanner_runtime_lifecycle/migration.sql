CREATE TYPE "SastScanAttemptStage" AS ENUM (
  'VALIDATING',
  'SCANNING',
  'CLEANUP_PENDING',
  'COMPLETED',
  'FAILED',
  'CLEANUP_FAILED'
);

ALTER TYPE "ScannerRunStatus" ADD VALUE 'QUARANTINED';
ALTER TYPE "ScannerRunStatus" ADD VALUE 'KILLED';

CREATE TYPE "SastScanFailureClass" AS ENUM (
  'RETRYABLE_INFRASTRUCTURE',
  'NON_RETRYABLE_INPUT',
  'SCANNER_DEFECT',
  'SECURITY_VIOLATION',
  'CAPACITY_REJECTED'
);

CREATE TABLE "SastScanAttempt" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptNumber" INTEGER NOT NULL,
  "sandboxId" TEXT NOT NULL,
  "workloadIdentityRef" TEXT NOT NULL,
  "stage" "SastScanAttemptStage" NOT NULL DEFAULT 'VALIDATING',
  "failureClass" "SastScanFailureClass",
  "failureReason" TEXT,
  "retryEligible" BOOLEAN NOT NULL DEFAULT false,
  "cleanupEvidence" JSONB,
  "cleanupEvidenceDigest" TEXT,
  "finalAuditEventId" TEXT,
  "startedAt" TIMESTAMP(3) NOT NULL,
  "attemptDeadlineAt" TIMESTAMP(3) NOT NULL,
  "completedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "SastScanAttempt_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastScanAttempt_attempt_number_check"
    CHECK ("attemptNumber" BETWEEN 1 AND 2),
  CONSTRAINT "SastScanAttempt_deadline_check"
    CHECK (
      "attemptDeadlineAt" > "startedAt"
      AND "attemptDeadlineAt" <= "startedAt" + INTERVAL '1 hour 5 seconds'
    ),
  CONSTRAINT "SastScanAttempt_cleanup_digest_check"
    CHECK (
      "cleanupEvidenceDigest" IS NULL
      OR "cleanupEvidenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    ),
  CONSTRAINT "SastScanAttempt_retry_eligibility_check"
    CHECK (
      "retryEligible" = false
      OR COALESCE(
        (
          "stage" = 'FAILED'
          AND "failureClass" = 'RETRYABLE_INFRASTRUCTURE'
          AND "attemptNumber" = 1
        ),
        false
      )
    ),
  CONSTRAINT "SastScanAttempt_completed_cleanup_check"
    CHECK (
      "stage" NOT IN ('COMPLETED', 'FAILED')
      OR COALESCE(
        (
          "cleanupEvidence" IS NOT NULL
          AND "cleanupEvidenceDigest" IS NOT NULL
          AND "cleanupEvidence" #>> '{observation,credentialRevokedAndWiped}' = 'true'
          AND "cleanupEvidence" #>> '{observation,scannerProcessesTerminated}' = 'true'
          AND "cleanupEvidence" #>> '{observation,writableVolumesDestroyed}' = 'true'
          AND "cleanupEvidence" #>> '{observation,microVmTerminated}' = 'true'
          AND "cleanupEvidence" #>> '{observation,resultIngressClosed}' = 'true'
          AND "cleanupEvidence" #>> '{signature}' ~ '^sha256:[a-f0-9]{64}$'
        ),
        false
      )
    ),
  CONSTRAINT "SastScanAttempt_lifecycle_state_check"
    CHECK (
      COALESCE(
        (
          "stage" IN ('VALIDATING', 'SCANNING', 'CLEANUP_PENDING')
          AND "completedAt" IS NULL
          AND "finalAuditEventId" IS NULL
          AND "failureClass" IS NULL
          AND "failureReason" IS NULL
          AND "retryEligible" = false
        )
        OR (
          "stage" = 'COMPLETED'
          AND "completedAt" IS NOT NULL
          AND "completedAt" >= "startedAt"
          AND "finalAuditEventId" IS NOT NULL
          AND "failureClass" IS NULL
          AND "failureReason" IS NULL
          AND "retryEligible" = false
        )
        OR (
          "stage" = 'FAILED'
          AND "completedAt" IS NOT NULL
          AND "completedAt" >= "startedAt"
          AND "finalAuditEventId" IS NOT NULL
          AND "failureClass" IS NOT NULL
          AND char_length("failureReason") BETWEEN 1 AND 255
        )
        OR (
          "stage" = 'CLEANUP_FAILED'
          AND "completedAt" IS NOT NULL
          AND "completedAt" >= "startedAt"
          AND "finalAuditEventId" IS NOT NULL
          AND "failureClass" IS NOT NULL
          AND char_length("failureReason") BETWEEN 1 AND 255
          AND "retryEligible" = false
        ),
        false
      )
    )
);

CREATE UNIQUE INDEX "SastScanAttempt_scanRequestId_attemptNumber_key"
  ON "SastScanAttempt"("scanRequestId", "attemptNumber");
CREATE UNIQUE INDEX "SastScanAttempt_one_active_per_scan_key"
  ON "SastScanAttempt"("scanRequestId")
  WHERE "stage" IN ('VALIDATING', 'SCANNING', 'CLEANUP_PENDING');
CREATE UNIQUE INDEX "SastScanAttempt_sandboxId_key"
  ON "SastScanAttempt"("sandboxId");
CREATE UNIQUE INDEX "SastScanAttempt_workloadIdentityRef_key"
  ON "SastScanAttempt"("workloadIdentityRef");
CREATE UNIQUE INDEX "SastScanAttempt_id_tenantId_key"
  ON "SastScanAttempt"("id", "tenantId");
CREATE UNIQUE INDEX "SastScanAttempt_scope_key"
  ON "SastScanAttempt"("id", "tenantId", "repositoryBindingId", "scanRequestId");
CREATE UNIQUE INDEX "SastScanAttempt_finalAuditEventId_key"
  ON "SastScanAttempt"("finalAuditEventId");
CREATE UNIQUE INDEX "SastScanAttempt_final_audit_scope_key"
  ON "SastScanAttempt"("finalAuditEventId", "id", "tenantId");
CREATE INDEX "SastScanAttempt_tenantId_stage_idx"
  ON "SastScanAttempt"("tenantId", "stage");
CREATE INDEX "SastScanAttempt_stage_attemptDeadlineAt_idx"
  ON "SastScanAttempt"("stage", "attemptDeadlineAt");
CREATE INDEX "SastScanAttempt_repositoryBindingId_idx"
  ON "SastScanAttempt"("repositoryBindingId");
CREATE INDEX "SastScanAttempt_completedAt_idx"
  ON "SastScanAttempt"("completedAt");

ALTER TABLE "SastScanAttempt"
  ADD CONSTRAINT "SastScanAttempt_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanAttempt"
  ADD CONSTRAINT "SastScanAttempt_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanAttempt"
  ADD CONSTRAINT "SastScanAttempt_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ScannerRun"
  ADD COLUMN "attemptId" TEXT,
  ADD COLUMN "repositoryBindingId" TEXT,
  ADD COLUMN "required" BOOLEAN,
  ADD COLUMN "wrapperDigest" TEXT,
  ADD COLUMN "scannerImageDigest" TEXT,
  ADD COLUMN "ruleBundleDigest" TEXT,
  ADD COLUMN "databaseDigest" TEXT,
  ADD COLUMN "scannerSetDigest" TEXT,
  ADD COLUMN "profileId" TEXT,
  ADD COLUMN "profileDigest" TEXT,
  ADD COLUMN "preflightAttestationRef" TEXT,
  ADD COLUMN "preflightInventoryDigest" TEXT,
  ADD COLUMN "scannerWorkspaceInventoryDigest" TEXT,
  ADD COLUMN "artifactSchema" TEXT,
  ADD COLUMN "artifactSchemaVersion" TEXT,
  ADD COLUMN "exitCode" INTEGER,
  ADD COLUMN "terminationSignal" TEXT,
  ADD COLUMN "timedOut" BOOLEAN,
  ADD COLUMN "outputLimitExceeded" BOOLEAN,
  ADD COLUMN "durationMilliseconds" INTEGER,
  ADD COLUMN "stdoutMetadata" JSONB,
  ADD COLUMN "stderrMetadata" JSONB,
  ADD COLUMN "resourceMetadata" JSONB,
  ADD COLUMN "artifactMetadata" JSONB;

ALTER TABLE "AuditEvent" ADD COLUMN "attemptId" TEXT;

-- Indexes and constraints that inspect existing ScannerRun/AuditEvent rows are
-- applied immediately after Prisma Migrate by scripts/apply-online-sast-runtime-schema.mjs.
-- Keeping them outside this transactional migration permits CREATE INDEX CONCURRENTLY
-- and releases the brief ADD CONSTRAINT lock before online validation scans existing rows.
