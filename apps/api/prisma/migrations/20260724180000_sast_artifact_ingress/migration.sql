CREATE TYPE "SastArtifactIngestionStatus" AS ENUM (
  'RECEIVING',
  'PENDING_VALIDATION',
  'ACCEPTED',
  'REJECTED',
  'QUARANTINED'
);

-- Deployment contract: prisma:migrate:deploy synchronously runs
-- scripts/apply-online-sast-runtime-schema.mjs and MUST finish before new-version
-- traffic is admitted. The v1 ScannerRun runtime constraint stays active
-- throughout this transaction; the online step validates v2 first and only then
-- removes v1, so a failed rollout cannot leave a constraint gap.

CREATE TABLE "SastArtifactIngestion" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "scannerRunId" TEXT NOT NULL,
  "workloadIdentityRef" TEXT NOT NULL,
  "idempotencyKey" TEXT NOT NULL,
  "envelopeDigest" TEXT NOT NULL,
  "declaredContentDigest" TEXT NOT NULL,
  "observedContentDigest" TEXT,
  "declaredByteSize" INTEGER NOT NULL,
  "observedByteSize" INTEGER,
  "objectKey" TEXT,
  "identityValidated" BOOLEAN NOT NULL DEFAULT false,
  "status" "SastArtifactIngestionStatus" NOT NULL DEFAULT 'RECEIVING',
  "validationMetadata" JSONB,
  "rejectionReason" TEXT,
  "receivedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "SastArtifactIngestion_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastArtifactIngestion_identity_check"
    CHECK (
      "identityValidated" = true
      AND char_length("workloadIdentityRef") BETWEEN 1 AND 512
    ),
  CONSTRAINT "SastArtifactIngestion_digest_check"
    CHECK (
      "envelopeDigest" ~ '^sha256:[a-f0-9]{64}$'
      AND "declaredContentDigest" ~ '^sha256:[a-f0-9]{64}$'
      AND (
        "observedContentDigest" IS NULL
        OR "observedContentDigest" ~ '^sha256:[a-f0-9]{64}$'
      )
    ),
  CONSTRAINT "SastArtifactIngestion_size_check"
    CHECK (
      "declaredByteSize" BETWEEN 1 AND 268435456
      AND (
        "observedByteSize" IS NULL
        OR "observedByteSize" BETWEEN 0 AND 268435457
      )
    ),
  CONSTRAINT "SastArtifactIngestion_key_check"
    CHECK (
      char_length("idempotencyKey") BETWEEN 1 AND 1024
      AND (
        "objectKey" IS NULL
        OR char_length("objectKey") BETWEEN 1 AND 2048
      )
    ),
  CONSTRAINT "SastArtifactIngestion_lifecycle_check"
    CHECK (
      COALESCE(
        (
          "status" = 'RECEIVING'
          AND "objectKey" IS NULL
          AND "observedContentDigest" IS NULL
          AND "observedByteSize" IS NULL
          AND "rejectionReason" IS NULL
          AND "receivedAt" IS NULL
        )
        OR (
          "status" IN ('PENDING_VALIDATION', 'ACCEPTED')
          AND "objectKey" IS NOT NULL
          AND "observedContentDigest" IS NOT NULL
          AND "observedByteSize" = "declaredByteSize"
          AND "rejectionReason" IS NULL
          AND "receivedAt" IS NOT NULL
        )
        OR (
          "status" = 'REJECTED'
          AND "objectKey" IS NULL
          AND char_length("rejectionReason") BETWEEN 1 AND 255
          AND "receivedAt" IS NOT NULL
        )
        OR (
          "status" = 'QUARANTINED'
          AND "objectKey" IS NOT NULL
          AND "observedContentDigest" IS NOT NULL
          AND "observedByteSize" IS NOT NULL
          AND char_length("rejectionReason") BETWEEN 1 AND 255
          AND "receivedAt" IS NOT NULL
        ),
        false
      )
    )
);

CREATE UNIQUE INDEX "SastArtifactIngestion_scannerRunId_key"
  ON "SastArtifactIngestion"("scannerRunId");
CREATE UNIQUE INDEX "SastArtifactIngestion_objectKey_key"
  ON "SastArtifactIngestion"("objectKey");
CREATE UNIQUE INDEX "SastArtifactIngestion_idempotency_scope_key"
  ON "SastArtifactIngestion"("tenantId", "scanRequestId", "idempotencyKey");
CREATE UNIQUE INDEX "SastArtifactIngestion_scanner_scope_key"
  ON "SastArtifactIngestion"("scannerRunId", "attemptId", "tenantId", "repositoryBindingId", "scanRequestId");
CREATE INDEX "SastArtifactIngestion_tenantId_scanRequestId_status_idx"
  ON "SastArtifactIngestion"("tenantId", "scanRequestId", "status");
CREATE INDEX "SastArtifactIngestion_attemptId_status_idx"
  ON "SastArtifactIngestion"("attemptId", "status");
CREATE INDEX "SastArtifactIngestion_createdAt_idx"
  ON "SastArtifactIngestion"("createdAt");

ALTER TABLE "SastArtifactIngestion"
  ADD CONSTRAINT "SastArtifactIngestion_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastArtifactIngestion"
  ADD CONSTRAINT "SastArtifactIngestion_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastArtifactIngestion"
  ADD CONSTRAINT "SastArtifactIngestion_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastArtifactIngestion"
  ADD CONSTRAINT "SastArtifactIngestion_attempt_scope_fkey"
  FOREIGN KEY ("attemptId", "tenantId", "repositoryBindingId", "scanRequestId")
  REFERENCES "SastScanAttempt"("id", "tenantId", "repositoryBindingId", "scanRequestId")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- ScannerRun scope uniqueness and the corresponding ingestion foreign key are
-- installed by the mandatory online schema step after this transaction.
