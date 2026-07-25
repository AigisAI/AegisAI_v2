CREATE TYPE "SastArtifactFinalDisposition" AS ENUM (
  'ACCEPTED',
  'REJECTED',
  'QUARANTINED'
);

-- Existing-table changes stay nullable and avoid table rewrites. The blocking
-- prisma:online-schema deployment step installs the unique/claim indexes,
-- validates lifecycle v2, and only then removes lifecycle v1.
ALTER TABLE "SastArtifactIngestion"
  ADD COLUMN "dispositionLeaseOwner" TEXT,
  ADD COLUMN "dispositionLeaseToken" TEXT,
  ADD COLUMN "dispositionLeaseExpiresAt" TIMESTAMP(3),
  ADD COLUMN "dispositionNextAttemptAt" TIMESTAMP(3),
  ADD COLUMN "dispositionAttemptCount" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "dispositionLastErrorCode" TEXT,
  ADD COLUMN "dispositionIntent" JSONB,
  ADD COLUMN "dispositionIntentDigest" TEXT,
  ADD COLUMN "dispositionOperationId" TEXT,
  ADD COLUMN "retentionExpiresAt" TIMESTAMP(3),
  ADD COLUMN "dispositionDecidedAt" TIMESTAMP(3);

CREATE TABLE "SastArtifactDispositionDecision" (
  "id" TEXT NOT NULL,
  "ingestionId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "scannerRunId" TEXT NOT NULL,
  "disposition" "SastArtifactFinalDisposition" NOT NULL,
  "failureClass" "SastScanFailureClass",
  "reasonCodes" JSONB NOT NULL,
  "validationReasonCodes" JSONB NOT NULL,
  "validationResultDigest" TEXT NOT NULL,
  "intentDigest" TEXT NOT NULL,
  "operationId" TEXT NOT NULL,
  "decision" JSONB NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "storageReceiptRef" TEXT NOT NULL,
  "storageReceiptDigest" TEXT NOT NULL,
  "acceptanceControlRef" TEXT,
  "encryptionContextDigest" TEXT,
  "retentionExpiresAt" TIMESTAMP(3),
  "normalizationEligible" BOOLEAN NOT NULL DEFAULT false,
  "auditEventId" TEXT NOT NULL,
  "decidedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastArtifactDispositionDecision_pkey"
    PRIMARY KEY ("id"),
  CONSTRAINT "SastArtifactDispositionDecision_digest_check"
    CHECK (
      "validationResultDigest" ~ '^sha256:[a-f0-9]{64}$'
      AND "intentDigest" ~ '^sha256:[a-f0-9]{64}$'
      AND "decisionDigest" ~ '^sha256:[a-f0-9]{64}$'
      AND "storageReceiptDigest" ~ '^sha256:[a-f0-9]{64}$'
      AND (
        "encryptionContextDigest" IS NULL
        OR "encryptionContextDigest" ~ '^sha256:[a-f0-9]{64}$'
      )
    ),
  CONSTRAINT "SastArtifactDispositionDecision_reference_check"
    CHECK (
      "operationId" ~ '^sast-artifact-disposition-v1:[a-f0-9]{64}$'
      AND "storageReceiptRef"
        ~ '^storage-receipt://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+$'
      AND char_length("storageReceiptRef") BETWEEN 19 AND 2048
      AND (
        "acceptanceControlRef" IS NULL
        OR char_length("acceptanceControlRef") BETWEEN 1 AND 2048
      )
      AND jsonb_typeof("reasonCodes") = 'array'
      AND jsonb_typeof("validationReasonCodes") = 'array'
      AND jsonb_typeof("decision") = 'object'
      AND (
        "decision" - ARRAY[
          'version',
          'ingestionId',
          'disposition',
          'storageAction',
          'failureClass',
          'reasonCodes',
          'validationReasonCodes',
          'validationResultDigest',
          'normalizationEligible',
          'retentionExpiresAt',
          'acceptanceControlRef',
          'intentDigest',
          'storageOperationId',
          'storageReceiptRef',
          'storageReceiptDigest',
          'encryptionContextDigest',
          'decidedAt',
          'decisionDigest'
        ]::text[]
      ) = '{}'::jsonb
      AND "decision" ->> 'version' = 'sast-artifact-disposition-v1'
      AND "decision" ->> 'ingestionId' = "ingestionId"
      AND "decision" ->> 'disposition' = "disposition"::text
      AND "decision" ->> 'storageAction' = CASE "disposition"
        WHEN 'ACCEPTED' THEN 'RETAIN_ACCEPTED'
        WHEN 'REJECTED' THEN 'DELETE_REJECTED'
        WHEN 'QUARANTINED' THEN 'MOVE_REENCRYPT_QUARANTINE'
      END
      AND ("decision" ->> 'failureClass')
        IS NOT DISTINCT FROM "failureClass"::text
      AND "decision" -> 'reasonCodes' = "reasonCodes"
      AND "decision" -> 'validationReasonCodes' = "validationReasonCodes"
      AND "decision" ->> 'validationResultDigest'
        = "validationResultDigest"
      AND "decision" ->> 'intentDigest' = "intentDigest"
      AND "decision" ->> 'decisionDigest' = "decisionDigest"
      AND "decision" ->> 'storageOperationId' = "operationId"
      AND "decision" ->> 'storageReceiptRef' = "storageReceiptRef"
      AND "decision" ->> 'storageReceiptDigest' = "storageReceiptDigest"
      AND ("decision" ->> 'acceptanceControlRef')
        IS NOT DISTINCT FROM "acceptanceControlRef"
      AND ("decision" ->> 'encryptionContextDigest')
        IS NOT DISTINCT FROM "encryptionContextDigest"
      AND (
        ("decision" ->> 'retentionExpiresAt')::timestamptz
          AT TIME ZONE 'UTC'
      ) IS NOT DISTINCT FROM "retentionExpiresAt"
      AND (
        ("decision" ->> 'decidedAt')::timestamptz
          AT TIME ZONE 'UTC'
      ) = "decidedAt"
      AND (
        "reasonCodes" ? 'ARTIFACT_SOURCE_OBJECT_MISSING'
        OR "operationId" = 'sast-artifact-disposition-v1:'
          || substr("intentDigest", 8)
      )
      AND jsonb_typeof("decision" -> 'normalizationEligible') = 'boolean'
      AND ("decision" ->> 'normalizationEligible')::boolean
        = "normalizationEligible"
      AND (
        "reasonCodes" ? 'ARTIFACT_VALIDATION_FAILED'
      ) = (jsonb_array_length("validationReasonCodes") > 0)
    ),
  CONSTRAINT "SastArtifactDispositionDecision_state_check"
    CHECK (
      (
        "disposition" = 'ACCEPTED'
        AND "failureClass" IS NULL
        AND "normalizationEligible" = true
        AND "retentionExpiresAt" IS NOT NULL
        AND "retentionExpiresAt" > "decidedAt"
        AND "acceptanceControlRef" IS NOT NULL
        AND "encryptionContextDigest" IS NULL
        AND "reasonCodes" = '["ARTIFACT_VALIDATION_ACCEPTED"]'::jsonb
        AND jsonb_array_length("validationReasonCodes") = 0
      )
      OR (
        "disposition" = 'REJECTED'
        AND "failureClass" IN ('NON_RETRYABLE_INPUT', 'SECURITY_VIOLATION')
        AND "normalizationEligible" = false
        AND "retentionExpiresAt" IS NULL
        AND "encryptionContextDigest" IS NULL
        AND NOT ("reasonCodes" ? 'ARTIFACT_VALIDATION_ACCEPTED')
        AND (
          "reasonCodes" ? 'ARTIFACT_RETENTION_EXPIRED'
          OR "reasonCodes" ? 'ARTIFACT_SOURCE_OBJECT_MISSING'
        )
        AND (
          ("reasonCodes" ? 'ARTIFACT_ACCEPTANCE_DENIED')
          = ("acceptanceControlRef" IS NOT NULL)
        )
      )
      OR (
        "disposition" = 'QUARANTINED'
        AND "failureClass" = 'SECURITY_VIOLATION'
        AND "normalizationEligible" = false
        AND "retentionExpiresAt" IS NOT NULL
        AND "retentionExpiresAt" > "decidedAt"
        AND "encryptionContextDigest" IS NOT NULL
        AND jsonb_array_length("reasonCodes") > 0
        AND NOT ("reasonCodes" ? 'ARTIFACT_VALIDATION_ACCEPTED')
        AND NOT ("reasonCodes" ? 'ARTIFACT_RETENTION_EXPIRED')
        AND NOT ("reasonCodes" ? 'ARTIFACT_SOURCE_OBJECT_MISSING')
        AND (
          ("reasonCodes" ? 'ARTIFACT_ACCEPTANCE_DENIED')
          = ("acceptanceControlRef" IS NOT NULL)
        )
      )
    )
);

CREATE UNIQUE INDEX "SastArtifactDispositionDecision_ingestionId_key"
  ON "SastArtifactDispositionDecision"("ingestionId");
CREATE UNIQUE INDEX "SastArtifactDispositionDecision_operationId_key"
  ON "SastArtifactDispositionDecision"("operationId");
CREATE UNIQUE INDEX "SastArtifactDispositionDecision_decisionDigest_key"
  ON "SastArtifactDispositionDecision"("decisionDigest");
CREATE UNIQUE INDEX "SastArtifactDispositionDecision_auditEventId_key"
  ON "SastArtifactDispositionDecision"("auditEventId");
CREATE UNIQUE INDEX "SastArtifactDispositionDecision_scope_key"
  ON "SastArtifactDispositionDecision"(
    "ingestionId",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId",
    "scannerRunId"
  );
CREATE UNIQUE INDEX "SastArtifactDispositionDecision_audit_scope_key"
  ON "SastArtifactDispositionDecision"(
    "auditEventId",
    "attemptId",
    "tenantId",
    "scanRequestId"
  );
CREATE INDEX "SastArtifactDispositionDecision_tenantId_scanRequestId_disposition_idx"
  ON "SastArtifactDispositionDecision"("tenantId", "scanRequestId", "disposition");
CREATE INDEX "SastArtifactDispositionDecision_retentionExpiresAt_disposition_idx"
  ON "SastArtifactDispositionDecision"("retentionExpiresAt", "disposition");
CREATE INDEX "SastArtifactDispositionDecision_scannerRunId_idx"
  ON "SastArtifactDispositionDecision"("scannerRunId");
CREATE INDEX "SastArtifactDispositionDecision_decidedAt_idx"
  ON "SastArtifactDispositionDecision"("decidedAt");
