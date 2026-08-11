-- T042 keeps the immutable T041 pack at zero downstream authority and adds
-- separate purpose-bound access and deletion ledgers. Existing live packs are
-- backfilled by the bounded deletion task; new packs are scheduled in the same
-- serializable transaction that writes the T041 pack.
ALTER TABLE "Tenant"
  ADD COLUMN "sastAiAdvisoryOptIn" BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE "RepositoryBinding"
  ADD COLUMN "sastAiAdvisoryOptIn" BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE "SastEvidenceDeletionSchedule" (
  "id" TEXT NOT NULL,
  "operationId" TEXT NOT NULL,
  "evidencePackId" TEXT NOT NULL,
  "buildDecisionId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "occurrenceId" TEXT NOT NULL,
  "sourcePackDigest" TEXT NOT NULL,
  "deleteAfter" TIMESTAMP(3) NOT NULL,
  "scheduledAt" TIMESTAMP(3) NOT NULL,
  "schedule" JSONB NOT NULL,
  "scheduleDigest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastEvidenceDeletionSchedule_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastEvidenceDeletionSchedule_contract_check" CHECK (
    "id" ~ '^sast-evidence-deletion://[a-f0-9]{64}$'
    AND "operationId" ~ '^sast-evidence-delete://[a-f0-9]{64}$'
    AND "evidencePackId" ~ '^sast-evidence-pack://[a-f0-9]{64}$'
    AND "buildDecisionId" ~ '^sast-evidence-build://[a-f0-9]{64}$'
    AND "occurrenceId" ~ '^finding-occurrence://[a-f0-9]{64}$'
    AND "sourcePackDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "scheduleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND jsonb_typeof("schedule") = 'object'
    AND "deleteAfter" > "scheduledAt"
    AND "deleteAfter" <= "scheduledAt" + INTERVAL '7 days'
    AND ("schedule"->>'maximumRetentionSeconds')::integer = 604800
  )
);

CREATE TABLE "SastEvidenceAccessDecision" (
  "id" TEXT NOT NULL,
  "buildDecisionId" TEXT NOT NULL,
  "deletionScheduleId" TEXT NOT NULL,
  "evidencePackId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "occurrenceId" TEXT NOT NULL,
  "findingFingerprint" TEXT NOT NULL,
  "purpose" TEXT NOT NULL,
  "accessPolicyVersion" TEXT NOT NULL,
  "secretRegistryVersion" TEXT NOT NULL,
  "outcome" TEXT NOT NULL,
  "classification" TEXT NOT NULL,
  "reasonCodes" JSONB NOT NULL,
  "sourcePackDigest" TEXT NOT NULL,
  "redactedProjectionDigest" TEXT,
  "redactedFragmentCount" INTEGER NOT NULL,
  "redactedTotalBytes" INTEGER NOT NULL,
  "redactionCount" INTEGER NOT NULL,
  "secondPassRedactionDecisionRef" TEXT,
  "reducedEvidenceRef" TEXT,
  "aiPayloadExpiresAt" TIMESTAMP(3),
  "evidenceExpiresAt" TIMESTAMP(3) NOT NULL,
  "decision" JSONB NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "decidedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastEvidenceAccessDecision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastEvidenceAccessDecision_contract_check" CHECK (
    "id" ~ '^sast-evidence-access://[a-f0-9]{64}$'
    AND "buildDecisionId" ~ '^sast-evidence-build://[a-f0-9]{64}$'
    AND "deletionScheduleId" ~ '^sast-evidence-deletion://[a-f0-9]{64}$'
    AND "evidencePackId" ~ '^sast-evidence-pack://[a-f0-9]{64}$'
    AND "occurrenceId" ~ '^finding-occurrence://[a-f0-9]{64}$'
    AND "findingFingerprint" ~ '^sha256:[a-f0-9]{64}$'
    AND "accessPolicyVersion" = 'sast-evidence-access-policy-v1'
    AND "purpose" IN ('DASHBOARD', 'AI_ADVISORY')
    AND "outcome" IN ('ALLOWED', 'DENIED')
    AND "classification" IN ('DASHBOARD_SAFE', 'AI_REDUCED_REFERENCE_SAFE', 'DENIED')
    AND jsonb_typeof("reasonCodes") = 'array'
    AND jsonb_typeof("decision") = 'object'
    AND "sourcePackDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND ("redactedProjectionDigest" IS NULL OR "redactedProjectionDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND "redactedFragmentCount" BETWEEN 0 AND 5
    AND "redactedTotalBytes" BETWEEN 0 AND 32768
    AND "redactionCount" BETWEEN 0 AND 32768
    AND "decisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND (
      (
        "outcome" = 'ALLOWED'
        AND jsonb_array_length("reasonCodes") = 0
        AND "redactedProjectionDigest" IS NOT NULL
        AND "redactedFragmentCount" BETWEEN 1 AND 5
        AND "redactedTotalBytes" > 0
        AND "secondPassRedactionDecisionRef" ~ '^sast-evidence-access-redaction://[a-f0-9]{64}$'
        AND "decidedAt" < "evidenceExpiresAt"
      )
      OR
      (
        "outcome" = 'DENIED'
        AND "classification" = 'DENIED'
        AND jsonb_array_length("reasonCodes") > 0
        AND "redactedProjectionDigest" IS NULL
        AND "redactedFragmentCount" = 0
        AND "redactedTotalBytes" = 0
        AND "redactionCount" = 0
        AND "secondPassRedactionDecisionRef" IS NULL
        AND "reducedEvidenceRef" IS NULL
        AND "aiPayloadExpiresAt" IS NULL
      )
    )
    AND (
      (
        "purpose" = 'DASHBOARD'
        AND "classification" IN ('DASHBOARD_SAFE', 'DENIED')
        AND "reducedEvidenceRef" IS NULL
        AND "aiPayloadExpiresAt" IS NULL
      )
      OR
      (
        "purpose" = 'AI_ADVISORY'
        AND "classification" IN ('AI_REDUCED_REFERENCE_SAFE', 'DENIED')
        AND (
          "outcome" = 'DENIED'
          OR (
            "reducedEvidenceRef" ~ '^sast-reduced-evidence://[a-f0-9]{64}$'
            AND "aiPayloadExpiresAt" > "decidedAt"
            AND "aiPayloadExpiresAt" <= "decidedAt" + INTERVAL '24 hours'
            AND "aiPayloadExpiresAt" <= "evidenceExpiresAt"
          )
        )
      )
    )
    AND ("decision"#>>'{authority,aiPayloadAllowed}')::boolean IS FALSE
    AND ("decision"#>>'{authority,aiProviderCallAllowed}')::boolean IS FALSE
    AND ("decision"#>>'{authority,retrievalAllowed}')::boolean IS FALSE
    AND ("decision"#>>'{authority,toolsAllowed}')::boolean IS FALSE
    AND ("decision"#>>'{authority,policyAuthority}')::boolean IS FALSE
    AND ("decision"#>>'{authority,publicationAuthority}')::boolean IS FALSE
    AND ("decision"#>>'{authority,lifecycleMutationAuthority}')::boolean IS FALSE
    AND ("decision"#>>'{authority,scmWriteAuthority}')::boolean IS FALSE
    AND ("decision"#>>'{audit,rawSourceStored}')::boolean IS FALSE
    AND ("decision"#>>'{audit,secretValueStored}')::boolean IS FALSE
    AND ("decision"#>>'{audit,preRedactionPayloadStored}')::boolean IS FALSE
    AND ("decision"#>>'{audit,matchedValueDigestStored}')::boolean IS FALSE
    AND ("decision"#>>'{audit,dashboardPayloadPersisted}')::boolean IS FALSE
    AND ("decision"#>>'{audit,aiPayloadCreated}')::boolean IS FALSE
    AND ("decision"#>>'{audit,aiProviderCalled}')::boolean IS FALSE
  )
);

CREATE TABLE "SastEvidenceDeletionClaim" (
  "scheduleId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'PENDING',
  "leaseOwner" TEXT,
  "leaseToken" TEXT,
  "leaseExpiresAt" TIMESTAMP(3),
  "nextAttemptAt" TIMESTAMP(3) NOT NULL,
  "attemptCount" INTEGER NOT NULL DEFAULT 0,
  "lastErrorCode" TEXT,
  "quarantinedAt" TIMESTAMP(3),
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "SastEvidenceDeletionClaim_pkey" PRIMARY KEY ("scheduleId"),
  CONSTRAINT "SastEvidenceDeletionClaim_contract_check" CHECK (
    "scheduleId" ~ '^sast-evidence-deletion://[a-f0-9]{64}$'
    AND "status" IN ('PENDING', 'CLAIMED', 'COMPLETED', 'QUARANTINED')
    AND "attemptCount" >= 0
    AND ("lastErrorCode" IS NULL OR "lastErrorCode" = 'CONTEXT_DRIFT')
    AND (
      (
        "status" = 'CLAIMED'
        AND "leaseOwner" IS NOT NULL
        AND "leaseToken" IS NOT NULL
        AND "leaseExpiresAt" IS NOT NULL
        AND "quarantinedAt" IS NULL
      )
      OR (
        "status" IN ('PENDING', 'COMPLETED')
        AND "leaseOwner" IS NULL
        AND "leaseToken" IS NULL
        AND "leaseExpiresAt" IS NULL
        AND "quarantinedAt" IS NULL
      )
      OR (
        "status" = 'QUARANTINED'
        AND "leaseOwner" IS NULL
        AND "leaseToken" IS NULL
        AND "leaseExpiresAt" IS NULL
        AND "lastErrorCode" = 'CONTEXT_DRIFT'
        AND "quarantinedAt" IS NOT NULL
      )
    )
  )
);

CREATE TABLE "SastEvidenceDeletionProof" (
  "id" TEXT NOT NULL,
  "scheduleId" TEXT NOT NULL,
  "operationId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "evidencePackId" TEXT NOT NULL,
  "buildDecisionId" TEXT NOT NULL,
  "providerReceiptRef" TEXT NOT NULL,
  "providerReceiptDigest" TEXT NOT NULL,
  "completedAt" TIMESTAMP(3) NOT NULL,
  "proof" JSONB NOT NULL,
  "proofDigest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastEvidenceDeletionProof_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastEvidenceDeletionProof_contract_check" CHECK (
    "id" ~ '^sast-evidence-deletion-proof://[a-f0-9]{64}$'
    AND "scheduleId" ~ '^sast-evidence-deletion://[a-f0-9]{64}$'
    AND "operationId" ~ '^sast-evidence-delete://[a-f0-9]{64}$'
    AND "evidencePackId" ~ '^sast-evidence-pack://[a-f0-9]{64}$'
    AND "buildDecisionId" ~ '^sast-evidence-build://[a-f0-9]{64}$'
    AND "providerReceiptRef" ~ '^sast-evidence-delete-receipt://[a-f0-9]{64}$'
    AND "providerReceiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "proofDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND jsonb_typeof("proof") = 'object'
    AND ("proof"->>'contentDeleted')::boolean IS TRUE
    AND ("proof"->>'fragmentsDeleted')::boolean IS TRUE
    AND ("proof"->>'buildDecisionRetained')::boolean IS TRUE
    AND ("proof"->>'accessAuthorityRevoked')::boolean IS TRUE
  )
);

CREATE UNIQUE INDEX "SastEvidenceDeletionSchedule_operationId_key"
  ON "SastEvidenceDeletionSchedule"("operationId");
CREATE UNIQUE INDEX "SastEvidenceDeletionSchedule_evidencePackId_key"
  ON "SastEvidenceDeletionSchedule"("evidencePackId");
CREATE UNIQUE INDEX "SastEvidenceDeletionSchedule_scheduleDigest_key"
  ON "SastEvidenceDeletionSchedule"("scheduleDigest");
CREATE UNIQUE INDEX "SastEvidenceDeletionSchedule_tenant_scope_key"
  ON "SastEvidenceDeletionSchedule"("id", "tenantId");
CREATE UNIQUE INDEX "SastEvidenceDeletionSchedule_operation_scope_key"
  ON "SastEvidenceDeletionSchedule"("id", "operationId", "tenantId");
CREATE INDEX "SastEvidenceDeletionSchedule_tenant_expiry_idx"
  ON "SastEvidenceDeletionSchedule"("tenantId", "repositoryBindingId", "deleteAfter");
CREATE INDEX "SastEvidenceDeletionSchedule_deleteAfter_idx"
  ON "SastEvidenceDeletionSchedule"("deleteAfter");
CREATE INDEX "SastEvidenceDeletionSchedule_buildDecisionId_idx"
  ON "SastEvidenceDeletionSchedule"("buildDecisionId");

CREATE UNIQUE INDEX "SastEvidenceAccessDecision_decisionDigest_key"
  ON "SastEvidenceAccessDecision"("decisionDigest");
CREATE UNIQUE INDEX "SastEvidenceAccessDecision_tenant_scope_key"
  ON "SastEvidenceAccessDecision"("id", "tenantId");
CREATE INDEX "SastEvidenceAccessDecision_lookup_idx"
  ON "SastEvidenceAccessDecision"("tenantId", "repositoryBindingId", "evidencePackId", "purpose");
CREATE INDEX "SastEvidenceAccessDecision_expiresAt_idx"
  ON "SastEvidenceAccessDecision"("evidenceExpiresAt");
CREATE INDEX "SastEvidenceAccessDecision_aiPayloadExpiresAt_idx"
  ON "SastEvidenceAccessDecision"("aiPayloadExpiresAt");
CREATE INDEX "SastEvidenceAccessDecision_deletionScheduleId_idx"
  ON "SastEvidenceAccessDecision"("deletionScheduleId");
CREATE INDEX "SastEvidenceAccessDecision_scan_scope_idx"
  ON "SastEvidenceAccessDecision"("scanRequestId", "tenantId", "repositoryBindingId");
CREATE INDEX "SastEvidenceAccessDecision_build_scope_idx"
  ON "SastEvidenceAccessDecision"("buildDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId");
CREATE INDEX "SastEvidenceDeletionSchedule_scan_scope_idx"
  ON "SastEvidenceDeletionSchedule"("scanRequestId", "tenantId", "repositoryBindingId");

CREATE UNIQUE INDEX "SastEvidenceDeletionClaim_leaseToken_key"
  ON "SastEvidenceDeletionClaim"("leaseToken");
CREATE UNIQUE INDEX "SastEvidenceDeletionClaim_schedule_scope_key"
  ON "SastEvidenceDeletionClaim"("scheduleId", "tenantId");
CREATE INDEX "SastEvidenceDeletionClaim_due_idx"
  ON "SastEvidenceDeletionClaim"("status", "nextAttemptAt", "leaseExpiresAt");
CREATE INDEX "SastEvidenceDeletionClaim_tenant_status_idx"
  ON "SastEvidenceDeletionClaim"("tenantId", "status");

CREATE UNIQUE INDEX "SastEvidenceDeletionProof_scheduleId_key"
  ON "SastEvidenceDeletionProof"("scheduleId");
CREATE UNIQUE INDEX "SastEvidenceDeletionProof_operationId_key"
  ON "SastEvidenceDeletionProof"("operationId");
CREATE UNIQUE INDEX "SastEvidenceDeletionProof_evidencePackId_key"
  ON "SastEvidenceDeletionProof"("evidencePackId");
CREATE UNIQUE INDEX "SastEvidenceDeletionProof_proofDigest_key"
  ON "SastEvidenceDeletionProof"("proofDigest");
CREATE UNIQUE INDEX "SastEvidenceDeletionProof_schedule_scope_key"
  ON "SastEvidenceDeletionProof"("scheduleId", "operationId", "tenantId");
CREATE INDEX "SastEvidenceDeletionProof_tenant_completed_idx"
  ON "SastEvidenceDeletionProof"("tenantId", "completedAt");
CREATE INDEX "SastEvidenceDeletionProof_buildDecisionId_idx"
  ON "SastEvidenceDeletionProof"("buildDecisionId");

ALTER TABLE "SastEvidenceDeletionSchedule"
  ADD CONSTRAINT "SastEvidenceDeletionSchedule_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastEvidenceDeletionSchedule"
  ADD CONSTRAINT "SastEvidenceDeletionSchedule_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastEvidenceDeletionSchedule"
  ADD CONSTRAINT "SastEvidenceDeletionSchedule_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastEvidenceDeletionSchedule"
  ADD CONSTRAINT "SastEvidenceDeletionSchedule_build_scope_fkey"
  FOREIGN KEY ("buildDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  REFERENCES "SastEvidenceBuildDecision"("id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastEvidenceAccessDecision"
  ADD CONSTRAINT "SastEvidenceAccessDecision_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastEvidenceAccessDecision"
  ADD CONSTRAINT "SastEvidenceAccessDecision_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastEvidenceAccessDecision"
  ADD CONSTRAINT "SastEvidenceAccessDecision_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastEvidenceAccessDecision"
  ADD CONSTRAINT "SastEvidenceAccessDecision_build_scope_fkey"
  FOREIGN KEY ("buildDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  REFERENCES "SastEvidenceBuildDecision"("id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastEvidenceAccessDecision"
  ADD CONSTRAINT "SastEvidenceAccessDecision_schedule_scope_fkey"
  FOREIGN KEY ("deletionScheduleId", "tenantId")
  REFERENCES "SastEvidenceDeletionSchedule"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastEvidenceDeletionClaim"
  ADD CONSTRAINT "SastEvidenceDeletionClaim_schedule_scope_fkey"
  FOREIGN KEY ("scheduleId", "tenantId")
  REFERENCES "SastEvidenceDeletionSchedule"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastEvidenceDeletionProof"
  ADD CONSTRAINT "SastEvidenceDeletionProof_schedule_scope_fkey"
  FOREIGN KEY ("scheduleId", "operationId", "tenantId")
  REFERENCES "SastEvidenceDeletionSchedule"("id", "operationId", "tenantId")
  -- Deliberate audit hold: normal offboarding soft-revokes tenant/repository
  -- scope. The documented exceptional purge deletes proof ledgers first.
  ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE FUNCTION "reject_sast_evidence_access_ledger_update"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'evidence access, schedule, and deletion proof ledgers are immutable'
    USING ERRCODE = '55000';
  RETURN OLD;
END;
$$;

CREATE TRIGGER "SastEvidenceAccessDecision_immutable_update"
  BEFORE UPDATE ON "SastEvidenceAccessDecision"
  FOR EACH ROW
  EXECUTE FUNCTION "reject_sast_evidence_access_ledger_update"();
CREATE TRIGGER "SastEvidenceDeletionSchedule_immutable_update"
  BEFORE UPDATE ON "SastEvidenceDeletionSchedule"
  FOR EACH ROW
  EXECUTE FUNCTION "reject_sast_evidence_access_ledger_update"();
CREATE TRIGGER "SastEvidenceDeletionProof_immutable_update"
  BEFORE UPDATE ON "SastEvidenceDeletionProof"
  FOR EACH ROW
  EXECUTE FUNCTION "reject_sast_evidence_access_ledger_update"();
