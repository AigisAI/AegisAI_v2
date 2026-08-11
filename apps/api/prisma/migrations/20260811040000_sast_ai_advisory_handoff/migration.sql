-- T043 accepts only a T042 AI access decision plus its durable normalized
-- occurrence. The request payload is never persisted; this ledger retains
-- canonical references, digests, expiry, and explicit zero downstream authority.
ALTER TABLE "AiAdvisoryMetadata"
  ADD COLUMN "sastHandoffId" TEXT;

CREATE UNIQUE INDEX "SastEvidenceAccessDecision_ai_scope_key"
  ON "SastEvidenceAccessDecision"(
    "id",
    "decisionDigest",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId",
    "occurrenceId",
    "evidencePackId",
    "findingFingerprint",
    "decidedAt"
  );

CREATE TABLE "SastAiAdvisoryHandoff" (
  "id" TEXT NOT NULL,
  "requestId" TEXT NOT NULL,
  "advisoryId" TEXT NOT NULL,
  "accessDecisionId" TEXT NOT NULL,
  "accessDecisionDigest" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "occurrenceId" TEXT NOT NULL,
  "normalizedFindingId" TEXT NOT NULL,
  "scannerRunId" TEXT NOT NULL,
  "evidencePackId" TEXT NOT NULL,
  "findingFingerprint" TEXT NOT NULL,
  "modelVersion" TEXT NOT NULL,
  "payloadExpiresAt" TIMESTAMP(3) NOT NULL,
  "requestDigest" TEXT NOT NULL,
  "handoffDigest" TEXT NOT NULL,
  "normalizedFindingAllowed" BOOLEAN NOT NULL DEFAULT true,
  "reducedEvidenceReferenceAllowed" BOOLEAN NOT NULL DEFAULT true,
  "aiPayloadAllowed" BOOLEAN NOT NULL DEFAULT true,
  "aiProviderCallAllowed" BOOLEAN NOT NULL DEFAULT true,
  "advisoryOnly" BOOLEAN NOT NULL DEFAULT true,
  "callerFindingAccepted" BOOLEAN NOT NULL DEFAULT false,
  "callerEvidenceAccepted" BOOLEAN NOT NULL DEFAULT false,
  "callerPromptAccepted" BOOLEAN NOT NULL DEFAULT false,
  "requestPayloadStored" BOOLEAN NOT NULL DEFAULT false,
  "rawSourceStored" BOOLEAN NOT NULL DEFAULT false,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT false,
  "evidenceFragmentStored" BOOLEAN NOT NULL DEFAULT false,
  "retrievalAttempted" BOOLEAN NOT NULL DEFAULT false,
  "toolsInvoked" BOOLEAN NOT NULL DEFAULT false,
  "retrievalAllowed" BOOLEAN NOT NULL DEFAULT false,
  "toolsAllowed" BOOLEAN NOT NULL DEFAULT false,
  "policyAuthority" BOOLEAN NOT NULL DEFAULT false,
  "publicationAuthority" BOOLEAN NOT NULL DEFAULT false,
  "lifecycleMutationAuthority" BOOLEAN NOT NULL DEFAULT false,
  "scmWriteAuthority" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "SastAiAdvisoryHandoff_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastAiAdvisoryHandoff_contract_check" CHECK (
    "id" ~ '^sast-ai-handoff://[a-f0-9]{64}$'
    AND "requestId" ~ '^sast-ai-request://[a-f0-9]{64}$'
    AND "advisoryId" ~ '^sast-ai-advisory://[a-f0-9]{64}$'
    AND "accessDecisionId" ~ '^sast-evidence-access://[a-f0-9]{64}$'
    AND "accessDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "evidencePackId" ~ '^sast-evidence-pack://[a-f0-9]{64}$'
    AND "findingFingerprint" ~ '^sha256:[a-f0-9]{64}$'
    AND "requestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "handoffDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND octet_length("modelVersion") BETWEEN 1 AND 128
    AND "modelVersion" ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,127}$'
    AND "createdAt" < "payloadExpiresAt"
    AND "payloadExpiresAt" <= "createdAt" + INTERVAL '24 hours'
    AND "normalizedFindingAllowed" IS TRUE
    AND "reducedEvidenceReferenceAllowed" IS TRUE
    AND "aiPayloadAllowed" IS TRUE
    AND "aiProviderCallAllowed" IS TRUE
    AND "advisoryOnly" IS TRUE
    AND "callerFindingAccepted" IS FALSE
    AND "callerEvidenceAccepted" IS FALSE
    AND "callerPromptAccepted" IS FALSE
    AND "requestPayloadStored" IS FALSE
    AND "rawSourceStored" IS FALSE
    AND "secretValueStored" IS FALSE
    AND "evidenceFragmentStored" IS FALSE
    AND "retrievalAttempted" IS FALSE
    AND "toolsInvoked" IS FALSE
    AND "retrievalAllowed" IS FALSE
    AND "toolsAllowed" IS FALSE
    AND "policyAuthority" IS FALSE
    AND "publicationAuthority" IS FALSE
    AND "lifecycleMutationAuthority" IS FALSE
    AND "scmWriteAuthority" IS FALSE
  )
);

CREATE UNIQUE INDEX "SastAiAdvisoryHandoff_requestId_key"
  ON "SastAiAdvisoryHandoff"("requestId");
CREATE UNIQUE INDEX "SastAiAdvisoryHandoff_advisoryId_key"
  ON "SastAiAdvisoryHandoff"("advisoryId");
CREATE UNIQUE INDEX "SastAiAdvisoryHandoff_requestDigest_key"
  ON "SastAiAdvisoryHandoff"("requestDigest");
CREATE UNIQUE INDEX "SastAiAdvisoryHandoff_handoffDigest_key"
  ON "SastAiAdvisoryHandoff"("handoffDigest");
CREATE UNIQUE INDEX "SastAiAdvisoryHandoff_tenant_scope_key"
  ON "SastAiAdvisoryHandoff"("id", "tenantId");
CREATE INDEX "SastAiAdvisoryHandoff_scan_idx"
  ON "SastAiAdvisoryHandoff"(
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "createdAt"
  );
CREATE INDEX "SastAiAdvisoryHandoff_access_scope_idx"
  ON "SastAiAdvisoryHandoff"(
    "accessDecisionId",
    "accessDecisionDigest",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId",
    "occurrenceId",
    "evidencePackId",
    "findingFingerprint",
    "createdAt"
  );
CREATE INDEX "SastAiAdvisoryHandoff_finding_scope_idx"
  ON "SastAiAdvisoryHandoff"(
    "normalizedFindingId",
    "tenantId",
    "scanRequestId",
    "scannerRunId"
  );
CREATE INDEX "SastAiAdvisoryHandoff_payloadExpiresAt_idx"
  ON "SastAiAdvisoryHandoff"("payloadExpiresAt");

CREATE UNIQUE INDEX "AiAdvisoryMetadata_sastHandoffId_key"
  ON "AiAdvisoryMetadata"("sastHandoffId");

ALTER TABLE "SastAiAdvisoryHandoff"
  ADD CONSTRAINT "SastAiAdvisoryHandoff_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SastAiAdvisoryHandoff"
  ADD CONSTRAINT "SastAiAdvisoryHandoff_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SastAiAdvisoryHandoff"
  ADD CONSTRAINT "SastAiAdvisoryHandoff_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SastAiAdvisoryHandoff"
  ADD CONSTRAINT "SastAiAdvisoryHandoff_occurrence_scope_fkey"
  FOREIGN KEY (
    "occurrenceId",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId"
  )
  REFERENCES "SastFindingOccurrence"(
    "id",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId"
  )
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SastAiAdvisoryHandoff"
  ADD CONSTRAINT "SastAiAdvisoryHandoff_finding_scope_fkey"
  FOREIGN KEY (
    "normalizedFindingId",
    "tenantId",
    "scanRequestId",
    "scannerRunId"
  )
  REFERENCES "NormalizedFinding"(
    "id",
    "tenantId",
    "scanRequestId",
    "scannerRunId"
  )
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SastAiAdvisoryHandoff"
  ADD CONSTRAINT "SastAiAdvisoryHandoff_access_scope_fkey"
  FOREIGN KEY (
    "accessDecisionId",
    "accessDecisionDigest",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId",
    "occurrenceId",
    "evidencePackId",
    "findingFingerprint",
    "createdAt"
  )
  REFERENCES "SastEvidenceAccessDecision"(
    "id",
    "decisionDigest",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId",
    "occurrenceId",
    "evidencePackId",
    "findingFingerprint",
    "decidedAt"
  )
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "AiAdvisoryMetadata"
  ADD CONSTRAINT "AiAdvisoryMetadata_sastHandoffId_fkey"
  FOREIGN KEY ("sastHandoffId") REFERENCES "SastAiAdvisoryHandoff"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE FUNCTION "reject_sast_ai_advisory_handoff_update"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'SAST AI advisory handoff ledgers are immutable'
    USING ERRCODE = '55000';
  RETURN OLD;
END;
$$;

CREATE TRIGGER "SastAiAdvisoryHandoff_immutable_update"
  BEFORE UPDATE ON "SastAiAdvisoryHandoff"
  FOR EACH ROW
  EXECUTE FUNCTION "reject_sast_ai_advisory_handoff_update"();

CREATE TRIGGER "SastAiAdvisoryHandoff_immutable_delete"
  BEFORE DELETE ON "SastAiAdvisoryHandoff"
  FOR EACH ROW
  EXECUTE FUNCTION "reject_sast_ai_advisory_handoff_update"();
