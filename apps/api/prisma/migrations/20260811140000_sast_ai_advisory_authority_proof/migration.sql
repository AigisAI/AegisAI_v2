-- T044 proves that consuming T043 advisory output performs one proof-ledger
-- write and no authoritative finding, lifecycle, policy, waiver, or suppression
-- mutation. The ledger stores only scope references, counts, digests, and fixed
-- zero-authority bits; it never stores advisory, source, evidence, or secret text.
CREATE TABLE "SastAiAdvisoryAuthorityProof" (
  "id" TEXT NOT NULL,
  "advisoryId" TEXT NOT NULL,
  "handoffId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "occurrenceId" TEXT NOT NULL,
  "normalizedFindingId" TEXT NOT NULL,
  "findingFingerprint" TEXT NOT NULL,
  "requestDigest" TEXT NOT NULL,
  "handoffDigest" TEXT NOT NULL,
  "normalizedFindingCount" INTEGER NOT NULL,
  "normalizedFindingSetDigest" TEXT NOT NULL,
  "targetFindingDigest" TEXT NOT NULL,
  "lifecycleStateCount" INTEGER NOT NULL,
  "lifecycleStateSetDigest" TEXT NOT NULL,
  "policyDecisionCount" INTEGER NOT NULL,
  "policyDecisionSetDigest" TEXT NOT NULL,
  "waiverCount" INTEGER NOT NULL,
  "waiverSetDigest" TEXT NOT NULL,
  "suppressionCount" INTEGER NOT NULL,
  "suppressionSetDigest" TEXT NOT NULL,
  "beforeStateDigest" TEXT NOT NULL,
  "afterStateDigest" TEXT NOT NULL,
  "findingCreateAuthority" BOOLEAN NOT NULL DEFAULT false,
  "findingStatusMutationAuthority" BOOLEAN NOT NULL DEFAULT false,
  "findingSeverityMutationAuthority" BOOLEAN NOT NULL DEFAULT false,
  "lifecycleMutationAuthority" BOOLEAN NOT NULL DEFAULT false,
  "waiverMutationAuthority" BOOLEAN NOT NULL DEFAULT false,
  "suppressionMutationAuthority" BOOLEAN NOT NULL DEFAULT false,
  "policyOverrideAuthority" BOOLEAN NOT NULL DEFAULT false,
  "blockDecisionAuthority" BOOLEAN NOT NULL DEFAULT false,
  "publicationAuthority" BOOLEAN NOT NULL DEFAULT false,
  "scmWriteAuthority" BOOLEAN NOT NULL DEFAULT false,
  "advisoryOnly" BOOLEAN NOT NULL DEFAULT true,
  "proofLedgerWritten" BOOLEAN NOT NULL DEFAULT true,
  "authoritativeFindingWritten" BOOLEAN NOT NULL DEFAULT false,
  "lifecycleStateWritten" BOOLEAN NOT NULL DEFAULT false,
  "policyDecisionWritten" BOOLEAN NOT NULL DEFAULT false,
  "waiverWritten" BOOLEAN NOT NULL DEFAULT false,
  "suppressionWritten" BOOLEAN NOT NULL DEFAULT false,
  "callerAuthorityFieldsAccepted" BOOLEAN NOT NULL DEFAULT false,
  "advisoryContentStored" BOOLEAN NOT NULL DEFAULT false,
  "sourceContentStored" BOOLEAN NOT NULL DEFAULT false,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT false,
  "verifiedAt" TIMESTAMP(3) NOT NULL,
  "proofDigest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastAiAdvisoryAuthorityProof_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastAiAdvisoryAuthorityProof_contract_check" CHECK (
    "id" ~ '^sast-ai-authority-proof://[a-f0-9]{64}$'
    AND "advisoryId" ~ '^sast-ai-advisory://[a-f0-9]{64}$'
    AND "handoffId" ~ '^sast-ai-handoff://[a-f0-9]{64}$'
    AND "occurrenceId" ~ '^finding-occurrence://[a-f0-9]{64}$'
    AND "findingFingerprint" ~ '^sha256:[a-f0-9]{64}$'
    AND "requestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "handoffDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "normalizedFindingSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "targetFindingDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "lifecycleStateSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "policyDecisionSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "waiverSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "suppressionSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "beforeStateDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "afterStateDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "proofDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND octet_length("tenantId") BETWEEN 1 AND 512
    AND octet_length("repositoryBindingId") BETWEEN 1 AND 512
    AND octet_length("scanRequestId") BETWEEN 1 AND 512
    AND octet_length("attemptId") BETWEEN 1 AND 512
    AND octet_length("normalizedFindingId") BETWEEN 1 AND 512
    AND "normalizedFindingCount" BETWEEN 1 AND 25000
    AND "lifecycleStateCount" = 1
    AND "policyDecisionCount" BETWEEN 0 AND 1024
    AND "waiverCount" BETWEEN 0 AND 1024
    AND "suppressionCount" BETWEEN 0 AND 1024
    AND "beforeStateDigest" = "afterStateDigest"
    AND "findingCreateAuthority" IS FALSE
    AND "findingStatusMutationAuthority" IS FALSE
    AND "findingSeverityMutationAuthority" IS FALSE
    AND "lifecycleMutationAuthority" IS FALSE
    AND "waiverMutationAuthority" IS FALSE
    AND "suppressionMutationAuthority" IS FALSE
    AND "policyOverrideAuthority" IS FALSE
    AND "blockDecisionAuthority" IS FALSE
    AND "publicationAuthority" IS FALSE
    AND "scmWriteAuthority" IS FALSE
    AND "advisoryOnly" IS TRUE
    AND "proofLedgerWritten" IS TRUE
    AND "authoritativeFindingWritten" IS FALSE
    AND "lifecycleStateWritten" IS FALSE
    AND "policyDecisionWritten" IS FALSE
    AND "waiverWritten" IS FALSE
    AND "suppressionWritten" IS FALSE
    AND "callerAuthorityFieldsAccepted" IS FALSE
    AND "advisoryContentStored" IS FALSE
    AND "sourceContentStored" IS FALSE
    AND "secretValueStored" IS FALSE
  )
);

COMMENT ON TABLE "SastAiAdvisoryAuthorityProof" IS
  'Immutable T044 security proof retained with advisory audit metadata; controlled tenant/legal hard purge requires prior audit export and explicit privileged maintenance.';

CREATE UNIQUE INDEX "SastAiAdvisoryAuthorityProof_advisoryId_key"
  ON "SastAiAdvisoryAuthorityProof"("advisoryId");
CREATE UNIQUE INDEX "SastAiAdvisoryAuthorityProof_handoffId_key"
  ON "SastAiAdvisoryAuthorityProof"("handoffId");
CREATE UNIQUE INDEX "SastAiAdvisoryAuthorityProof_proofDigest_key"
  ON "SastAiAdvisoryAuthorityProof"("proofDigest");
CREATE UNIQUE INDEX "SastAiAdvisoryAuthorityProof_tenant_scope_key"
  ON "SastAiAdvisoryAuthorityProof"("id", "tenantId");
CREATE UNIQUE INDEX "SastAiAdvisoryAuthorityProof_handoff_tenant_key"
  ON "SastAiAdvisoryAuthorityProof"("handoffId", "tenantId");
CREATE INDEX "SastAiAdvisoryAuthorityProof_scan_idx"
  ON "SastAiAdvisoryAuthorityProof"(
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "verifiedAt"
  );
CREATE INDEX "SastAiAdvisoryAuthorityProof_occurrence_scope_idx"
  ON "SastAiAdvisoryAuthorityProof"(
    "occurrenceId",
    "tenantId",
    "repositoryBindingId",
    "scanRequestId",
    "attemptId"
  );
CREATE INDEX "SastAiAdvisoryAuthorityProof_finding_scope_idx"
  ON "SastAiAdvisoryAuthorityProof"(
    "normalizedFindingId",
    "tenantId",
    "scanRequestId"
  );

ALTER TABLE "SastAiAdvisoryAuthorityProof"
  ADD CONSTRAINT "SastAiAdvisoryAuthorityProof_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SastAiAdvisoryAuthorityProof"
  ADD CONSTRAINT "SastAiAdvisoryAuthorityProof_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SastAiAdvisoryAuthorityProof"
  ADD CONSTRAINT "SastAiAdvisoryAuthorityProof_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SastAiAdvisoryAuthorityProof"
  ADD CONSTRAINT "SastAiAdvisoryAuthorityProof_handoff_scope_fkey"
  FOREIGN KEY ("handoffId", "tenantId")
  REFERENCES "SastAiAdvisoryHandoff"("id", "tenantId")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SastAiAdvisoryAuthorityProof"
  ADD CONSTRAINT "SastAiAdvisoryAuthorityProof_advisoryId_fkey"
  FOREIGN KEY ("advisoryId") REFERENCES "AiAdvisoryMetadata"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE FUNCTION "reject_sast_ai_advisory_authority_proof_update"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'SAST AI advisory authority proof ledgers are immutable'
    USING ERRCODE = '55000';
  RETURN OLD;
END;
$$;

CREATE TRIGGER "SastAiAdvisoryAuthorityProof_immutable_update"
  BEFORE UPDATE ON "SastAiAdvisoryAuthorityProof"
  FOR EACH ROW
  EXECUTE FUNCTION "reject_sast_ai_advisory_authority_proof_update"();

CREATE TRIGGER "SastAiAdvisoryAuthorityProof_immutable_delete"
  BEFORE DELETE ON "SastAiAdvisoryAuthorityProof"
  FOR EACH ROW
  EXECUTE FUNCTION "reject_sast_ai_advisory_authority_proof_update"();
