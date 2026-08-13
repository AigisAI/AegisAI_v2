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

-- This coordination ledger is not authoritative product state. Every writer
-- that can change a T044 snapshot advances and locks the same scoped row that
-- proof creation locks before reading the snapshot. That makes a concurrent
-- write a real PostgreSQL serialization conflict instead of a same-snapshot
-- before/after comparison.
CREATE TABLE "SastAiAdvisoryAuthorityFence" (
  "scopeKey" TEXT NOT NULL,
  "version" BIGINT NOT NULL DEFAULT 1,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastAiAdvisoryAuthorityFence_pkey" PRIMARY KEY ("scopeKey"),
  CONSTRAINT "SastAiAdvisoryAuthorityFence_contract_check" CHECK (
    octet_length("scopeKey") BETWEEN 1 AND 4096
    AND "version" >= 1
  )
);

COMMENT ON TABLE "SastAiAdvisoryAuthorityFence" IS
  'Internal T044 concurrency fence; contains only canonical scope keys and monotonic versions.';

CREATE FUNCTION "sast_ai_authority_scan_fence_key"(
  tenant_id TEXT,
  scan_request_id TEXT
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT jsonb_build_array(
    'sast-ai-authority-scan-v1',
    tenant_id,
    scan_request_id
  )::TEXT
$$;

CREATE FUNCTION "sast_ai_authority_lifecycle_fence_key"(
  tenant_id TEXT,
  repository_binding_id TEXT,
  lifecycle_context_key TEXT,
  lineage_id TEXT
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT jsonb_build_array(
    'sast-ai-authority-lifecycle-v1',
    tenant_id,
    repository_binding_id,
    lifecycle_context_key,
    lineage_id
  )::TEXT
$$;

CREATE FUNCTION "sast_ai_authority_finding_fence_key"(
  tenant_id TEXT,
  normalized_finding_id TEXT
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT jsonb_build_array(
    'sast-ai-authority-finding-v1',
    tenant_id,
    normalized_finding_id
  )::TEXT
$$;

CREATE FUNCTION "sast_ai_authority_advisory_fence_key"(
  tenant_id TEXT,
  advisory_id TEXT
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT jsonb_build_array(
    'sast-ai-authority-advisory-v1',
    tenant_id,
    advisory_id
  )::TEXT
$$;

CREATE FUNCTION "touch_sast_ai_advisory_authority_fences"(
  scope_keys TEXT[]
)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  current_scope_key TEXT;
BEGIN
  FOR current_scope_key IN
    SELECT DISTINCT scope_key
    FROM unnest(scope_keys) AS requested(scope_key)
    WHERE scope_key IS NOT NULL AND octet_length(scope_key) > 0
    ORDER BY scope_key
  LOOP
    INSERT INTO public."SastAiAdvisoryAuthorityFence" (
      "scopeKey",
      "version"
    ) VALUES (
      current_scope_key,
      1
    )
    ON CONFLICT ("scopeKey") DO UPDATE
    SET "version" =
      public."SastAiAdvisoryAuthorityFence"."version" + 1;
  END LOOP;
END;
$$;

CREATE FUNCTION "fence_sast_ai_authority_normalized_finding"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  scope_keys TEXT[] := ARRAY[]::TEXT[];
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') THEN
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_scan_fence_key"(
        OLD."tenantId",
        OLD."scanRequestId"
      )
    );
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_finding_fence_key"(
        OLD."tenantId",
        OLD."id"
      )
    );
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_scan_fence_key"(
        NEW."tenantId",
        NEW."scanRequestId"
      )
    );
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_finding_fence_key"(
        NEW."tenantId",
        NEW."id"
      )
    );
  END IF;
  PERFORM public."touch_sast_ai_advisory_authority_fences"(scope_keys);
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "fence_sast_ai_authority_lifecycle_state"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  scope_keys TEXT[] := ARRAY[]::TEXT[];
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') THEN
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_lifecycle_fence_key"(
        OLD."tenantId",
        OLD."repositoryBindingId",
        OLD."lifecycleContextKey",
        OLD."lineageId"
      )
    );
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_lifecycle_fence_key"(
        NEW."tenantId",
        NEW."repositoryBindingId",
        NEW."lifecycleContextKey",
        NEW."lineageId"
      )
    );
  END IF;
  PERFORM public."touch_sast_ai_advisory_authority_fences"(scope_keys);
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "fence_sast_ai_authority_finding_reference"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  scope_keys TEXT[] := ARRAY[]::TEXT[];
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') AND OLD."findingId" IS NOT NULL THEN
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_finding_fence_key"(
        OLD."tenantId",
        OLD."findingId"
      )
    );
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') AND NEW."findingId" IS NOT NULL THEN
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_finding_fence_key"(
        NEW."tenantId",
        NEW."findingId"
      )
    );
  END IF;
  PERFORM public."touch_sast_ai_advisory_authority_fences"(scope_keys);
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "fence_sast_ai_authority_waiver"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  scope_keys TEXT[] := ARRAY[]::TEXT[];
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') AND OLD."scope" LIKE 'finding:_%' THEN
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_finding_fence_key"(
        OLD."tenantId",
        substring(OLD."scope" FROM 9)
      )
    );
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') AND NEW."scope" LIKE 'finding:_%' THEN
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_finding_fence_key"(
        NEW."tenantId",
        substring(NEW."scope" FROM 9)
      )
    );
  END IF;
  PERFORM public."touch_sast_ai_advisory_authority_fences"(scope_keys);
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "fence_sast_ai_authority_advisory_metadata"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  scope_keys TEXT[] := ARRAY[]::TEXT[];
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') THEN
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_advisory_fence_key"(
        OLD."tenantId",
        OLD."id"
      )
    );
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    scope_keys := array_append(
      scope_keys,
      public."sast_ai_authority_advisory_fence_key"(
        NEW."tenantId",
        NEW."id"
      )
    );
  END IF;
  PERFORM public."touch_sast_ai_advisory_authority_fences"(scope_keys);
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

INSERT INTO "SastAiAdvisoryAuthorityFence" ("scopeKey", "version")
SELECT DISTINCT scope_key, 1
FROM (
  SELECT "sast_ai_authority_scan_fence_key"(
    "tenantId",
    "scanRequestId"
  ) AS scope_key
  FROM "NormalizedFinding"
  UNION ALL
  SELECT "sast_ai_authority_finding_fence_key"(
    "tenantId",
    "id"
  ) AS scope_key
  FROM "NormalizedFinding"
  UNION ALL
  SELECT "sast_ai_authority_lifecycle_fence_key"(
    "tenantId",
    "repositoryBindingId",
    "lifecycleContextKey",
    "lineageId"
  ) AS scope_key
  FROM "SastFindingLifecycleState"
  UNION ALL
  SELECT "sast_ai_authority_advisory_fence_key"(
    "tenantId",
    "id"
  ) AS scope_key
  FROM "AiAdvisoryMetadata"
) AS existing_scopes
ON CONFLICT ("scopeKey") DO NOTHING;

CREATE TRIGGER "NormalizedFinding_ai_authority_fence"
  BEFORE INSERT OR UPDATE OR DELETE ON "NormalizedFinding"
  FOR EACH ROW
  EXECUTE FUNCTION "fence_sast_ai_authority_normalized_finding"();

CREATE TRIGGER "SastFindingLifecycleState_ai_authority_fence"
  BEFORE INSERT OR UPDATE OR DELETE ON "SastFindingLifecycleState"
  FOR EACH ROW
  EXECUTE FUNCTION "fence_sast_ai_authority_lifecycle_state"();

CREATE TRIGGER "PolicyDecision_ai_authority_fence"
  BEFORE INSERT OR UPDATE OR DELETE ON "PolicyDecision"
  FOR EACH ROW
  EXECUTE FUNCTION "fence_sast_ai_authority_finding_reference"();

CREATE TRIGGER "Suppression_ai_authority_fence"
  BEFORE INSERT OR UPDATE OR DELETE ON "Suppression"
  FOR EACH ROW
  EXECUTE FUNCTION "fence_sast_ai_authority_finding_reference"();

CREATE TRIGGER "Waiver_ai_authority_fence"
  BEFORE INSERT OR UPDATE OR DELETE ON "Waiver"
  FOR EACH ROW
  EXECUTE FUNCTION "fence_sast_ai_authority_waiver"();

CREATE TRIGGER "AiAdvisoryMetadata_ai_authority_fence"
  BEFORE INSERT OR UPDATE OR DELETE ON "AiAdvisoryMetadata"
  FOR EACH ROW
  EXECUTE FUNCTION "fence_sast_ai_authority_advisory_metadata"();

CREATE FUNCTION "acquire_sast_ai_advisory_context_fence"(
  tenant_id TEXT,
  advisory_id TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  locked_context_count INTEGER := 0;
BEGIN
  PERFORM 1
  FROM public."SastAiAdvisoryAuthorityFence"
  WHERE "scopeKey" = public."sast_ai_authority_advisory_fence_key"(
    tenant_id,
    advisory_id
  )
  FOR UPDATE;
  GET DIAGNOSTICS locked_context_count = ROW_COUNT;
  RETURN locked_context_count;
END;
$$;

CREATE FUNCTION "acquire_sast_ai_advisory_authority_fence"(
  tenant_id TEXT,
  scan_request_id TEXT,
  repository_binding_id TEXT,
  lifecycle_context_key TEXT,
  lineage_id TEXT,
  normalized_finding_id TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  current_scope_key TEXT;
  locked_scope_count INTEGER := 0;
  required_scope_keys TEXT[] := ARRAY[
    public."sast_ai_authority_scan_fence_key"(
      tenant_id,
      scan_request_id
    ),
    public."sast_ai_authority_lifecycle_fence_key"(
      tenant_id,
      repository_binding_id,
      lifecycle_context_key,
      lineage_id
    ),
    public."sast_ai_authority_finding_fence_key"(
      tenant_id,
      normalized_finding_id
    )
  ];
BEGIN
  FOR current_scope_key IN
    SELECT "scopeKey"
    FROM public."SastAiAdvisoryAuthorityFence"
    WHERE "scopeKey" = ANY(required_scope_keys)
    ORDER BY "scopeKey"
    FOR UPDATE
  LOOP
    locked_scope_count := locked_scope_count + 1;
  END LOOP;
  RETURN locked_scope_count;
END;
$$;

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
  ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastAiAdvisoryAuthorityProof"
  ADD CONSTRAINT "SastAiAdvisoryAuthorityProof_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastAiAdvisoryAuthorityProof"
  ADD CONSTRAINT "SastAiAdvisoryAuthorityProof_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastAiAdvisoryAuthorityProof"
  ADD CONSTRAINT "SastAiAdvisoryAuthorityProof_handoff_scope_fkey"
  FOREIGN KEY ("handoffId", "tenantId")
  REFERENCES "SastAiAdvisoryHandoff"("id", "tenantId")
  ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastAiAdvisoryAuthorityProof"
  ADD CONSTRAINT "SastAiAdvisoryAuthorityProof_advisoryId_fkey"
  FOREIGN KEY ("advisoryId") REFERENCES "AiAdvisoryMetadata"("id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

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
