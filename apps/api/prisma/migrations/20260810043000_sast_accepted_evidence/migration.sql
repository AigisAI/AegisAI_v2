CREATE TABLE "SastEvidenceBuildDecision" (
  "id" TEXT NOT NULL,
  "freshnessDecisionId" TEXT NOT NULL,
  "coverageDecisionId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "occurrenceId" TEXT NOT NULL,
  "observationBatchId" TEXT NOT NULL,
  "normalizedFindingId" TEXT NOT NULL,
  "lineageId" TEXT NOT NULL,
  "findingFingerprint" TEXT NOT NULL,
  "fingerprintVersion" TEXT NOT NULL,
  "capability" "SastFindingCapability" NOT NULL,
  "policyVersion" TEXT NOT NULL,
  "candidateSetDigest" TEXT NOT NULL,
  "outcome" TEXT NOT NULL,
  "reasonCodes" JSONB NOT NULL,
  "selectedFragmentCount" INTEGER NOT NULL,
  "suppressedFragmentCount" INTEGER NOT NULL,
  "reconstructionStatus" TEXT NOT NULL,
  "reconstructionDecision" JSONB NOT NULL,
  "reconstructionDecisionDigest" TEXT NOT NULL,
  "evidencePackId" TEXT,
  "evidencePackDigest" TEXT,
  "authority" JSONB NOT NULL,
  "audit" JSONB NOT NULL,
  "decision" JSONB NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "decidedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastEvidenceBuildDecision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastEvidenceBuildDecision_contract_check" CHECK (
    "id" ~ '^sast-evidence-build://[a-f0-9]{64}$'
    AND "freshnessDecisionId" ~ '^sast-freshness://[a-f0-9]{64}$'
    AND "coverageDecisionId" ~ '^sast-coverage://[a-f0-9]{64}$'
    AND "occurrenceId" ~ '^finding-occurrence://[a-f0-9]{64}$'
    AND "observationBatchId" ~ '^finding-observation://[a-f0-9]{64}$'
    AND "lineageId" ~ '^finding-lineage://[a-f0-9]{64}$'
    AND "findingFingerprint" ~ '^sha256:[a-f0-9]{64}$'
    AND "fingerprintVersion" = 'sast-fingerprint-v1'
    AND "candidateSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "reconstructionDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "decisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "selectedFragmentCount" BETWEEN 0 AND 5
    AND "suppressedFragmentCount" >= 0
    AND "outcome" IN ('ACCEPTED', 'REJECTED')
    AND "reconstructionStatus" IN ('SAFE', 'RISK', 'NOT_CHECKED')
    AND jsonb_typeof("reasonCodes") = 'array'
    AND jsonb_typeof("reconstructionDecision") = 'object'
    AND jsonb_typeof("authority") = 'object'
    AND jsonb_typeof("audit") = 'object'
    AND jsonb_typeof("decision") = 'object'
    AND ("authority"->>'dashboardAccessAllowed')::boolean IS FALSE
    AND ("authority"->>'aiPayloadAllowed')::boolean IS FALSE
    AND ("authority"->>'policyAuthority')::boolean IS FALSE
    AND ("authority"->>'publicationAuthority')::boolean IS FALSE
    AND ("authority"->>'lifecycleMutationAuthority')::boolean IS FALSE
    AND ("audit"->>'rawSourceStored')::boolean IS FALSE
    AND ("audit"->>'secretValuesStored')::boolean IS FALSE
    AND ("audit"->>'dashboardPayloadCreated')::boolean IS FALSE
    AND ("audit"->>'aiPayloadCreated')::boolean IS FALSE
    AND ("audit"->>'publicationAttempted')::boolean IS FALSE
    AND (
      (
        "outcome" = 'ACCEPTED'
        AND "selectedFragmentCount" > 0
        AND "reconstructionStatus" = 'SAFE'
        AND jsonb_array_length("reasonCodes") = 0
        AND "evidencePackId" IS NOT NULL
        AND "evidencePackId" ~ '^sast-evidence-pack://[a-f0-9]{64}$'
        AND "evidencePackDigest" IS NOT NULL
        AND "evidencePackDigest" ~ '^sha256:[a-f0-9]{64}$'
        AND ("authority"->>'evidenceConstructionAuthority')::boolean IS TRUE
      )
      OR
      (
        "outcome" = 'REJECTED'
        AND "selectedFragmentCount" = 0
        AND jsonb_array_length("reasonCodes") > 0
        AND "evidencePackId" IS NULL
        AND "evidencePackDigest" IS NULL
        AND ("authority"->>'evidenceConstructionAuthority')::boolean IS FALSE
      )
    )
  )
);

CREATE TABLE "SastAcceptedEvidencePack" (
  "id" TEXT NOT NULL,
  "buildDecisionId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "occurrenceId" TEXT NOT NULL,
  "normalizedFindingId" TEXT NOT NULL,
  "lineageId" TEXT NOT NULL,
  "findingFingerprint" TEXT NOT NULL,
  "policyVersion" TEXT NOT NULL,
  "candidateSetDigest" TEXT NOT NULL,
  "totalBytes" INTEGER NOT NULL,
  "fragmentCount" INTEGER NOT NULL,
  "truncated" BOOLEAN NOT NULL,
  "suppressedFragmentCount" INTEGER NOT NULL,
  "reconstructionRiskChecked" BOOLEAN NOT NULL DEFAULT true,
  "reconstructionDecisionId" TEXT NOT NULL,
  "reconstructionDecisionDigest" TEXT NOT NULL,
  "classificationDecisionRef" TEXT,
  "deletionScheduleRef" TEXT,
  "dashboardSafe" BOOLEAN NOT NULL DEFAULT false,
  "aiSafe" BOOLEAN NOT NULL DEFAULT false,
  "pack" JSONB NOT NULL,
  "packDigest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "SastAcceptedEvidencePack_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastAcceptedEvidencePack_contract_check" CHECK (
    "id" ~ '^sast-evidence-pack://[a-f0-9]{64}$'
    AND "buildDecisionId" ~ '^sast-evidence-build://[a-f0-9]{64}$'
    AND "occurrenceId" ~ '^finding-occurrence://[a-f0-9]{64}$'
    AND "lineageId" ~ '^finding-lineage://[a-f0-9]{64}$'
    AND "findingFingerprint" ~ '^sha256:[a-f0-9]{64}$'
    AND "candidateSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "totalBytes" BETWEEN 1 AND 32768
    AND "fragmentCount" BETWEEN 1 AND 5
    AND "suppressedFragmentCount" >= 0
    AND "truncated" = ("suppressedFragmentCount" > 0)
    AND "reconstructionRiskChecked" = true
    AND "reconstructionDecisionId" ~ '^sast-evidence-reconstruction://[a-f0-9]{64}$'
    AND "reconstructionDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "classificationDecisionRef" IS NULL
    AND "deletionScheduleRef" IS NULL
    AND "dashboardSafe" = false
    AND "aiSafe" = false
    AND "packDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND jsonb_typeof("pack") = 'object'
    AND "expiresAt" > "createdAt"
    AND "expiresAt" <= "createdAt" + INTERVAL '7 days'
  )
);

CREATE TABLE "SastAcceptedEvidenceFragment" (
  "id" TEXT NOT NULL,
  "evidencePackId" TEXT NOT NULL,
  "buildDecisionId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "candidateId" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "role" TEXT NOT NULL,
  "normalizedPath" TEXT NOT NULL,
  "startLine" INTEGER NOT NULL,
  "endLine" INTEGER NOT NULL,
  "anchorStartLine" INTEGER NOT NULL,
  "anchorEndLine" INTEGER NOT NULL,
  "sourceFileLineCount" INTEGER NOT NULL,
  "redactedContent" TEXT NOT NULL,
  "byteSize" INTEGER NOT NULL,
  "sourceContentDigest" TEXT NOT NULL,
  "contentDigest" TEXT NOT NULL,
  "sourceAttestationRef" TEXT NOT NULL,
  "scannerRedactionDecisionRef" TEXT NOT NULL,
  "platformRedactionDecisionRef" TEXT NOT NULL,
  "secretRedactionApplied" BOOLEAN NOT NULL DEFAULT true,
  "rawSourceStored" BOOLEAN NOT NULL DEFAULT false,
  "isFullFile" BOOLEAN NOT NULL DEFAULT false,
  "fragment" JSONB NOT NULL,
  "fragmentDigest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastAcceptedEvidenceFragment_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastAcceptedEvidenceFragment_contract_check" CHECK (
    "id" ~ '^sast-evidence-fragment://[a-f0-9]{64}$'
    AND "evidencePackId" ~ '^sast-evidence-pack://[a-f0-9]{64}$'
    AND "buildDecisionId" ~ '^sast-evidence-build://[a-f0-9]{64}$'
    AND "candidateId" ~ '^sast-evidence-candidate://[a-f0-9]{64}$'
    AND "ordinal" BETWEEN 0 AND 4
    AND "role" IN ('PRIMARY', 'RELATED')
    AND "startLine" > 0
    AND "endLine" >= "startLine"
    AND "anchorStartLine" BETWEEN "startLine" AND "endLine"
    AND "anchorEndLine" BETWEEN "anchorStartLine" AND "endLine"
    AND "sourceFileLineCount" >= "endLine"
    AND NOT ("startLine" = 1 AND "endLine" = "sourceFileLineCount")
    AND "byteSize" BETWEEN 1 AND 8192
    AND "sourceContentDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "contentDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "secretRedactionApplied" = true
    AND "rawSourceStored" = false
    AND "isFullFile" = false
    AND "fragmentDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND jsonb_typeof("fragment") = 'object'
  )
);

CREATE UNIQUE INDEX "SastEvidenceBuildDecision_decisionDigest_key"
  ON "SastEvidenceBuildDecision"("decisionDigest");
CREATE UNIQUE INDEX "SastEvidenceBuildDecision_scope_key"
  ON "SastEvidenceBuildDecision"("id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId");
CREATE UNIQUE INDEX "SastEvidenceBuildDecision_replay_key"
  ON "SastEvidenceBuildDecision"("tenantId", "occurrenceId", "policyVersion", "candidateSetDigest");
CREATE INDEX "SastEvidenceBuildDecision_freshnessDecisionId_idx"
  ON "SastEvidenceBuildDecision"("freshnessDecisionId");
CREATE INDEX "SastEvidenceBuildDecision_occurrenceId_idx"
  ON "SastEvidenceBuildDecision"("occurrenceId");
CREATE INDEX "SastEvidenceBuildDecision_outcome_idx"
  ON "SastEvidenceBuildDecision"("tenantId", "outcome", "decidedAt");

CREATE UNIQUE INDEX "SastAcceptedEvidencePack_buildDecisionId_key"
  ON "SastAcceptedEvidencePack"("buildDecisionId");
CREATE UNIQUE INDEX "SastAcceptedEvidencePack_packDigest_key"
  ON "SastAcceptedEvidencePack"("packDigest");
CREATE UNIQUE INDEX "SastAcceptedEvidencePack_scope_key"
  ON "SastAcceptedEvidencePack"("id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId");
CREATE UNIQUE INDEX "SastAcceptedEvidencePack_decision_key"
  ON "SastAcceptedEvidencePack"("id", "buildDecisionId");
CREATE UNIQUE INDEX "SastAcceptedEvidencePack_decision_scope_key"
  ON "SastAcceptedEvidencePack"("buildDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId");
CREATE UNIQUE INDEX "SastAcceptedEvidencePack_fragment_scope_key"
  ON "SastAcceptedEvidencePack"("id", "buildDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId");
CREATE INDEX "SastAcceptedEvidencePack_scan_idx"
  ON "SastAcceptedEvidencePack"("tenantId", "scanRequestId", "createdAt");
CREATE INDEX "SastAcceptedEvidencePack_expiresAt_idx"
  ON "SastAcceptedEvidencePack"("expiresAt");

CREATE UNIQUE INDEX "SastAcceptedEvidenceFragment_fragmentDigest_key"
  ON "SastAcceptedEvidenceFragment"("fragmentDigest");
CREATE UNIQUE INDEX "SastAcceptedEvidenceFragment_pack_ordinal_key"
  ON "SastAcceptedEvidenceFragment"("evidencePackId", "ordinal");
CREATE UNIQUE INDEX "SastAcceptedEvidenceFragment_pack_candidate_key"
  ON "SastAcceptedEvidenceFragment"("evidencePackId", "candidateId");
CREATE INDEX "SastAcceptedEvidenceFragment_path_idx"
  ON "SastAcceptedEvidenceFragment"("tenantId", "scanRequestId", "normalizedPath");
CREATE INDEX "SastAcceptedEvidenceFragment_contentDigest_idx"
  ON "SastAcceptedEvidenceFragment"("contentDigest");

ALTER TABLE "SastEvidenceBuildDecision"
  ADD CONSTRAINT "SastEvidenceBuildDecision_freshness_scope_fkey"
  FOREIGN KEY ("freshnessDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  REFERENCES "SastScanFreshnessDecision"("id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastEvidenceBuildDecision"
  ADD CONSTRAINT "SastEvidenceBuildDecision_occurrence_scope_fkey"
  FOREIGN KEY ("occurrenceId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  REFERENCES "SastFindingOccurrence"("id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastAcceptedEvidencePack"
  ADD CONSTRAINT "SastAcceptedEvidencePack_decision_scope_fkey"
  FOREIGN KEY ("buildDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  REFERENCES "SastEvidenceBuildDecision"("id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastAcceptedEvidenceFragment"
  ADD CONSTRAINT "SastAcceptedEvidenceFragment_pack_scope_fkey"
  FOREIGN KEY ("evidencePackId", "buildDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  REFERENCES "SastAcceptedEvidencePack"("id", "buildDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  ON DELETE CASCADE ON UPDATE CASCADE;
