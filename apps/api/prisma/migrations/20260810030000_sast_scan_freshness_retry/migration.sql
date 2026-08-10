-- T039 remains an immutable zero-authority source ledger. Install the
-- replacement without scanning the populated table; prisma:online-schema
-- validates it before dropping the old name, so there is no unguarded window.
ALTER TABLE "SastExternalPublicationDecision"
  ADD CONSTRAINT "SastExternalPublicationDecision_t039_source_check" CHECK (
    "externalCommentAllowed" = false
    AND "blockingStatusAllowed" = false
    AND "aiAdvisoryAllowed" = false
    AND "lifecycleMutationAllowed" = false
    AND "latestTargetAuthority" = 'UNAVAILABLE'
    AND "staleStatus" = 'UNKNOWN'
    AND "comparabilityStatus" = 'UNKNOWN'
  ) NOT VALID;

CREATE TABLE "SastLatestTargetObservation" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "provider" "RepoProvider" NOT NULL,
  "targetRef" TEXT NOT NULL,
  "headCommitSha" TEXT NOT NULL,
  "sequence" BIGINT NOT NULL,
  "observerRef" TEXT NOT NULL,
  "observation" JSONB NOT NULL,
  "observationDigest" TEXT NOT NULL,
  "observedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastLatestTargetObservation_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastLatestTargetObservation_contract_check" CHECK (
    "id" ~ '^sast-target-observation://[a-f0-9]{64}$'
    AND "headCommitSha" ~ '^[a-f0-9]{40}([a-f0-9]{24})?$'
    AND "sequence" > 0
    AND "observationDigest" ~ '^sha256:[a-f0-9]{64}$'
  )
);

CREATE TABLE "SastScanFreshnessDecision" (
  "id" TEXT NOT NULL,
  "coverageDecisionId" TEXT NOT NULL,
  "previousCoverageDecisionId" TEXT,
  "observationId" TEXT,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "provider" "RepoProvider" NOT NULL,
  "targetRef" TEXT NOT NULL,
  "commitSha" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "attemptNumber" INTEGER NOT NULL,
  "coverageDecisionDigest" TEXT NOT NULL,
  "lifecycleContextKey" TEXT NOT NULL,
  "canonicalScanKey" TEXT NOT NULL,
  "planDigest" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "profileFamily" TEXT NOT NULL,
  "requiredCapabilities" JSONB NOT NULL,
  "fingerprintVersion" TEXT NOT NULL,
  "lifecycleEligibilityScope" TEXT NOT NULL,
  "observationDigest" TEXT,
  "observedHeadCommitSha" TEXT,
  "observationSequence" BIGINT,
  "previousCoverageDecisionDigest" TEXT,
  "previousScanRequestId" TEXT,
  "previousCommitSha" TEXT,
  "latestTargetAuthority" TEXT NOT NULL,
  "staleStatus" TEXT NOT NULL,
  "comparabilityStatus" TEXT NOT NULL,
  "externalCommentEligible" BOOLEAN NOT NULL DEFAULT false,
  "blockingStatusEligible" BOOLEAN NOT NULL DEFAULT false,
  "lifecycleMutationAllowed" BOOLEAN NOT NULL DEFAULT false,
  "aiAdvisoryAllowed" BOOLEAN NOT NULL DEFAULT false,
  "publicationAttempted" BOOLEAN NOT NULL DEFAULT false,
  "reasonCodes" JSONB NOT NULL,
  "decision" JSONB NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "decidedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastScanFreshnessDecision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastScanFreshnessDecision_contract_check" CHECK (
    "id" ~ '^sast-freshness://[a-f0-9]{64}$'
    AND "commitSha" ~ '^[a-f0-9]{40}([a-f0-9]{24})?$'
    AND "attemptNumber" BETWEEN 1 AND 2
    AND "coverageDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "lifecycleContextKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "canonicalScanKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "planDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "profileFamily" IN ('JAVA', 'COMMON')
    AND "fingerprintVersion" = 'sast-fingerprint-v1'
    AND "lifecycleEligibilityScope" ~ '^sha256:[a-f0-9]{64}$'
    AND "latestTargetAuthority" IN ('VERIFIED', 'UNAVAILABLE', 'INVALID')
    AND "staleStatus" IN ('FRESH', 'STALE', 'UNKNOWN')
    AND "comparabilityStatus" IN ('COMPARABLE', 'INCOMPARABLE', 'UNKNOWN')
    AND "aiAdvisoryAllowed" = false
    AND "publicationAttempted" = false
    AND (
      ("observationId" IS NULL
        AND "observationDigest" IS NULL
        AND "observedHeadCommitSha" IS NULL
        AND "observationSequence" IS NULL)
      OR
      ("observationId" IS NOT NULL
        AND "observationDigest" ~ '^sha256:[a-f0-9]{64}$'
        AND "observedHeadCommitSha" ~ '^[a-f0-9]{40}([a-f0-9]{24})?$'
        AND "observationSequence" > 0)
    )
    AND (
      ("previousCoverageDecisionId" IS NULL
        AND "previousCoverageDecisionDigest" IS NULL
        AND "previousScanRequestId" IS NULL
        AND "previousCommitSha" IS NULL)
      OR
      ("previousCoverageDecisionId" IS NOT NULL
        AND "previousCoverageDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
        AND "previousScanRequestId" IS NOT NULL
        AND "previousCommitSha" ~ '^[a-f0-9]{40}([a-f0-9]{24})?$')
    )
    AND (
      ("externalCommentEligible" = true
        AND "blockingStatusEligible" = true
        AND "lifecycleMutationAllowed" = true
        AND "latestTargetAuthority" = 'VERIFIED'
        AND "staleStatus" = 'FRESH'
        AND "comparabilityStatus" = 'COMPARABLE'
        AND "observationId" IS NOT NULL
        AND "previousCoverageDecisionId" IS NOT NULL
        AND jsonb_array_length("reasonCodes") = 0)
      OR
      ("externalCommentEligible" = false
        AND "blockingStatusEligible" = false
        AND "lifecycleMutationAllowed" = false
        AND jsonb_array_length("reasonCodes") > 0)
    )
  )
);

CREATE TABLE "SastScanRetryDecision" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "canonicalScanKey" TEXT NOT NULL,
  "planDigest" TEXT NOT NULL,
  "originalScannerSetDigest" TEXT NOT NULL,
  "previousAttemptId" TEXT NOT NULL,
  "previousAttemptNumber" INTEGER NOT NULL,
  "previousSandboxId" TEXT NOT NULL,
  "previousWorkloadIdentityRef" TEXT NOT NULL,
  "requestedAttemptId" TEXT NOT NULL,
  "requestedAttemptNumber" INTEGER NOT NULL,
  "requestedSandboxId" TEXT NOT NULL,
  "requestedWorkloadIdentityRef" TEXT NOT NULL,
  "retryAllowed" BOOLEAN NOT NULL,
  "previousFailureClass" TEXT,
  "previousCompletedAt" TIMESTAMP(3),
  "previousFinalAuditEventId" TEXT,
  "currentScannerSetDigest" TEXT,
  "scannerSetAvailable" BOOLEAN NOT NULL,
  "killSwitchStatus" TEXT NOT NULL,
  "killSwitchSnapshotDigest" TEXT,
  "reasonCodes" JSONB NOT NULL,
  "decision" JSONB NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "decidedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastScanRetryDecision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastScanRetryDecision_contract_check" CHECK (
    "id" ~ '^sast-retry://[a-f0-9]{64}$'
    AND "canonicalScanKey" ~ '^sha256:[a-f0-9]{64}$'
    AND "planDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "originalScannerSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "previousAttemptNumber" > 0
    AND "requestedAttemptNumber" > 0
    AND "requestedAttemptNumber" <= 100
    AND ("currentScannerSetDigest" IS NULL OR "currentScannerSetDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND "killSwitchStatus" IN ('CLEAR', 'ACTIVE', 'UNAVAILABLE')
    AND ("killSwitchSnapshotDigest" IS NULL OR "killSwitchSnapshotDigest" ~ '^sha256:[a-f0-9]{64}$')
    AND (
      ("retryAllowed" = false
        AND jsonb_array_length("reasonCodes") > 0)
      OR (
        "retryAllowed" = true
        AND "previousAttemptNumber" = 1
        AND "requestedAttemptNumber" = 2
        AND "previousFailureClass" = 'RETRYABLE_INFRASTRUCTURE'
        AND "previousCompletedAt" IS NOT NULL
        AND "previousFinalAuditEventId" IS NOT NULL
        AND "scannerSetAvailable" = true
        AND "killSwitchStatus" = 'CLEAR'
        AND "currentScannerSetDigest" = "originalScannerSetDigest"
        AND "killSwitchSnapshotDigest" IS NOT NULL
        AND "previousAttemptId" <> "requestedAttemptId"
        AND "previousSandboxId" <> "requestedSandboxId"
        AND "previousWorkloadIdentityRef" <> "requestedWorkloadIdentityRef"
        AND jsonb_array_length("reasonCodes") = 0
      )
    )
  )
);

ALTER TABLE "SastScanAttempt"
  ADD COLUMN "retryDecisionId" TEXT;

-- Existing pre-T040 attempt-two rows may not have an authority reference. The
-- NOT VALID form is rolling-safe while enforcing the invariant for every new
-- or updated row after this migration.
ALTER TABLE "SastScanAttempt"
  ADD CONSTRAINT "SastScanAttempt_retry_authority_check" CHECK (
    ("attemptNumber" = 1 AND "retryDecisionId" IS NULL)
    OR ("attemptNumber" = 2 AND "retryDecisionId" IS NOT NULL)
  ) NOT VALID;

CREATE UNIQUE INDEX "SastLatestTargetObservation_observationDigest_key"
  ON "SastLatestTargetObservation"("observationDigest");
CREATE UNIQUE INDEX "SastLatestTargetObservation_scope_key"
  ON "SastLatestTargetObservation"("id", "tenantId", "repositoryBindingId", "provider", "targetRef");
CREATE UNIQUE INDEX "SastLatestTargetObservation_sequence_key"
  ON "SastLatestTargetObservation"("tenantId", "repositoryBindingId", "provider", "targetRef", "sequence");
CREATE INDEX "SastLatestTargetObservation_latest_idx"
  ON "SastLatestTargetObservation"("tenantId", "repositoryBindingId", "provider", "targetRef", "observedAt" DESC);

CREATE UNIQUE INDEX "SastScanFreshnessDecision_coverageDecisionId_key"
  ON "SastScanFreshnessDecision"("coverageDecisionId");
CREATE UNIQUE INDEX "SastScanFreshnessDecision_decisionDigest_key"
  ON "SastScanFreshnessDecision"("decisionDigest");
CREATE UNIQUE INDEX "SastScanFreshnessDecision_scope_key"
  ON "SastScanFreshnessDecision"("id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId");
CREATE UNIQUE INDEX "SastScanFreshnessDecision_coverage_scope_key"
  ON "SastScanFreshnessDecision"("coverageDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId");
CREATE INDEX "SastScanFreshnessDecision_target_idx"
  ON "SastScanFreshnessDecision"("tenantId", "repositoryBindingId", "targetRef", "decidedAt" DESC);
CREATE INDEX "SastScanFreshnessDecision_previousCoverageDecisionId_idx"
  ON "SastScanFreshnessDecision"("previousCoverageDecisionId");
CREATE INDEX "SastScanFreshnessDecision_observationId_idx"
  ON "SastScanFreshnessDecision"("observationId");

CREATE UNIQUE INDEX "SastScanRetryDecision_requestedAttemptId_key"
  ON "SastScanRetryDecision"("requestedAttemptId");
CREATE UNIQUE INDEX "SastScanRetryDecision_requestedSandboxId_key"
  ON "SastScanRetryDecision"("requestedSandboxId");
CREATE UNIQUE INDEX "SastScanRetryDecision_requestedWorkloadIdentityRef_key"
  ON "SastScanRetryDecision"("requestedWorkloadIdentityRef");
CREATE UNIQUE INDEX "SastScanRetryDecision_decisionDigest_key"
  ON "SastScanRetryDecision"("decisionDigest");
CREATE UNIQUE INDEX "SastScanRetryDecision_attempt_number_key"
  ON "SastScanRetryDecision"("scanRequestId", "requestedAttemptNumber");
CREATE UNIQUE INDEX "SastScanRetryDecision_scope_key"
  ON "SastScanRetryDecision"("id", "tenantId", "repositoryBindingId", "scanRequestId");
CREATE INDEX "SastScanRetryDecision_outcome_idx"
  ON "SastScanRetryDecision"("tenantId", "retryAllowed", "decidedAt");
CREATE INDEX "SastScanRetryDecision_previousAttemptId_idx"
  ON "SastScanRetryDecision"("previousAttemptId");
CREATE INDEX "SastScanRetryDecision_previousFinalAuditEventId_idx"
  ON "SastScanRetryDecision"("previousFinalAuditEventId");

-- Unique indexes added to the populated coverage and attempt tables are built
-- concurrently by the mandatory prisma:online-schema deployment step.

ALTER TABLE "SastLatestTargetObservation"
  ADD CONSTRAINT "SastLatestTargetObservation_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastLatestTargetObservation"
  ADD CONSTRAINT "SastLatestTargetObservation_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastScanFreshnessDecision"
  ADD CONSTRAINT "SastScanFreshnessDecision_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanFreshnessDecision"
  ADD CONSTRAINT "SastScanFreshnessDecision_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanFreshnessDecision"
  ADD CONSTRAINT "SastScanFreshnessDecision_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanFreshnessDecision"
  ADD CONSTRAINT "SastScanFreshnessDecision_coverage_scope_fkey"
  FOREIGN KEY ("coverageDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  REFERENCES "SastScanCoverageDecision"("id", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanFreshnessDecision"
  ADD CONSTRAINT "SastScanFreshnessDecision_observation_scope_fkey"
  FOREIGN KEY ("observationId", "tenantId", "repositoryBindingId", "provider", "targetRef")
  REFERENCES "SastLatestTargetObservation"("id", "tenantId", "repositoryBindingId", "provider", "targetRef")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "SastScanRetryDecision"
  ADD CONSTRAINT "SastScanRetryDecision_tenantId_fkey"
  FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanRetryDecision"
  ADD CONSTRAINT "SastScanRetryDecision_repository_scope_fkey"
  FOREIGN KEY ("repositoryBindingId", "tenantId")
  REFERENCES "RepositoryBinding"("id", "tenantId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanRetryDecision"
  ADD CONSTRAINT "SastScanRetryDecision_scan_scope_fkey"
  FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
  REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastScanRetryDecision"
  ADD CONSTRAINT "SastScanRetryDecision_previous_attempt_fkey"
  FOREIGN KEY ("previousAttemptId", "tenantId", "repositoryBindingId", "scanRequestId")
  REFERENCES "SastScanAttempt"("id", "tenantId", "repositoryBindingId", "scanRequestId")
  ON DELETE RESTRICT ON UPDATE CASCADE;
-- The previous-coverage and final-audit scope FKs depend on concurrently
-- installed referenced indexes and are added and validated by the mandatory
-- prisma:online-schema deployment step.

ALTER TABLE "SastScanAttempt"
  ADD CONSTRAINT "SastScanAttempt_retryDecisionId_fkey"
  FOREIGN KEY ("retryDecisionId") REFERENCES "SastScanRetryDecision"("id")
  ON DELETE NO ACTION ON UPDATE NO ACTION NOT VALID;
