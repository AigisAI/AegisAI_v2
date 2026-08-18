-- T048 adds deterministic tenant-safe canary cohorts, an append-only
-- observation ledger, fail-closed step gates, and the exact CANARY -> ACTIVE
-- authority receipt. No source, finding, credential, or HMAC key material is
-- stored in this ledger.

-- Canonical scan-key v4 commits stable rollout and membership identity. The
-- evaluation-time assignment receipt remains in the immutable plan for queue
-- fencing, but is intentionally excluded from the canonical key. Immutable v3
-- plans are never rewritten, so every non-terminal v3 plan must be drained.
DO $t048_canonical_key_cutover$
BEGIN
  IF EXISTS (
    SELECT 1 FROM "ScanRequest"
    WHERE "status" IN ('QUEUED', 'PLANNING', 'RUNNING')
      AND "sastPlanning" IS NOT NULL
  ) OR EXISTS (
    SELECT 1 FROM "SastQueueReservation"
    WHERE "terminalStatus" IS NULL
  ) THEN
    RAISE EXCEPTION
      'T048 canonical scan-key v4 cutover requires all existing v3 SAST plans and reservations to be completed, failed, or canceled';
  END IF;
END;
$t048_canonical_key_cutover$;

CREATE FUNCTION "derive_sast_rule_bundle_canary_bucket"(digest TEXT)
RETURNS INTEGER
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE digest_bytes BYTEA; bucket INTEGER := 0; byte_index INTEGER;
BEGIN
  IF digest !~ '^sha256:[a-f0-9]{64}$' THEN RETURN NULL; END IF;
  digest_bytes := decode(substring(digest FROM 8 FOR 16), 'hex');
  FOR byte_index IN 0..7 LOOP
    bucket := mod(bucket * 256 + get_byte(digest_bytes, byte_index), 10000);
  END LOOP;
  RETURN bucket;
END;
$$;

CREATE TABLE "SastRuleBundleCanaryRollout" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "rolloutDigest" TEXT NOT NULL,
  "candidateManifestId" TEXT NOT NULL,
  "candidateManifestDigest" TEXT NOT NULL,
  "candidateBundleId" TEXT NOT NULL,
  "candidateBundleDigest" TEXT NOT NULL,
  "baselineManifestId" TEXT NOT NULL,
  "baselineManifestDigest" TEXT NOT NULL,
  "baselineBundleDigest" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "promotionEvidenceId" TEXT NOT NULL,
  "promotionEvidenceDigest" TEXT NOT NULL,
  "canaryTransitionId" TEXT NOT NULL,
  "canaryTransitionDigest" TEXT NOT NULL,
  "cohortKeyRef" TEXT NOT NULL,
  "cohortKeyVersion" TEXT NOT NULL,
  "eligibilityPolicyRef" TEXT NOT NULL,
  "eligibilityPolicyDigest" TEXT NOT NULL,
  "observationSourceRef" TEXT NOT NULL,
  "observationSourceDigest" TEXT NOT NULL,
  "progressionCount" INTEGER NOT NULL DEFAULT 6,
  "immutable" BOOLEAN NOT NULL DEFAULT true,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT false,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT false,
  "findingContentStored" BOOLEAN NOT NULL DEFAULT false,
  "secretKeyMaterialStored" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleCanaryRollout_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleCanaryRollout_contract_check" CHECK (
    "id" ~ '^sast-rule-bundle-canary-rollout://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-bundle-canary-rollout-v1'
    AND "rolloutDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-canary-rollout://' || substring("rolloutDigest" FROM 8)
    AND "candidateManifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "baselineManifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "candidateManifestId" <> "baselineManifestId"
    AND "candidateManifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "baselineManifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "candidateManifestId" = 'sast-rule-bundle-manifest://' || substring("candidateManifestDigest" FROM 8)
    AND "baselineManifestId" = 'sast-rule-bundle-manifest://' || substring("baselineManifestDigest" FROM 8)
    AND "candidateManifestDigest" <> "baselineManifestDigest"
    AND "candidateBundleId" ~ '^sast-rule-bundle://(opengrep|trivy)/[a-z0-9][a-z0-9._-]{0,127}$'
    AND "candidateBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "baselineBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "candidateBundleDigest" <> "baselineBundleDigest"
    AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1')
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "promotionEvidenceId" = 'sast-rule-bundle-promotion-evidence://' || substring("promotionEvidenceDigest" FROM 8)
    AND "canaryTransitionId" = 'sast-rule-bundle-lifecycle-transition://' || substring("canaryTransitionDigest" FROM 8)
    AND "cohortKeyRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "cohortKeyRef" !~ '^https?://' AND octet_length("cohortKeyVersion") BETWEEN 1 AND 512
    AND "eligibilityPolicyDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND right("eligibilityPolicyRef", 71) = "eligibilityPolicyDigest"
    AND "eligibilityPolicyRef" !~ '^https?://'
    AND "observationSourceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND right("observationSourceRef", 71) = "observationSourceDigest"
    AND "observationSourceRef" !~ '^https?://'
    AND "progressionCount" = 6 AND "immutable" IS TRUE
    AND "customerInputAccepted" IS FALSE
    AND "repositoryContentStored" IS FALSE
    AND "findingContentStored" IS FALSE
    AND "secretKeyMaterialStored" IS FALSE
  )
);

CREATE TABLE "SastRuleBundleCanaryRolloutStep" (
  "rolloutId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "step" TEXT NOT NULL,
  CONSTRAINT "SastRuleBundleCanaryRolloutStep_pkey" PRIMARY KEY ("rolloutId", "position"),
  CONSTRAINT "SastRuleBundleCanaryRolloutStep_contract_check" CHECK (
    "position" BETWEEN 0 AND 5
    AND (("position" = 0 AND "step" = 'INTERNAL_CORPUS')
      OR ("position" = 1 AND "step" = 'INTERNAL_REPOSITORIES')
      OR ("position" = 2 AND "step" = 'PERCENT_1')
      OR ("position" = 3 AND "step" = 'PERCENT_5')
      OR ("position" = 4 AND "step" = 'PERCENT_25')
      OR ("position" = 5 AND "step" = 'PERCENT_100'))
  )
);

CREATE TABLE "SastRuleBundleCanaryEligibilityDecision" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "eligibilityDecisionDigest" TEXT NOT NULL,
  "rolloutId" TEXT NOT NULL,
  "rolloutDigest" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "eligibilityClass" TEXT NOT NULL,
  "excluded" BOOLEAN NOT NULL,
  "exclusionRef" TEXT,
  "eligibilityPolicyRef" TEXT NOT NULL,
  "eligibilityPolicyDigest" TEXT NOT NULL,
  "actorRef" TEXT NOT NULL,
  "auditRef" TEXT NOT NULL,
  "evaluatedAt" TIMESTAMP(3) NOT NULL,
  "platformManaged" BOOLEAN NOT NULL DEFAULT true,
  "customerOverrideAccepted" BOOLEAN NOT NULL DEFAULT false,
  "repositoryContentUsed" BOOLEAN NOT NULL DEFAULT false,
  "findingOrSeverityUsed" BOOLEAN NOT NULL DEFAULT false,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleCanaryEligibilityDecision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleCanaryEligibilityDecision_contract_check" CHECK (
    "id" = 'sast-rule-bundle-canary-eligibility://' || substring("eligibilityDecisionDigest" FROM 8)
    AND "eligibilityDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-bundle-canary-eligibility-v1'
    AND "rolloutId" = 'sast-rule-bundle-canary-rollout://' || substring("rolloutDigest" FROM 8)
    AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1')
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "eligibilityClass" IN ('INTERNAL_CORPUS','INTERNAL_REPOSITORY','ELIGIBLE_PRODUCTION')
    AND (("excluded" IS TRUE AND "exclusionRef" IS NOT NULL
          AND right("exclusionRef", 71) ~ '^sha256:[a-f0-9]{64}$')
      OR ("excluded" IS FALSE AND "exclusionRef" IS NULL))
    AND "eligibilityPolicyDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND right("eligibilityPolicyRef", 71) = "eligibilityPolicyDigest"
    AND "actorRef" ~ '^actor://[a-zA-Z0-9._~:/@+-]+$'
    AND right("auditRef", 71) ~ '^sha256:[a-f0-9]{64}$'
    AND "platformManaged" IS TRUE AND "customerOverrideAccepted" IS FALSE
    AND "repositoryContentUsed" IS FALSE AND "findingOrSeverityUsed" IS FALSE
  )
);

CREATE TABLE "SastRuleBundleCanaryMembership" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "membershipDigest" TEXT NOT NULL,
  "rolloutId" TEXT NOT NULL,
  "rolloutDigest" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "eligibilityDecisionId" TEXT NOT NULL,
  "eligibilityDecisionDigest" TEXT NOT NULL,
  "eligibilityClass" TEXT NOT NULL,
  "excluded" BOOLEAN NOT NULL,
  "exclusionRef" TEXT,
  "eligibilityPolicyRef" TEXT NOT NULL,
  "eligibilityPolicyDigest" TEXT NOT NULL,
  "cohortKeyRef" TEXT NOT NULL,
  "cohortKeyVersion" TEXT NOT NULL,
  "assignmentHmacDigest" TEXT NOT NULL,
  "bucketBasisPoints" INTEGER NOT NULL,
  "evaluatedAt" TIMESTAMP(3) NOT NULL,
  "immutableForRollout" BOOLEAN NOT NULL DEFAULT true,
  "repositoryContentUsed" BOOLEAN NOT NULL DEFAULT false,
  "findingOrSeverityUsed" BOOLEAN NOT NULL DEFAULT false,
  "customerAttributeUsed" BOOLEAN NOT NULL DEFAULT false,
  "secretKeyMaterialStored" BOOLEAN NOT NULL DEFAULT false,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleCanaryMembership_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleCanaryMembership_contract_check" CHECK (
    "id" = 'sast-rule-bundle-canary-membership://' || substring("membershipDigest" FROM 8)
    AND "membershipDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-bundle-canary-membership-v1'
    AND "rolloutId" = 'sast-rule-bundle-canary-rollout://' || substring("rolloutDigest" FROM 8)
    AND "eligibilityDecisionId" = 'sast-rule-bundle-canary-eligibility://' || substring("eligibilityDecisionDigest" FROM 8)
    AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1')
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "eligibilityClass" IN ('INTERNAL_CORPUS','INTERNAL_REPOSITORY','ELIGIBLE_PRODUCTION')
    AND (("excluded" IS TRUE AND "exclusionRef" IS NOT NULL)
      OR ("excluded" IS FALSE AND "exclusionRef" IS NULL))
    AND "eligibilityPolicyDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND right("eligibilityPolicyRef", 71) = "eligibilityPolicyDigest"
    AND "assignmentHmacDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "bucketBasisPoints" BETWEEN 0 AND 9999
    AND "bucketBasisPoints" = public."derive_sast_rule_bundle_canary_bucket"("assignmentHmacDigest")
    AND octet_length("cohortKeyVersion") BETWEEN 1 AND 512
    AND "immutableForRollout" IS TRUE
    AND "repositoryContentUsed" IS FALSE AND "findingOrSeverityUsed" IS FALSE
    AND "customerAttributeUsed" IS FALSE AND "secretKeyMaterialStored" IS FALSE
  )
);

CREATE TABLE "SastRuleBundleCanaryAssignmentReceipt" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "assignmentReceiptDigest" TEXT NOT NULL,
  "rolloutId" TEXT NOT NULL,
  "rolloutDigest" TEXT NOT NULL,
  "membershipId" TEXT NOT NULL,
  "membershipDigest" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "eligibilityClass" TEXT NOT NULL,
  "excluded" BOOLEAN NOT NULL,
  "bucketBasisPoints" INTEGER NOT NULL,
  "step" TEXT NOT NULL,
  "stepHeadDecisionId" TEXT,
  "stepHeadDecisionDigest" TEXT,
  "candidateManifestId" TEXT NOT NULL,
  "candidateManifestDigest" TEXT NOT NULL,
  "candidateBundleDigest" TEXT NOT NULL,
  "baselineManifestId" TEXT NOT NULL,
  "baselineManifestDigest" TEXT NOT NULL,
  "baselineBundleDigest" TEXT NOT NULL,
  "selection" TEXT NOT NULL,
  "selectedManifestId" TEXT,
  "selectedManifestDigest" TEXT,
  "selectedBundleDigest" TEXT,
  "evaluatedAt" TIMESTAMP(3) NOT NULL,
  "deterministic" BOOLEAN NOT NULL DEFAULT true,
  "immutable" BOOLEAN NOT NULL DEFAULT true,
  "customerOverrideAccepted" BOOLEAN NOT NULL DEFAULT false,
  "repositoryContentUsed" BOOLEAN NOT NULL DEFAULT false,
  "findingOrSeverityUsed" BOOLEAN NOT NULL DEFAULT false,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleCanaryAssignmentReceipt_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleCanaryAssignmentReceipt_contract_check" CHECK (
    "id" = 'sast-rule-bundle-canary-assignment://' || substring("assignmentReceiptDigest" FROM 8)
    AND "assignmentReceiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-bundle-canary-assignment-v1'
    AND "rolloutId" = 'sast-rule-bundle-canary-rollout://' || substring("rolloutDigest" FROM 8)
    AND "membershipId" = 'sast-rule-bundle-canary-membership://' || substring("membershipDigest" FROM 8)
    AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1')
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "eligibilityClass" IN ('INTERNAL_CORPUS','INTERNAL_REPOSITORY','ELIGIBLE_PRODUCTION')
    AND "excluded" IS FALSE AND "bucketBasisPoints" BETWEEN 0 AND 9999
    AND "step" IN ('INTERNAL_CORPUS','INTERNAL_REPOSITORIES','PERCENT_1','PERCENT_5','PERCENT_25','PERCENT_100')
    AND (("stepHeadDecisionId" IS NULL AND "stepHeadDecisionDigest" IS NULL)
      OR "stepHeadDecisionId" = 'sast-rule-bundle-canary-step-decision://' || substring("stepHeadDecisionDigest" FROM 8))
    AND "candidateManifestId" = 'sast-rule-bundle-manifest://' || substring("candidateManifestDigest" FROM 8)
    AND "baselineManifestId" = 'sast-rule-bundle-manifest://' || substring("baselineManifestDigest" FROM 8)
    AND "selection" = 'CANDIDATE'
    AND "selectedManifestId" = "candidateManifestId"
    AND "selectedManifestDigest" = "candidateManifestDigest"
    AND "selectedBundleDigest" = "candidateBundleDigest"
    AND (("eligibilityClass" = 'INTERNAL_CORPUS' AND "step" = 'INTERNAL_CORPUS')
      OR ("eligibilityClass" = 'INTERNAL_REPOSITORY' AND "step" <> 'INTERNAL_CORPUS')
      OR ("eligibilityClass" = 'ELIGIBLE_PRODUCTION'
          AND (("step" = 'PERCENT_1' AND "bucketBasisPoints" < 100)
            OR ("step" = 'PERCENT_5' AND "bucketBasisPoints" < 500)
            OR ("step" = 'PERCENT_25' AND "bucketBasisPoints" < 2500)
            OR ("step" = 'PERCENT_100' AND "bucketBasisPoints" < 10000))))
    AND "deterministic" IS TRUE AND "immutable" IS TRUE
    AND "customerOverrideAccepted" IS FALSE
    AND "repositoryContentUsed" IS FALSE AND "findingOrSeverityUsed" IS FALSE
  )
);

CREATE TABLE "SastRuleBundleCanaryScanObservation" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "observationDigest" TEXT NOT NULL,
  "rolloutId" TEXT NOT NULL,
  "rolloutDigest" TEXT NOT NULL,
  "step" TEXT NOT NULL,
  "cohortRole" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "attemptId" TEXT NOT NULL,
  "assignmentReceiptId" TEXT,
  "assignmentReceiptDigest" TEXT,
  "selectedManifestId" TEXT NOT NULL,
  "selectedManifestDigest" TEXT NOT NULL,
  "selectedBundleDigest" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "lane" "ScanLane" NOT NULL,
  "repositorySizeBucket" TEXT NOT NULL,
  "coverageDecisionId" TEXT NOT NULL,
  "coverageDecisionDigest" TEXT NOT NULL,
  "publicationDecisionId" TEXT NOT NULL,
  "publicationDecisionDigest" TEXT NOT NULL,
  "observationSourceRef" TEXT NOT NULL,
  "observationSourceDigest" TEXT NOT NULL,
  "telemetrySourceRef" TEXT NOT NULL,
  "telemetrySourceDigest" TEXT NOT NULL,
  "startedAt" TIMESTAMP(3) NOT NULL,
  "completedAt" TIMESTAMP(3) NOT NULL,
  "findingCount" INTEGER NOT NULL,
  "criticalHighFindingCount" INTEGER NOT NULL,
  "falsePositiveCount" INTEGER NOT NULL,
  "feedbackEligibleFindingCount" INTEGER NOT NULL,
  "waiverCount" INTEGER NOT NULL,
  "suppressionCount" INTEGER NOT NULL,
  "scannerFailureCount" INTEGER NOT NULL,
  "scannerTimeoutCount" INTEGER NOT NULL,
  "eligibleScannerAttemptCount" INTEGER NOT NULL,
  "artifactRejectionCount" INTEGER NOT NULL,
  "latencyMilliseconds" INTEGER NOT NULL,
  "cpuMilliseconds" BIGINT NOT NULL,
  "peakMemoryBytes" BIGINT NOT NULL,
  "diskBytes" BIGINT NOT NULL,
  "incompleteCoverageCount" INTEGER NOT NULL,
  "publicationDenialCount" INTEGER NOT NULL,
  "egressDenialCount" INTEGER NOT NULL,
  "cleanupLagMilliseconds" INTEGER NOT NULL,
  "quarantineCount" INTEGER NOT NULL,
  "killSwitchSignalCount" INTEGER NOT NULL,
  "crossTenantEvents" INTEGER NOT NULL,
  "secretLeakEvents" INTEGER NOT NULL,
  "sandboxEscapeEvents" INTEGER NOT NULL,
  "stalePublicationEvents" INTEGER NOT NULL,
  "unauthorizedEgressEvents" INTEGER NOT NULL,
  "missingDestructionEvidenceEvents" INTEGER NOT NULL,
  "evidencePolicyViolationEvents" INTEGER NOT NULL,
  "unsignedArtifactExecutionEvents" INTEGER NOT NULL,
  "terminalScanVerified" BOOLEAN NOT NULL DEFAULT true,
  "immutablePlanVerified" BOOLEAN NOT NULL DEFAULT true,
  "coverageComplete" BOOLEAN NOT NULL DEFAULT true,
  "telemetryComplete" BOOLEAN NOT NULL DEFAULT true,
  "sourceOrFindingContentStored" BOOLEAN NOT NULL DEFAULT false,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT false,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleCanaryScanObservation_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleCanaryScanObservation_contract_check" CHECK (
    "id" = 'sast-rule-bundle-canary-observation://' || substring("observationDigest" FROM 8)
    AND "contractVersion" = 'sast-rule-bundle-canary-scan-observation-v1'
    AND "observationDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "rolloutId" = 'sast-rule-bundle-canary-rollout://' || substring("rolloutDigest" FROM 8)
    AND "step" IN ('INTERNAL_CORPUS','INTERNAL_REPOSITORIES','PERCENT_1','PERCENT_5','PERCENT_25','PERCENT_100')
    AND "cohortRole" IN ('CANDIDATE','BASELINE')
    AND (("cohortRole" = 'CANDIDATE'
          AND "assignmentReceiptId" = 'sast-rule-bundle-canary-assignment://' || substring("assignmentReceiptDigest" FROM 8))
      OR ("cohortRole" = 'BASELINE' AND "assignmentReceiptId" IS NULL AND "assignmentReceiptDigest" IS NULL))
    AND "selectedManifestId" = 'sast-rule-bundle-manifest://' || substring("selectedManifestDigest" FROM 8)
    AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1')
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "repositorySizeBucket" IN ('SMALL','MEDIUM','LARGE')
    AND "coverageDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "publicationDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND right("observationSourceRef", 71) = "observationSourceDigest"
    AND "observationSourceRef" !~ '^https?://'
    AND right("telemetrySourceRef", 71) = "telemetrySourceDigest"
    AND "startedAt" <= "completedAt"
    AND "findingCount" BETWEEN 0 AND 1000000000
    AND "criticalHighFindingCount" BETWEEN 0 AND "findingCount"
    AND "falsePositiveCount" BETWEEN 0 AND "feedbackEligibleFindingCount"
    AND "feedbackEligibleFindingCount" BETWEEN 0 AND "findingCount"
    AND "waiverCount" BETWEEN 0 AND "findingCount"
    AND "suppressionCount" BETWEEN 0 AND "findingCount"
    AND "scannerFailureCount" BETWEEN 0 AND "eligibleScannerAttemptCount"
    AND "scannerTimeoutCount" BETWEEN 0 AND "scannerFailureCount"
    AND "eligibleScannerAttemptCount" BETWEEN 1 AND 1000000000
    AND "artifactRejectionCount" BETWEEN 0 AND 1000000000
    AND "latencyMilliseconds" BETWEEN 0 AND 2700000
    AND "cpuMilliseconds" BETWEEN 0 AND 9007199254740991
    AND "peakMemoryBytes" BETWEEN 0 AND 9007199254740991
    AND "diskBytes" BETWEEN 0 AND 9007199254740991
    AND "incompleteCoverageCount" BETWEEN 0 AND 1
    AND "publicationDenialCount" BETWEEN 0 AND 1
    AND "egressDenialCount" BETWEEN 0 AND 1000000000
    AND "cleanupLagMilliseconds" BETWEEN 0 AND 1000000000
    AND "quarantineCount" BETWEEN 0 AND 1000000000
    AND "killSwitchSignalCount" BETWEEN 0 AND 1000000000
    AND "crossTenantEvents" BETWEEN 0 AND 1000000000
    AND "secretLeakEvents" BETWEEN 0 AND 1000000000
    AND "sandboxEscapeEvents" BETWEEN 0 AND 1000000000
    AND "stalePublicationEvents" BETWEEN 0 AND 1000000000
    AND "unauthorizedEgressEvents" BETWEEN 0 AND 1000000000
    AND "missingDestructionEvidenceEvents" BETWEEN 0 AND 1000000000
    AND "evidencePolicyViolationEvents" BETWEEN 0 AND 1000000000
    AND "unsignedArtifactExecutionEvents" BETWEEN 0 AND 1000000000
    AND "terminalScanVerified" IS TRUE AND "immutablePlanVerified" IS TRUE
    AND "sourceOrFindingContentStored" IS FALSE AND "secretValueStored" IS FALSE
  )
);

CREATE TABLE "SastRuleBundleCanaryStepDecision" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "rolloutId" TEXT NOT NULL,
  "rolloutDigest" TEXT NOT NULL,
  "candidateManifestId" TEXT NOT NULL,
  "candidateManifestDigest" TEXT NOT NULL,
  "candidateBundleDigest" TEXT NOT NULL,
  "baselineManifestId" TEXT NOT NULL,
  "baselineManifestDigest" TEXT NOT NULL,
  "baselineBundleDigest" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "sequence" INTEGER NOT NULL,
  "step" TEXT NOT NULL,
  "previousDecisionId" TEXT,
  "previousDecisionDigest" TEXT,
  "windowStartedAt" TIMESTAMP(3) NOT NULL,
  "windowEndedAt" TIMESTAMP(3) NOT NULL,
  "observationSetDigest" TEXT NOT NULL,
  "observationCount" INTEGER NOT NULL,
  "reasonCodeCount" INTEGER NOT NULL,
  "candidateCompletedScans" INTEGER NOT NULL,
  "baselineCompletedScans" INTEGER NOT NULL,
  "candidateFindingCount" INTEGER NOT NULL,
  "baselineFindingCount" INTEGER NOT NULL,
  "candidateCriticalHighFindingCount" INTEGER NOT NULL,
  "baselineCriticalHighFindingCount" INTEGER NOT NULL,
  "candidateFalsePositiveCount" INTEGER NOT NULL,
  "candidateFeedbackEligibleFindingCount" INTEGER NOT NULL,
  "baselineFalsePositiveCount" INTEGER NOT NULL,
  "baselineFeedbackEligibleFindingCount" INTEGER NOT NULL,
  "candidateWaiverCount" INTEGER NOT NULL,
  "baselineWaiverCount" INTEGER NOT NULL,
  "candidateSuppressionCount" INTEGER NOT NULL,
  "baselineSuppressionCount" INTEGER NOT NULL,
  "candidateScannerFailureCount" INTEGER NOT NULL,
  "candidateEligibleScannerAttemptCount" INTEGER NOT NULL,
  "baselineScannerFailureCount" INTEGER NOT NULL,
  "baselineEligibleScannerAttemptCount" INTEGER NOT NULL,
  "candidateScannerTimeoutCount" INTEGER NOT NULL,
  "baselineScannerTimeoutCount" INTEGER NOT NULL,
  "candidateP50LatencyMilliseconds" INTEGER NOT NULL,
  "candidateP95LatencyMilliseconds" INTEGER NOT NULL,
  "baselineP50LatencyMilliseconds" INTEGER NOT NULL,
  "baselineP95LatencyMilliseconds" INTEGER NOT NULL,
  "candidateP95CpuMilliseconds" BIGINT NOT NULL,
  "baselineP95CpuMilliseconds" BIGINT NOT NULL,
  "candidateP95PeakMemoryBytes" BIGINT NOT NULL,
  "baselineP95PeakMemoryBytes" BIGINT NOT NULL,
  "candidateP95DiskBytes" BIGINT NOT NULL,
  "baselineP95DiskBytes" BIGINT NOT NULL,
  "candidateArtifactRejectionCount" INTEGER NOT NULL,
  "baselineArtifactRejectionCount" INTEGER NOT NULL,
  "candidateIncompleteCoverageCount" INTEGER NOT NULL,
  "baselineIncompleteCoverageCount" INTEGER NOT NULL,
  "candidatePublicationDenialCount" INTEGER NOT NULL,
  "baselinePublicationDenialCount" INTEGER NOT NULL,
  "candidateEgressDenialCount" INTEGER NOT NULL,
  "baselineEgressDenialCount" INTEGER NOT NULL,
  "candidateP95CleanupLagMilliseconds" INTEGER NOT NULL,
  "baselineP95CleanupLagMilliseconds" INTEGER NOT NULL,
  "candidateQuarantineCount" INTEGER NOT NULL,
  "baselineQuarantineCount" INTEGER NOT NULL,
  "candidateKillSwitchSignalCount" INTEGER NOT NULL,
  "baselineKillSwitchSignalCount" INTEGER NOT NULL,
  "crossTenantEvents" INTEGER NOT NULL,
  "secretLeakEvents" INTEGER NOT NULL,
  "sandboxEscapeEvents" INTEGER NOT NULL,
  "stalePublicationEvents" INTEGER NOT NULL,
  "unauthorizedEgressEvents" INTEGER NOT NULL,
  "missingDestructionEvidenceEvents" INTEGER NOT NULL,
  "evidencePolicyViolationEvents" INTEGER NOT NULL,
  "unsignedArtifactExecutionEvents" INTEGER NOT NULL,
  "telemetryComplete" BOOLEAN NOT NULL,
  "allProfileSizeBucketsCompared" BOOLEAN NOT NULL,
  "evaluatorRef" TEXT NOT NULL,
  "auditRef" TEXT NOT NULL,
  "evaluatedAt" TIMESTAMP(3) NOT NULL,
  "outcome" TEXT NOT NULL,
  "thresholdsWaived" BOOLEAN NOT NULL DEFAULT false,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT false,
  "immutable" BOOLEAN NOT NULL DEFAULT true,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleCanaryStepDecision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleCanaryStepDecision_contract_check" CHECK (
    "id" = 'sast-rule-bundle-canary-step-decision://' || substring("decisionDigest" FROM 8)
    AND "decisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-bundle-canary-step-decision-v1'
    AND "rolloutId" = 'sast-rule-bundle-canary-rollout://' || substring("rolloutDigest" FROM 8)
    AND "candidateManifestId" = 'sast-rule-bundle-manifest://' || substring("candidateManifestDigest" FROM 8)
    AND "baselineManifestId" = 'sast-rule-bundle-manifest://' || substring("baselineManifestDigest" FROM 8)
    AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1')
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "sequence" BETWEEN 1 AND 1000000
    AND "step" IN ('INTERNAL_CORPUS','INTERNAL_REPOSITORIES','PERCENT_1','PERCENT_5','PERCENT_25','PERCENT_100')
    AND (("sequence" = 1 AND "previousDecisionId" IS NULL AND "previousDecisionDigest" IS NULL)
      OR ("sequence" > 1 AND "previousDecisionId" = 'sast-rule-bundle-canary-step-decision://' || substring("previousDecisionDigest" FROM 8)))
    AND "windowStartedAt" <= "windowEndedAt"
    AND "windowEndedAt" = "evaluatedAt"
    AND "observationSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "observationCount" BETWEEN 1 AND 20000
    AND "reasonCodeCount" BETWEEN 0 AND 11
    AND "candidateCompletedScans" >= 0 AND "baselineCompletedScans" >= 0
    AND "candidateFindingCount" >= 0 AND "baselineFindingCount" >= 0
    AND "candidateCriticalHighFindingCount" BETWEEN 0 AND "candidateFindingCount"
    AND "baselineCriticalHighFindingCount" BETWEEN 0 AND "baselineFindingCount"
    AND "candidateFalsePositiveCount" BETWEEN 0 AND "candidateFeedbackEligibleFindingCount"
    AND "baselineFalsePositiveCount" BETWEEN 0 AND "baselineFeedbackEligibleFindingCount"
    AND "candidateWaiverCount" >= 0 AND "baselineWaiverCount" >= 0
    AND "candidateSuppressionCount" >= 0 AND "baselineSuppressionCount" >= 0
    AND "candidateScannerFailureCount" BETWEEN 0 AND "candidateEligibleScannerAttemptCount"
    AND "baselineScannerFailureCount" BETWEEN 0 AND "baselineEligibleScannerAttemptCount"
    AND "candidateScannerTimeoutCount" BETWEEN 0 AND "candidateScannerFailureCount"
    AND "baselineScannerTimeoutCount" BETWEEN 0 AND "baselineScannerFailureCount"
    AND "candidateP50LatencyMilliseconds" BETWEEN 0 AND "candidateP95LatencyMilliseconds"
    AND "baselineP50LatencyMilliseconds" BETWEEN 0 AND "baselineP95LatencyMilliseconds"
    AND "candidateP95CpuMilliseconds" BETWEEN 0 AND 9007199254740991
    AND "baselineP95CpuMilliseconds" BETWEEN 0 AND 9007199254740991
    AND "candidateP95PeakMemoryBytes" BETWEEN 0 AND 9007199254740991
    AND "baselineP95PeakMemoryBytes" BETWEEN 0 AND 9007199254740991
    AND "candidateP95DiskBytes" BETWEEN 0 AND 9007199254740991
    AND "baselineP95DiskBytes" BETWEEN 0 AND 9007199254740991
    AND "candidateArtifactRejectionCount" >= 0 AND "baselineArtifactRejectionCount" >= 0
    AND "candidateIncompleteCoverageCount" >= 0 AND "baselineIncompleteCoverageCount" >= 0
    AND "candidatePublicationDenialCount" >= 0 AND "baselinePublicationDenialCount" >= 0
    AND "candidateEgressDenialCount" >= 0 AND "baselineEgressDenialCount" >= 0
    AND "candidateP95CleanupLagMilliseconds" >= 0 AND "baselineP95CleanupLagMilliseconds" >= 0
    AND "candidateQuarantineCount" >= 0 AND "baselineQuarantineCount" >= 0
    AND "candidateKillSwitchSignalCount" >= 0 AND "baselineKillSwitchSignalCount" >= 0
    AND "crossTenantEvents" >= 0 AND "secretLeakEvents" >= 0
    AND "sandboxEscapeEvents" >= 0 AND "stalePublicationEvents" >= 0
    AND "unauthorizedEgressEvents" >= 0 AND "missingDestructionEvidenceEvents" >= 0
    AND "evidencePolicyViolationEvents" >= 0 AND "unsignedArtifactExecutionEvents" >= 0
    AND "outcome" IN ('PENDING','PASSED','PAUSED')
    AND "evaluatorRef" ~ '^actor://[a-zA-Z0-9._~:/@+-]+$'
    AND right("auditRef", 71) ~ '^sha256:[a-f0-9]{64}$'
    AND "thresholdsWaived" IS FALSE
    AND "customerInputAccepted" IS FALSE AND "immutable" IS TRUE
  )
);

CREATE TABLE "SastRuleBundleCanaryStepDecisionReason" (
  "decisionId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "reasonCode" TEXT NOT NULL,
  CONSTRAINT "SastRuleBundleCanaryStepDecisionReason_pkey" PRIMARY KEY ("decisionId", "position"),
  CONSTRAINT "SastRuleBundleCanaryStepDecisionReason_contract_check" CHECK (
    "position" BETWEEN 0 AND 10
    AND "reasonCode" IN (
      'OBSERVATION_WINDOW_INSUFFICIENT','CANDIDATE_SAMPLE_INSUFFICIENT',
      'BASELINE_SAMPLE_INSUFFICIENT','TELEMETRY_MISSING',
      'COVERAGE_INCOMPLETE','PROFILE_SIZE_COMPARISON_INCOMPLETE',
      'FALSE_POSITIVE_GATE_FAILED',
      'SCANNER_FAILURE_GATE_FAILED','LATENCY_GATE_FAILED',
      'CRITICAL_HIGH_VOLUME_GATE_FAILED','ZERO_TOLERANCE_EVENT_RECORDED'
    )
  )
);

CREATE TABLE "SastRuleBundleCanaryStepDecisionObservation" (
  "decisionId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "observationId" TEXT NOT NULL,
  "observationDigest" TEXT NOT NULL,
  CONSTRAINT "SastRuleBundleCanaryStepDecisionObservation_pkey" PRIMARY KEY ("decisionId", "position"),
  CONSTRAINT "SastRuleBundleCanaryStepDecisionObservation_contract_check" CHECK (
    "position" BETWEEN 0 AND 19999
    AND "observationId" = 'sast-rule-bundle-canary-observation://' || substring("observationDigest" FROM 8)
  )
);

CREATE TABLE "SastRuleBundleCanaryRolloutHead" (
  "rolloutId" TEXT NOT NULL,
  "rolloutDigest" TEXT NOT NULL,
  "currentStep" TEXT NOT NULL,
  "latestDecisionId" TEXT,
  "latestDecisionDigest" TEXT,
  "latestSequence" INTEGER NOT NULL DEFAULT 0,
  "latestOutcome" TEXT,
  "windowStartedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleCanaryRolloutHead_pkey" PRIMARY KEY ("rolloutId"),
  CONSTRAINT "SastRuleBundleCanaryRolloutHead_contract_check" CHECK (
    "rolloutId" = 'sast-rule-bundle-canary-rollout://' || substring("rolloutDigest" FROM 8)
    AND "currentStep" IN ('INTERNAL_CORPUS','INTERNAL_REPOSITORIES','PERCENT_1','PERCENT_5','PERCENT_25','PERCENT_100')
    AND (("latestSequence" = 0 AND "latestDecisionId" IS NULL
          AND "latestDecisionDigest" IS NULL AND "latestOutcome" IS NULL
          AND "currentStep" = 'INTERNAL_CORPUS')
      OR ("latestSequence" BETWEEN 1 AND 1000000
          AND "latestDecisionId" = 'sast-rule-bundle-canary-step-decision://' || substring("latestDecisionDigest" FROM 8)
          AND "latestOutcome" IN ('PENDING','PASSED','PAUSED')))
  )
);

CREATE TABLE "SastRuleBundleCanaryObservationReceipt" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "receiptDigest" TEXT NOT NULL,
  "rolloutId" TEXT NOT NULL,
  "rolloutDigest" TEXT NOT NULL,
  "candidateManifestId" TEXT NOT NULL,
  "candidateManifestDigest" TEXT NOT NULL,
  "candidateBundleId" TEXT NOT NULL,
  "candidateBundleDigest" TEXT NOT NULL,
  "baselineManifestId" TEXT NOT NULL,
  "baselineManifestDigest" TEXT NOT NULL,
  "baselineBundleDigest" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "promotionEvidenceId" TEXT NOT NULL,
  "promotionEvidenceDigest" TEXT NOT NULL,
  "passedStepCount" INTEGER NOT NULL DEFAULT 6,
  "observedFrom" TIMESTAMP(3) NOT NULL,
  "observedThrough" TIMESTAMP(3) NOT NULL,
  "issuedAt" TIMESTAMP(3) NOT NULL,
  "everyStepPassed" BOOLEAN NOT NULL DEFAULT true,
  "thresholdsWaived" BOOLEAN NOT NULL DEFAULT false,
  "immutable" BOOLEAN NOT NULL DEFAULT true,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT false,
  "findingContentStored" BOOLEAN NOT NULL DEFAULT false,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleCanaryObservationReceipt_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleCanaryObservationReceipt_contract_check" CHECK (
    "id" = 'sast-rule-bundle-canary-observation-receipt://' || substring("receiptDigest" FROM 8)
    AND "contractVersion" = 'sast-rule-bundle-canary-observation-receipt-v1'
    AND "receiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "rolloutId" = 'sast-rule-bundle-canary-rollout://' || substring("rolloutDigest" FROM 8)
    AND "candidateManifestId" = 'sast-rule-bundle-manifest://' || substring("candidateManifestDigest" FROM 8)
    AND "baselineManifestId" = 'sast-rule-bundle-manifest://' || substring("baselineManifestDigest" FROM 8)
    AND "promotionEvidenceId" = 'sast-rule-bundle-promotion-evidence://' || substring("promotionEvidenceDigest" FROM 8)
    AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1')
    AND "passedStepCount" = 6
    AND "observedFrom" <= "observedThrough" AND "observedThrough" <= "issuedAt"
    AND "everyStepPassed" IS TRUE AND "thresholdsWaived" IS FALSE
    AND "immutable" IS TRUE AND "repositoryContentStored" IS FALSE
    AND "findingContentStored" IS FALSE
  )
);

CREATE TABLE "SastRuleBundleCanaryReceiptPassedStep" (
  "receiptId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "step" TEXT NOT NULL,
  "decisionId" TEXT NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  CONSTRAINT "SastRuleBundleCanaryReceiptPassedStep_pkey" PRIMARY KEY ("receiptId", "position"),
  CONSTRAINT "SastRuleBundleCanaryReceiptPassedStep_contract_check" CHECK (
    "position" BETWEEN 0 AND 5
    AND (("position" = 0 AND "step" = 'INTERNAL_CORPUS')
      OR ("position" = 1 AND "step" = 'INTERNAL_REPOSITORIES')
      OR ("position" = 2 AND "step" = 'PERCENT_1')
      OR ("position" = 3 AND "step" = 'PERCENT_5')
      OR ("position" = 4 AND "step" = 'PERCENT_25')
      OR ("position" = 5 AND "step" = 'PERCENT_100'))
    AND "decisionId" = 'sast-rule-bundle-canary-step-decision://' || substring("decisionDigest" FROM 8)
  )
);

CREATE UNIQUE INDEX "SastRuleBundleCanaryRollout_rolloutDigest_key" ON "SastRuleBundleCanaryRollout"("rolloutDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryRollout_binding_key" ON "SastRuleBundleCanaryRollout"("id","rolloutDigest","profileId","profileDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryRollout_candidate_profile_key" ON "SastRuleBundleCanaryRollout"("candidateManifestId","profileId");
CREATE INDEX "SastRuleBundleCanaryRollout_candidate_profile_idx" ON "SastRuleBundleCanaryRollout"("candidateManifestId","profileId","createdAt" DESC);
CREATE INDEX "SastRuleBundleCanaryRollout_baseline_idx" ON "SastRuleBundleCanaryRollout"("baselineManifestId");
CREATE UNIQUE INDEX "SastRuleBundleCanaryRolloutStep_rollout_step_key" ON "SastRuleBundleCanaryRolloutStep"("rolloutId","step");

CREATE UNIQUE INDEX "SastRuleBundleCanaryEligibilityDecision_eligibilityDecisionDigest_key" ON "SastRuleBundleCanaryEligibilityDecision"("eligibilityDecisionDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryEligibilityDecision_scope_key" ON "SastRuleBundleCanaryEligibilityDecision"("rolloutId","tenantId","repositoryBindingId","profileId");
CREATE UNIQUE INDEX "SastRuleBundleCanaryEligibilityDecision_binding_key" ON "SastRuleBundleCanaryEligibilityDecision"("id","eligibilityDecisionDigest","rolloutId","rolloutDigest");
CREATE INDEX "SastRuleBundleCanaryEligibilityDecision_tenant_repo_idx" ON "SastRuleBundleCanaryEligibilityDecision"("tenantId","repositoryBindingId","evaluatedAt");

CREATE UNIQUE INDEX "SastRuleBundleCanaryMembership_membershipDigest_key" ON "SastRuleBundleCanaryMembership"("membershipDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryMembership_scope_key" ON "SastRuleBundleCanaryMembership"("rolloutId","tenantId","repositoryBindingId","profileId");
CREATE UNIQUE INDEX "SastRuleBundleCanaryMembership_binding_key" ON "SastRuleBundleCanaryMembership"("id","membershipDigest","rolloutId","rolloutDigest","tenantId","repositoryBindingId","profileId");
CREATE INDEX "SastRuleBundleCanaryMembership_bucket_idx" ON "SastRuleBundleCanaryMembership"("rolloutId","bucketBasisPoints");

CREATE UNIQUE INDEX "SastRuleBundleCanaryAssignmentReceipt_assignmentReceiptDigest_key" ON "SastRuleBundleCanaryAssignmentReceipt"("assignmentReceiptDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryAssignmentReceipt_binding_key" ON "SastRuleBundleCanaryAssignmentReceipt"("id","assignmentReceiptDigest","rolloutId","rolloutDigest","membershipId","membershipDigest");
CREATE INDEX "SastRuleBundleCanaryAssignmentReceipt_scope_time_idx" ON "SastRuleBundleCanaryAssignmentReceipt"("rolloutId","tenantId","repositoryBindingId","evaluatedAt");
CREATE INDEX "SastRuleBundleCanaryAssignmentReceipt_step_head_idx" ON "SastRuleBundleCanaryAssignmentReceipt"("stepHeadDecisionId");

CREATE UNIQUE INDEX "SastRuleBundleCanaryScanObservation_observationDigest_key" ON "SastRuleBundleCanaryScanObservation"("observationDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryScanObservation_scan_key" ON "SastRuleBundleCanaryScanObservation"("rolloutId","tenantId","scanRequestId","attemptId");
CREATE UNIQUE INDEX "SastRuleBundleCanaryScanObservation_identity_key" ON "SastRuleBundleCanaryScanObservation"("id","observationDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryScanObservation_binding_key" ON "SastRuleBundleCanaryScanObservation"("id","observationDigest","rolloutId","rolloutDigest","step");
CREATE INDEX "SastRuleBundleCanaryScanObservation_gate_idx" ON "SastRuleBundleCanaryScanObservation"("rolloutId","step","cohortRole","repositorySizeBucket","completedAt");
CREATE INDEX "SastRuleBundleCanaryScanObservation_assignment_idx" ON "SastRuleBundleCanaryScanObservation"("assignmentReceiptId");

CREATE UNIQUE INDEX "SastRuleBundleCanaryStepDecision_decisionDigest_key" ON "SastRuleBundleCanaryStepDecision"("decisionDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryStepDecision_rollout_sequence_key" ON "SastRuleBundleCanaryStepDecision"("rolloutId","sequence");
CREATE UNIQUE INDEX "SastRuleBundleCanaryStepDecision_identity_key" ON "SastRuleBundleCanaryStepDecision"("id","decisionDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryStepDecision_binding_key" ON "SastRuleBundleCanaryStepDecision"("id","decisionDigest","rolloutId","rolloutDigest","sequence","step","outcome");
CREATE INDEX "SastRuleBundleCanaryStepDecision_gate_idx" ON "SastRuleBundleCanaryStepDecision"("rolloutId","step","outcome","evaluatedAt");
CREATE UNIQUE INDEX "SastRuleBundleCanaryStepDecisionReason_code_key" ON "SastRuleBundleCanaryStepDecisionReason"("decisionId","reasonCode");
CREATE UNIQUE INDEX "SastRuleBundleCanaryStepDecisionObservation_id_key" ON "SastRuleBundleCanaryStepDecisionObservation"("decisionId","observationId");

CREATE UNIQUE INDEX "SastRuleBundleCanaryRolloutHead_rolloutDigest_key" ON "SastRuleBundleCanaryRolloutHead"("rolloutDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryRolloutHead_latestDecisionId_key" ON "SastRuleBundleCanaryRolloutHead"("latestDecisionId");
CREATE UNIQUE INDEX "SastRuleBundleCanaryRolloutHead_latestDecisionDigest_key" ON "SastRuleBundleCanaryRolloutHead"("latestDecisionDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryRolloutHead_binding_key" ON "SastRuleBundleCanaryRolloutHead"("rolloutId","rolloutDigest","currentStep","latestDecisionId","latestDecisionDigest","latestSequence");
CREATE INDEX "SastRuleBundleCanaryRolloutHead_state_idx" ON "SastRuleBundleCanaryRolloutHead"("currentStep","latestOutcome","updatedAt");

CREATE UNIQUE INDEX "SastRuleBundleCanaryObservationReceipt_receiptDigest_key" ON "SastRuleBundleCanaryObservationReceipt"("receiptDigest");
CREATE UNIQUE INDEX "SastRuleBundleCanaryObservationReceipt_rolloutId_key" ON "SastRuleBundleCanaryObservationReceipt"("rolloutId");
CREATE UNIQUE INDEX "SastRuleBundleCanaryObservationReceipt_binding_key" ON "SastRuleBundleCanaryObservationReceipt"("id","receiptDigest","rolloutId","rolloutDigest");
CREATE INDEX "SastRuleBundleCanaryObservationReceipt_authority_idx" ON "SastRuleBundleCanaryObservationReceipt"("candidateManifestId","profileId","issuedAt");
CREATE UNIQUE INDEX "SastRuleBundleCanaryReceiptPassedStep_step_key" ON "SastRuleBundleCanaryReceiptPassedStep"("receiptId","step");
CREATE UNIQUE INDEX "SastRuleBundleCanaryReceiptPassedStep_decision_key" ON "SastRuleBundleCanaryReceiptPassedStep"("receiptId","decisionId");

ALTER TABLE "SastRuleBundleCanaryRollout" ADD CONSTRAINT "SastRuleBundleCanaryRollout_candidate_manifest_fkey" FOREIGN KEY ("candidateManifestId") REFERENCES "SastRuleBundleManifest"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryRollout" ADD CONSTRAINT "SastRuleBundleCanaryRollout_baseline_manifest_fkey" FOREIGN KEY ("baselineManifestId") REFERENCES "SastRuleBundleManifest"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryRollout" ADD CONSTRAINT "SastRuleBundleCanaryRollout_evidence_fkey" FOREIGN KEY ("promotionEvidenceId") REFERENCES "SastRuleBundlePromotionEvidence"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryRollout" ADD CONSTRAINT "SastRuleBundleCanaryRollout_transition_fkey" FOREIGN KEY ("canaryTransitionId") REFERENCES "SastRuleBundleLifecycleTransition"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryRolloutStep" ADD CONSTRAINT "SastRuleBundleCanaryRolloutStep_rollout_fkey" FOREIGN KEY ("rolloutId") REFERENCES "SastRuleBundleCanaryRollout"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "SastRuleBundleCanaryEligibilityDecision" ADD CONSTRAINT "SastRuleBundleCanaryEligibilityDecision_rollout_fkey" FOREIGN KEY ("rolloutId") REFERENCES "SastRuleBundleCanaryRollout"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryEligibilityDecision" ADD CONSTRAINT "SastRuleBundleCanaryEligibilityDecision_tenant_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryEligibilityDecision" ADD CONSTRAINT "SastRuleBundleCanaryEligibilityDecision_repository_fkey" FOREIGN KEY ("repositoryBindingId","tenantId") REFERENCES "RepositoryBinding"("id","tenantId") ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "SastRuleBundleCanaryMembership" ADD CONSTRAINT "SastRuleBundleCanaryMembership_rollout_fkey" FOREIGN KEY ("rolloutId") REFERENCES "SastRuleBundleCanaryRollout"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryMembership" ADD CONSTRAINT "SastRuleBundleCanaryMembership_eligibility_fkey" FOREIGN KEY ("eligibilityDecisionId","eligibilityDecisionDigest","rolloutId","rolloutDigest") REFERENCES "SastRuleBundleCanaryEligibilityDecision"("id","eligibilityDecisionDigest","rolloutId","rolloutDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryMembership" ADD CONSTRAINT "SastRuleBundleCanaryMembership_repository_fkey" FOREIGN KEY ("repositoryBindingId","tenantId") REFERENCES "RepositoryBinding"("id","tenantId") ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "SastRuleBundleCanaryAssignmentReceipt" ADD CONSTRAINT "SastRuleBundleCanaryAssignmentReceipt_rollout_fkey" FOREIGN KEY ("rolloutId") REFERENCES "SastRuleBundleCanaryRollout"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryAssignmentReceipt" ADD CONSTRAINT "SastRuleBundleCanaryAssignmentReceipt_membership_fkey" FOREIGN KEY ("membershipId","membershipDigest","rolloutId","rolloutDigest","tenantId","repositoryBindingId","profileId") REFERENCES "SastRuleBundleCanaryMembership"("id","membershipDigest","rolloutId","rolloutDigest","tenantId","repositoryBindingId","profileId") ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "SastRuleBundleCanaryScanObservation" ADD CONSTRAINT "SastRuleBundleCanaryScanObservation_rollout_fkey" FOREIGN KEY ("rolloutId") REFERENCES "SastRuleBundleCanaryRollout"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryScanObservation" ADD CONSTRAINT "SastRuleBundleCanaryScanObservation_assignment_fkey" FOREIGN KEY ("assignmentReceiptId") REFERENCES "SastRuleBundleCanaryAssignmentReceipt"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryScanObservation" ADD CONSTRAINT "SastRuleBundleCanaryScanObservation_repository_fkey" FOREIGN KEY ("repositoryBindingId","tenantId") REFERENCES "RepositoryBinding"("id","tenantId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryScanObservation" ADD CONSTRAINT "SastRuleBundleCanaryScanObservation_scan_fkey" FOREIGN KEY ("scanRequestId","tenantId","repositoryBindingId") REFERENCES "ScanRequest"("id","tenantId","repositoryBindingId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryScanObservation" ADD CONSTRAINT "SastRuleBundleCanaryScanObservation_attempt_fkey" FOREIGN KEY ("attemptId","tenantId","repositoryBindingId","scanRequestId") REFERENCES "SastScanAttempt"("id","tenantId","repositoryBindingId","scanRequestId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryScanObservation" ADD CONSTRAINT "SastRuleBundleCanaryScanObservation_coverage_fkey" FOREIGN KEY ("coverageDecisionId","tenantId","repositoryBindingId","scanRequestId","attemptId") REFERENCES "SastScanCoverageDecision"("id","tenantId","repositoryBindingId","scanRequestId","attemptId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryScanObservation" ADD CONSTRAINT "SastRuleBundleCanaryScanObservation_publication_fkey" FOREIGN KEY ("publicationDecisionId") REFERENCES "SastExternalPublicationDecision"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "SastRuleBundleCanaryStepDecision" ADD CONSTRAINT "SastRuleBundleCanaryStepDecision_rollout_fkey" FOREIGN KEY ("rolloutId") REFERENCES "SastRuleBundleCanaryRollout"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryStepDecision" ADD CONSTRAINT "SastRuleBundleCanaryStepDecision_previous_fkey" FOREIGN KEY ("previousDecisionId","previousDecisionDigest") REFERENCES "SastRuleBundleCanaryStepDecision"("id","decisionDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryStepDecisionReason" ADD CONSTRAINT "SastRuleBundleCanaryStepDecisionReason_decision_fkey" FOREIGN KEY ("decisionId") REFERENCES "SastRuleBundleCanaryStepDecision"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryStepDecisionObservation" ADD CONSTRAINT "SastRuleBundleCanaryStepDecisionObservation_decision_fkey" FOREIGN KEY ("decisionId") REFERENCES "SastRuleBundleCanaryStepDecision"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryStepDecisionObservation" ADD CONSTRAINT "SastRuleBundleCanaryStepDecisionObservation_observation_fkey" FOREIGN KEY ("observationId","observationDigest") REFERENCES "SastRuleBundleCanaryScanObservation"("id","observationDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "SastRuleBundleCanaryRolloutHead" ADD CONSTRAINT "SastRuleBundleCanaryRolloutHead_rollout_fkey" FOREIGN KEY ("rolloutId") REFERENCES "SastRuleBundleCanaryRollout"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryRolloutHead" ADD CONSTRAINT "SastRuleBundleCanaryRolloutHead_decision_fkey" FOREIGN KEY ("latestDecisionId") REFERENCES "SastRuleBundleCanaryStepDecision"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "SastRuleBundleCanaryObservationReceipt" ADD CONSTRAINT "SastRuleBundleCanaryObservationReceipt_rollout_fkey" FOREIGN KEY ("rolloutId") REFERENCES "SastRuleBundleCanaryRollout"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryReceiptPassedStep" ADD CONSTRAINT "SastRuleBundleCanaryReceiptPassedStep_receipt_fkey" FOREIGN KEY ("receiptId") REFERENCES "SastRuleBundleCanaryObservationReceipt"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCanaryReceiptPassedStep" ADD CONSTRAINT "SastRuleBundleCanaryReceiptPassedStep_decision_fkey" FOREIGN KEY ("decisionId","decisionDigest") REFERENCES "SastRuleBundleCanaryStepDecision"("id","decisionDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;

CREATE FUNCTION "reject_sast_rule_bundle_canary_mutation"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'SAST rule-bundle canary ledgers are append-only';
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_canary_rollout_binding"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE candidate_record RECORD; baseline_record RECORD;
        evidence_record RECORD; transition_record RECORD;
        lifecycle_head RECORD; baseline_lifecycle_head RECORD;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW."candidateManifestId", 0));
  PERFORM 1
  FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" IN (NEW."candidateManifestId", NEW."baselineManifestId")
  ORDER BY "manifestId"
  FOR UPDATE;
  SELECT * INTO candidate_record FROM public."SastRuleBundleManifest"
    WHERE "id" = NEW."candidateManifestId" FOR UPDATE;
  SELECT * INTO baseline_record FROM public."SastRuleBundleManifest"
    WHERE "id" = NEW."baselineManifestId";
  SELECT * INTO evidence_record FROM public."SastRuleBundlePromotionEvidence"
    WHERE "id" = NEW."promotionEvidenceId";
  SELECT * INTO transition_record FROM public."SastRuleBundleLifecycleTransition"
    WHERE "id" = NEW."canaryTransitionId";
  SELECT * INTO lifecycle_head FROM public."SastRuleBundleLifecycleHead"
    WHERE "manifestId" = NEW."candidateManifestId";
  SELECT * INTO baseline_lifecycle_head FROM public."SastRuleBundleLifecycleHead"
    WHERE "manifestId" = NEW."baselineManifestId";
  IF candidate_record."manifestDigest" IS DISTINCT FROM NEW."candidateManifestDigest"
     OR candidate_record."bundleId" IS DISTINCT FROM NEW."candidateBundleId"
     OR candidate_record."bundleDigest" IS DISTINCT FROM NEW."candidateBundleDigest"
     OR baseline_record."manifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR baseline_record."bundleId" IS DISTINCT FROM NEW."candidateBundleId"
     OR baseline_record."bundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR evidence_record."evidenceDigest" IS DISTINCT FROM NEW."promotionEvidenceDigest"
     OR evidence_record."manifestId" IS DISTINCT FROM NEW."candidateManifestId"
     OR evidence_record."baselineManifestId" IS DISTINCT FROM NEW."baselineManifestId"
     OR evidence_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR transition_record."transitionDigest" IS DISTINCT FROM NEW."canaryTransitionDigest"
     OR transition_record."manifestId" IS DISTINCT FROM NEW."candidateManifestId"
     OR transition_record."promotionEvidenceId" IS DISTINCT FROM NEW."promotionEvidenceId"
     OR transition_record."toState" IS DISTINCT FROM 'CANARY'
     OR lifecycle_head."transitionId" IS DISTINCT FROM NEW."canaryTransitionId"
     OR lifecycle_head."transitionDigest" IS DISTINCT FROM NEW."canaryTransitionDigest"
     OR lifecycle_head."lifecycleState" IS DISTINCT FROM 'CANARY'
     OR baseline_lifecycle_head."manifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR baseline_lifecycle_head."bundleId" IS DISTINCT FROM NEW."candidateBundleId"
     OR baseline_lifecycle_head."bundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR baseline_lifecycle_head."lifecycleState" IS DISTINCT FROM 'ACTIVE'
     OR NEW."createdAt" < transition_record."transitionedAt"
     OR NEW."createdAt" < baseline_lifecycle_head."transitionedAt" THEN
    RAISE EXCEPTION 'SAST canary rollout references are stale or invalid';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "initialize_sast_rule_bundle_canary_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  INSERT INTO public."SastRuleBundleCanaryRolloutHead" (
    "rolloutId","rolloutDigest","currentStep","latestDecisionId",
    "latestDecisionDigest","latestSequence","latestOutcome","windowStartedAt"
  ) VALUES (
    NEW."id",NEW."rolloutDigest",'INTERNAL_CORPUS',NULL,NULL,0,NULL,NEW."createdAt"
  );
  RETURN NULL;
END;
$$;

CREATE FUNCTION "protect_sast_rule_bundle_canary_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF pg_trigger_depth() < 2 THEN
    RAISE EXCEPTION 'SAST canary rollout head is a trigger-maintained projection';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_canary_progression"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE actual_count INTEGER;
BEGIN
  SELECT count(*) INTO actual_count
  FROM public."SastRuleBundleCanaryRolloutStep"
  WHERE "rolloutId" = NEW."id";
  IF actual_count <> NEW."progressionCount" OR actual_count <> 6 THEN
    RAISE EXCEPTION 'SAST canary rollout progression is incomplete';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_canary_eligibility"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE rollout_record RECORD; head_record RECORD;
BEGIN
  SELECT * INTO head_record FROM public."SastRuleBundleCanaryRolloutHead"
    WHERE "rolloutId" = NEW."rolloutId" FOR UPDATE;
  SELECT * INTO rollout_record FROM public."SastRuleBundleCanaryRollout"
    WHERE "id" = NEW."rolloutId";
  IF head_record."rolloutId" IS NULL OR rollout_record."id" IS NULL
     OR head_record."latestOutcome" IS NOT DISTINCT FROM 'PAUSED'
     OR EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryObservationReceipt" WHERE "rolloutId" = NEW."rolloutId")
     OR rollout_record."rolloutDigest" IS DISTINCT FROM NEW."rolloutDigest"
     OR rollout_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR rollout_record."profileDigest" IS DISTINCT FROM NEW."profileDigest"
     OR rollout_record."eligibilityPolicyRef" IS DISTINCT FROM NEW."eligibilityPolicyRef"
     OR rollout_record."eligibilityPolicyDigest" IS DISTINCT FROM NEW."eligibilityPolicyDigest"
     OR NEW."evaluatedAt" < rollout_record."createdAt" THEN
    RAISE EXCEPTION 'SAST canary eligibility is stale or outside rollout policy';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_canary_membership"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE rollout_record RECORD; eligibility_record RECORD; head_record RECORD;
BEGIN
  SELECT * INTO head_record FROM public."SastRuleBundleCanaryRolloutHead"
    WHERE "rolloutId" = NEW."rolloutId" FOR UPDATE;
  SELECT * INTO rollout_record FROM public."SastRuleBundleCanaryRollout"
    WHERE "id" = NEW."rolloutId";
  SELECT * INTO eligibility_record FROM public."SastRuleBundleCanaryEligibilityDecision"
    WHERE "id" = NEW."eligibilityDecisionId";
  IF head_record."rolloutId" IS NULL
     OR head_record."latestOutcome" IS NOT DISTINCT FROM 'PAUSED'
     OR EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryObservationReceipt" WHERE "rolloutId" = NEW."rolloutId")
     OR rollout_record."id" IS NULL OR eligibility_record."id" IS NULL
     OR rollout_record."rolloutDigest" IS DISTINCT FROM NEW."rolloutDigest"
     OR rollout_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR rollout_record."profileDigest" IS DISTINCT FROM NEW."profileDigest"
     OR rollout_record."cohortKeyRef" IS DISTINCT FROM NEW."cohortKeyRef"
     OR rollout_record."cohortKeyVersion" IS DISTINCT FROM NEW."cohortKeyVersion"
     OR eligibility_record."eligibilityDecisionDigest" IS DISTINCT FROM NEW."eligibilityDecisionDigest"
     OR eligibility_record."rolloutId" IS DISTINCT FROM NEW."rolloutId"
     OR eligibility_record."tenantId" IS DISTINCT FROM NEW."tenantId"
     OR eligibility_record."repositoryBindingId" IS DISTINCT FROM NEW."repositoryBindingId"
     OR eligibility_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR eligibility_record."profileDigest" IS DISTINCT FROM NEW."profileDigest"
     OR eligibility_record."eligibilityClass" IS DISTINCT FROM NEW."eligibilityClass"
     OR eligibility_record."excluded" IS DISTINCT FROM NEW."excluded"
     OR eligibility_record."exclusionRef" IS DISTINCT FROM NEW."exclusionRef"
     OR eligibility_record."eligibilityPolicyRef" IS DISTINCT FROM NEW."eligibilityPolicyRef"
     OR eligibility_record."eligibilityPolicyDigest" IS DISTINCT FROM NEW."eligibilityPolicyDigest"
     OR eligibility_record."evaluatedAt" IS DISTINCT FROM NEW."evaluatedAt" THEN
    RAISE EXCEPTION 'SAST canary membership is not bound to exact eligibility';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_canary_assignment"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE head_record RECORD; membership_record RECORD; rollout_record RECORD;
BEGIN
  SELECT * INTO head_record FROM public."SastRuleBundleCanaryRolloutHead"
    WHERE "rolloutId" = NEW."rolloutId" FOR UPDATE;
  SELECT * INTO membership_record FROM public."SastRuleBundleCanaryMembership"
    WHERE "id" = NEW."membershipId";
  SELECT * INTO rollout_record FROM public."SastRuleBundleCanaryRollout"
    WHERE "id" = NEW."rolloutId";
  IF head_record."rolloutId" IS NULL OR membership_record."id" IS NULL
     OR rollout_record."id" IS NULL
     OR head_record."latestOutcome" IS NOT DISTINCT FROM 'PAUSED'
     OR EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryObservationReceipt" WHERE "rolloutId" = NEW."rolloutId")
     OR head_record."rolloutDigest" IS DISTINCT FROM NEW."rolloutDigest"
     OR head_record."currentStep" IS DISTINCT FROM NEW."step"
     OR head_record."latestDecisionId" IS DISTINCT FROM NEW."stepHeadDecisionId"
     OR head_record."latestDecisionDigest" IS DISTINCT FROM NEW."stepHeadDecisionDigest"
     OR membership_record."membershipDigest" IS DISTINCT FROM NEW."membershipDigest"
     OR membership_record."tenantId" IS DISTINCT FROM NEW."tenantId"
     OR membership_record."repositoryBindingId" IS DISTINCT FROM NEW."repositoryBindingId"
     OR membership_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR membership_record."profileDigest" IS DISTINCT FROM NEW."profileDigest"
     OR membership_record."eligibilityClass" IS DISTINCT FROM NEW."eligibilityClass"
     OR membership_record."excluded" IS DISTINCT FROM NEW."excluded"
     OR membership_record."bucketBasisPoints" IS DISTINCT FROM NEW."bucketBasisPoints"
     OR NEW."evaluatedAt" < membership_record."evaluatedAt"
     OR NEW."evaluatedAt" < head_record."windowStartedAt"
     OR rollout_record."candidateManifestId" IS DISTINCT FROM NEW."candidateManifestId"
     OR rollout_record."candidateManifestDigest" IS DISTINCT FROM NEW."candidateManifestDigest"
     OR rollout_record."candidateBundleDigest" IS DISTINCT FROM NEW."candidateBundleDigest"
     OR rollout_record."baselineManifestId" IS DISTINCT FROM NEW."baselineManifestId"
     OR rollout_record."baselineManifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR rollout_record."baselineBundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest" THEN
    RAISE EXCEPTION 'SAST canary assignment is stale or not deterministic';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_canary_observation"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE head_record RECORD; rollout_record RECORD; assignment_record RECORD;
        reservation_record RECORD; attempt_record RECORD;
        coverage_record RECORD; publication_record RECORD;
BEGIN
  SELECT * INTO head_record FROM public."SastRuleBundleCanaryRolloutHead"
    WHERE "rolloutId" = NEW."rolloutId" FOR UPDATE;
  SELECT * INTO rollout_record FROM public."SastRuleBundleCanaryRollout"
    WHERE "id" = NEW."rolloutId";
  SELECT * INTO reservation_record FROM public."SastQueueReservation"
    WHERE "scanRequestId" = NEW."scanRequestId";
  SELECT * INTO attempt_record FROM public."SastScanAttempt"
    WHERE "id" = NEW."attemptId";
  SELECT * INTO coverage_record FROM public."SastScanCoverageDecision"
    WHERE "id" = NEW."coverageDecisionId";
  SELECT * INTO publication_record FROM public."SastExternalPublicationDecision"
    WHERE "id" = NEW."publicationDecisionId";
  IF head_record."rolloutId" IS NULL
     OR head_record."latestOutcome" IS NOT DISTINCT FROM 'PAUSED'
     OR EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryObservationReceipt" WHERE "rolloutId" = NEW."rolloutId")
     OR head_record."currentStep" IS DISTINCT FROM NEW."step"
     OR rollout_record."rolloutDigest" IS DISTINCT FROM NEW."rolloutDigest"
     OR rollout_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR rollout_record."profileDigest" IS DISTINCT FROM NEW."profileDigest"
     OR rollout_record."observationSourceRef" IS DISTINCT FROM NEW."observationSourceRef"
     OR rollout_record."observationSourceDigest" IS DISTINCT FROM NEW."observationSourceDigest"
     OR reservation_record."tenantId" IS DISTINCT FROM NEW."tenantId"
     OR reservation_record."repositoryBindingId" IS DISTINCT FROM NEW."repositoryBindingId"
     OR reservation_record."lane" IS DISTINCT FROM NEW."lane"
     OR reservation_record."immutablePlan"->'profile'->>'id' IS DISTINCT FROM NEW."profileId"
     OR reservation_record."immutablePlan"->>'profileDigest' IS DISTINCT FROM NEW."profileDigest"
     OR attempt_record."tenantId" IS DISTINCT FROM NEW."tenantId"
     OR attempt_record."repositoryBindingId" IS DISTINCT FROM NEW."repositoryBindingId"
     OR attempt_record."scanRequestId" IS DISTINCT FROM NEW."scanRequestId"
     OR attempt_record."stage" IS DISTINCT FROM 'COMPLETED'
     OR attempt_record."completedAt" IS NULL
     OR attempt_record."startedAt" IS DISTINCT FROM NEW."startedAt"
     OR attempt_record."completedAt" IS DISTINCT FROM NEW."completedAt"
     OR coverage_record."tenantId" IS DISTINCT FROM NEW."tenantId"
     OR coverage_record."repositoryBindingId" IS DISTINCT FROM NEW."repositoryBindingId"
     OR coverage_record."scanRequestId" IS DISTINCT FROM NEW."scanRequestId"
     OR coverage_record."attemptId" IS DISTINCT FROM NEW."attemptId"
     OR coverage_record."state" IS NOT DISTINCT FROM 'PENDING'
     OR NEW."coverageComplete" IS DISTINCT FROM (coverage_record."state" = 'COMPLETE')
     OR NEW."incompleteCoverageCount" IS DISTINCT FROM
        CASE WHEN coverage_record."state" = 'COMPLETE' THEN 0 ELSE 1 END
     OR coverage_record."decisionDigest" IS DISTINCT FROM NEW."coverageDecisionDigest"
     OR publication_record."coverageDecisionId" IS DISTINCT FROM NEW."coverageDecisionId"
     OR publication_record."tenantId" IS DISTINCT FROM NEW."tenantId"
     OR publication_record."repositoryBindingId" IS DISTINCT FROM NEW."repositoryBindingId"
     OR publication_record."scanRequestId" IS DISTINCT FROM NEW."scanRequestId"
     OR publication_record."attemptId" IS DISTINCT FROM NEW."attemptId"
     OR publication_record."decisionDigest" IS DISTINCT FROM NEW."publicationDecisionDigest"
     OR NEW."publicationDenialCount" IS DISTINCT FROM
        CASE WHEN publication_record."externalCommentAllowed" THEN 0 ELSE 1 END THEN
    RAISE EXCEPTION 'SAST canary observation source is incomplete or stale';
  END IF;

  IF NEW."cohortRole" = 'CANDIDATE' THEN
    SELECT * INTO assignment_record
    FROM public."SastRuleBundleCanaryAssignmentReceipt"
    WHERE "id" = NEW."assignmentReceiptId";
    IF assignment_record."assignmentReceiptDigest" IS DISTINCT FROM NEW."assignmentReceiptDigest"
       OR assignment_record."rolloutId" IS DISTINCT FROM NEW."rolloutId"
       OR assignment_record."tenantId" IS DISTINCT FROM NEW."tenantId"
       OR assignment_record."repositoryBindingId" IS DISTINCT FROM NEW."repositoryBindingId"
       OR assignment_record."profileId" IS DISTINCT FROM NEW."profileId"
       OR assignment_record."profileDigest" IS DISTINCT FROM NEW."profileDigest"
       OR assignment_record."evaluatedAt" > NEW."startedAt"
       OR assignment_record."step" IS DISTINCT FROM head_record."currentStep"
       OR assignment_record."stepHeadDecisionId" IS DISTINCT FROM head_record."latestDecisionId"
       OR assignment_record."stepHeadDecisionDigest" IS DISTINCT FROM head_record."latestDecisionDigest"
       OR assignment_record."selection" IS DISTINCT FROM 'CANDIDATE'
       OR assignment_record."selectedManifestId" IS DISTINCT FROM NEW."selectedManifestId"
       OR assignment_record."selectedManifestDigest" IS DISTINCT FROM NEW."selectedManifestDigest"
       OR assignment_record."selectedBundleDigest" IS DISTINCT FROM NEW."selectedBundleDigest"
       OR NOT EXISTS (
         SELECT 1
         FROM jsonb_array_elements(
           reservation_record."immutablePlan"->'scannerSet'->'ruleBundles'
         ) plan_bundle
         WHERE plan_bundle->>'manifestId' = NEW."selectedManifestId"
           AND plan_bundle->>'manifestDigest' = NEW."selectedManifestDigest"
           AND plan_bundle->>'digest' = NEW."selectedBundleDigest"
           AND plan_bundle->'lifecycle'->>'lifecycleState' = 'CANARY'
           AND plan_bundle->'canaryAssignment'->>'rolloutId' = NEW."rolloutId"
           AND plan_bundle->'canaryAssignment'->>'rolloutDigest' = NEW."rolloutDigest"
           AND plan_bundle->'canaryAssignment'->>'step' = NEW."step"
           AND plan_bundle->'canaryAssignment'->>'assignmentReceiptId' = NEW."assignmentReceiptId"
           AND plan_bundle->'canaryAssignment'->>'assignmentReceiptDigest' = NEW."assignmentReceiptDigest"
       ) THEN
      RAISE EXCEPTION 'SAST candidate observation assignment is unavailable';
    END IF;
  ELSE
    IF rollout_record."baselineManifestId" IS DISTINCT FROM NEW."selectedManifestId"
       OR rollout_record."baselineManifestDigest" IS DISTINCT FROM NEW."selectedManifestDigest"
       OR rollout_record."baselineBundleDigest" IS DISTINCT FROM NEW."selectedBundleDigest"
       OR NOT EXISTS (
         SELECT 1
         FROM jsonb_array_elements(
           reservation_record."immutablePlan"->'scannerSet'->'ruleBundles'
         ) plan_bundle
         WHERE plan_bundle->>'manifestId' = NEW."selectedManifestId"
           AND plan_bundle->>'manifestDigest' = NEW."selectedManifestDigest"
           AND plan_bundle->>'digest' = NEW."selectedBundleDigest"
           AND plan_bundle->'lifecycle'->>'lifecycleState' = 'ACTIVE'
           AND jsonb_typeof(plan_bundle->'canaryAssignment') = 'null'
       ) THEN
      RAISE EXCEPTION 'SAST baseline observation is not last-known-good';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_canary_decision_append"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE head_record RECORD; rollout_record RECORD;
BEGIN
  SELECT * INTO head_record FROM public."SastRuleBundleCanaryRolloutHead"
    WHERE "rolloutId" = NEW."rolloutId" FOR UPDATE;
  SELECT * INTO rollout_record FROM public."SastRuleBundleCanaryRollout"
    WHERE "id" = NEW."rolloutId";
  PERFORM 1
  FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" IN (
    rollout_record."candidateManifestId",
    rollout_record."baselineManifestId"
  )
  ORDER BY "manifestId"
  FOR SHARE;
  IF head_record."rolloutId" IS NULL
     OR head_record."latestOutcome" IS NOT DISTINCT FROM 'PAUSED'
     OR head_record."rolloutDigest" IS DISTINCT FROM NEW."rolloutDigest"
     OR head_record."currentStep" IS DISTINCT FROM NEW."step"
     OR head_record."latestSequence" + 1 IS DISTINCT FROM NEW."sequence"
     OR head_record."latestDecisionId" IS DISTINCT FROM NEW."previousDecisionId"
     OR head_record."latestDecisionDigest" IS DISTINCT FROM NEW."previousDecisionDigest"
     OR head_record."windowStartedAt" IS DISTINCT FROM NEW."windowStartedAt"
     OR rollout_record."candidateManifestId" IS DISTINCT FROM NEW."candidateManifestId"
     OR rollout_record."candidateManifestDigest" IS DISTINCT FROM NEW."candidateManifestDigest"
     OR rollout_record."candidateBundleDigest" IS DISTINCT FROM NEW."candidateBundleDigest"
     OR rollout_record."baselineManifestId" IS DISTINCT FROM NEW."baselineManifestId"
     OR rollout_record."baselineManifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR rollout_record."baselineBundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR rollout_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR rollout_record."profileDigest" IS DISTINCT FROM NEW."profileDigest"
     OR NOT EXISTS (
       SELECT 1 FROM public."SastRuleBundleLifecycleHead" lifecycle
       WHERE lifecycle."manifestId" = rollout_record."candidateManifestId"
         AND lifecycle."manifestDigest" = rollout_record."candidateManifestDigest"
         AND lifecycle."bundleId" = rollout_record."candidateBundleId"
         AND lifecycle."bundleDigest" = rollout_record."candidateBundleDigest"
         AND lifecycle."transitionId" = rollout_record."canaryTransitionId"
         AND lifecycle."transitionDigest" = rollout_record."canaryTransitionDigest"
         AND lifecycle."lifecycleState" = 'CANARY'
     )
     OR NOT EXISTS (
       SELECT 1 FROM public."SastRuleBundleLifecycleHead" lifecycle
       WHERE lifecycle."manifestId" = rollout_record."baselineManifestId"
         AND lifecycle."manifestDigest" = rollout_record."baselineManifestDigest"
         AND lifecycle."bundleId" = rollout_record."candidateBundleId"
         AND lifecycle."bundleDigest" = rollout_record."baselineBundleDigest"
         AND lifecycle."lifecycleState" = 'ACTIVE'
     )
     OR EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryObservationReceipt"
               WHERE "rolloutId" = NEW."rolloutId") THEN
    RAISE EXCEPTION 'SAST canary step decision does not extend the current head';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "refresh_sast_rule_bundle_canary_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE next_step TEXT; next_window TIMESTAMP(3);
BEGIN
  next_step := NEW."step";
  next_window := NEW."windowStartedAt";
  IF NEW."outcome" = 'PASSED' THEN
    next_step := CASE NEW."step"
      WHEN 'INTERNAL_CORPUS' THEN 'INTERNAL_REPOSITORIES'
      WHEN 'INTERNAL_REPOSITORIES' THEN 'PERCENT_1'
      WHEN 'PERCENT_1' THEN 'PERCENT_5'
      WHEN 'PERCENT_5' THEN 'PERCENT_25'
      WHEN 'PERCENT_25' THEN 'PERCENT_100'
      ELSE 'PERCENT_100'
    END;
    IF NEW."step" <> 'PERCENT_100' THEN next_window := NEW."evaluatedAt"; END IF;
  END IF;
  UPDATE public."SastRuleBundleCanaryRolloutHead"
  SET "currentStep" = next_step,
      "latestDecisionId" = NEW."id",
      "latestDecisionDigest" = NEW."decisionDigest",
      "latestSequence" = NEW."sequence",
      "latestOutcome" = NEW."outcome",
      "windowStartedAt" = next_window,
      "updatedAt" = CURRENT_TIMESTAMP
  WHERE "rolloutId" = NEW."rolloutId"
    AND "latestSequence" = NEW."sequence" - 1;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST canary head rejected a stale decision';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_canary_decision_evidence"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE agg RECORD; reason_count INTEGER; bucket_count INTEGER;
        actual_reasons TEXT[]; expected_reasons TEXT[];
        window_failed BOOLEAN; candidate_sample_failed BOOLEAN;
        baseline_sample_failed BOOLEAN; telemetry_failed BOOLEAN;
        coverage_failed BOOLEAN;
        bucket_failed BOOLEAN; false_positive_failed BOOLEAN;
        scanner_failure_failed BOOLEAN; latency_failed BOOLEAN;
        critical_high_failed BOOLEAN; zero_event_failed BOOLEAN;
        hard_failed BOOLEAN; insufficient BOOLEAN; expected_reason_count INTEGER;
        minimum_scans INTEGER; minimum_interval INTERVAL;
BEGIN
  SELECT
    count(*) FILTER (WHERE o."cohortRole" = 'CANDIDATE')::INTEGER AS candidate_scans,
    count(*) FILTER (WHERE o."cohortRole" = 'BASELINE')::INTEGER AS baseline_scans,
    coalesce(sum(o."findingCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_findings,
    coalesce(sum(o."findingCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_findings,
    coalesce(sum(o."criticalHighFindingCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_critical_high,
    coalesce(sum(o."criticalHighFindingCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_critical_high,
    coalesce(sum(o."falsePositiveCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_false_positive,
    coalesce(sum(o."feedbackEligibleFindingCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_feedback,
    coalesce(sum(o."falsePositiveCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_false_positive,
    coalesce(sum(o."feedbackEligibleFindingCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_feedback,
    coalesce(sum(o."waiverCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_waivers,
    coalesce(sum(o."waiverCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_waivers,
    coalesce(sum(o."suppressionCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_suppressions,
    coalesce(sum(o."suppressionCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_suppressions,
    coalesce(sum(o."scannerFailureCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_failures,
    coalesce(sum(o."eligibleScannerAttemptCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_attempts,
    coalesce(sum(o."scannerFailureCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_failures,
    coalesce(sum(o."eligibleScannerAttemptCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_attempts,
    coalesce(sum(o."scannerTimeoutCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_timeouts,
    coalesce(sum(o."scannerTimeoutCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_timeouts,
    coalesce(percentile_disc(0.50) WITHIN GROUP (ORDER BY o."latencyMilliseconds") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_p50_latency,
    coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY o."latencyMilliseconds") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_p95_latency,
    coalesce(percentile_disc(0.50) WITHIN GROUP (ORDER BY o."latencyMilliseconds") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_p50_latency,
    coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY o."latencyMilliseconds") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_p95_latency,
    coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY o."cpuMilliseconds") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::BIGINT AS candidate_p95_cpu,
    coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY o."cpuMilliseconds") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::BIGINT AS baseline_p95_cpu,
    coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY o."peakMemoryBytes") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::BIGINT AS candidate_p95_memory,
    coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY o."peakMemoryBytes") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::BIGINT AS baseline_p95_memory,
    coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY o."diskBytes") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::BIGINT AS candidate_p95_disk,
    coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY o."diskBytes") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::BIGINT AS baseline_p95_disk,
    coalesce(sum(o."artifactRejectionCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_rejections,
    coalesce(sum(o."artifactRejectionCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_rejections,
    coalesce(sum(o."incompleteCoverageCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_incomplete,
    coalesce(sum(o."incompleteCoverageCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_incomplete,
    coalesce(sum(o."publicationDenialCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_denials,
    coalesce(sum(o."publicationDenialCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_denials,
    coalesce(sum(o."egressDenialCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_egress_denials,
    coalesce(sum(o."egressDenialCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_egress_denials,
    coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY o."cleanupLagMilliseconds") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_cleanup,
    coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY o."cleanupLagMilliseconds") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_cleanup,
    coalesce(sum(o."quarantineCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_quarantine,
    coalesce(sum(o."quarantineCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_quarantine,
    coalesce(sum(o."killSwitchSignalCount") FILTER (WHERE o."cohortRole" = 'CANDIDATE'),0)::INTEGER AS candidate_kill,
    coalesce(sum(o."killSwitchSignalCount") FILTER (WHERE o."cohortRole" = 'BASELINE'),0)::INTEGER AS baseline_kill,
    coalesce(sum(o."crossTenantEvents"),0)::INTEGER AS cross_tenant,
    coalesce(sum(o."secretLeakEvents"),0)::INTEGER AS secret_leak,
    coalesce(sum(o."sandboxEscapeEvents"),0)::INTEGER AS sandbox_escape,
    coalesce(sum(o."stalePublicationEvents"),0)::INTEGER AS stale_publication,
    coalesce(sum(o."unauthorizedEgressEvents"),0)::INTEGER AS unauthorized_egress,
    coalesce(sum(o."missingDestructionEvidenceEvents"),0)::INTEGER AS missing_destruction,
    coalesce(sum(o."evidencePolicyViolationEvents"),0)::INTEGER AS evidence_violation,
    coalesce(sum(o."unsignedArtifactExecutionEvents"),0)::INTEGER AS unsigned_execution,
    bool_and(o."telemetryComplete") AS telemetry_complete
  INTO agg
  FROM public."SastRuleBundleCanaryStepDecisionObservation" b
  JOIN public."SastRuleBundleCanaryScanObservation" o
    ON o."id" = b."observationId" AND o."observationDigest" = b."observationDigest"
  WHERE b."decisionId" = NEW."id";

  SELECT count(*) INTO reason_count
  FROM public."SastRuleBundleCanaryStepDecisionReason"
  WHERE "decisionId" = NEW."id";
  SELECT coalesce(array_agg("reasonCode" ORDER BY "position"), ARRAY[]::TEXT[])
    INTO actual_reasons
  FROM public."SastRuleBundleCanaryStepDecisionReason"
  WHERE "decisionId" = NEW."id";
  SELECT count(DISTINCT o."cohortRole" || ':' || o."repositorySizeBucket")
    INTO bucket_count
  FROM public."SastRuleBundleCanaryStepDecisionObservation" b
  JOIN public."SastRuleBundleCanaryScanObservation" o ON o."id" = b."observationId"
  WHERE b."decisionId" = NEW."id";

  IF NEW."observationCount" IS DISTINCT FROM agg.candidate_scans + agg.baseline_scans
     OR NEW."reasonCodeCount" IS DISTINCT FROM reason_count
     OR EXISTS (
       SELECT 1
       FROM (
         SELECT b."position", b."observationId",
                row_number() OVER (ORDER BY b."position") - 1 AS expected_position,
                lag(b."observationId") OVER (ORDER BY b."position") AS previous_id
         FROM public."SastRuleBundleCanaryStepDecisionObservation" b
         WHERE b."decisionId" = NEW."id"
       ) ordered_observations
       WHERE ordered_observations."position" <> ordered_observations.expected_position
          OR ordered_observations.previous_id >= ordered_observations."observationId"
     )
     OR EXISTS (
       SELECT 1
       FROM public."SastRuleBundleCanaryStepDecisionObservation" b
       JOIN public."SastRuleBundleCanaryScanObservation" o ON o."id" = b."observationId"
       WHERE b."decisionId" = NEW."id"
         AND (o."rolloutId" <> NEW."rolloutId" OR o."rolloutDigest" <> NEW."rolloutDigest"
           OR o."step" <> NEW."step" OR o."profileId" <> NEW."profileId"
           OR o."profileDigest" <> NEW."profileDigest"
           OR o."completedAt" < NEW."windowStartedAt" OR o."completedAt" > NEW."windowEndedAt")
     )
     OR EXISTS (
       SELECT 1
       FROM public."SastRuleBundleCanaryScanObservation" o
       WHERE o."rolloutId" = NEW."rolloutId"
         AND o."step" = NEW."step"
         AND o."completedAt" >= NEW."windowStartedAt"
         AND o."completedAt" <= NEW."windowEndedAt"
         AND NOT EXISTS (
           SELECT 1
           FROM public."SastRuleBundleCanaryStepDecisionObservation" b
           WHERE b."decisionId" = NEW."id"
             AND b."observationId" = o."id"
             AND b."observationDigest" = o."observationDigest"
         )
     )
     OR NEW."candidateCompletedScans" IS DISTINCT FROM agg.candidate_scans
     OR NEW."baselineCompletedScans" IS DISTINCT FROM agg.baseline_scans
     OR NEW."candidateFindingCount" IS DISTINCT FROM agg.candidate_findings
     OR NEW."baselineFindingCount" IS DISTINCT FROM agg.baseline_findings
     OR NEW."candidateCriticalHighFindingCount" IS DISTINCT FROM agg.candidate_critical_high
     OR NEW."baselineCriticalHighFindingCount" IS DISTINCT FROM agg.baseline_critical_high
     OR NEW."candidateFalsePositiveCount" IS DISTINCT FROM agg.candidate_false_positive
     OR NEW."candidateFeedbackEligibleFindingCount" IS DISTINCT FROM agg.candidate_feedback
     OR NEW."baselineFalsePositiveCount" IS DISTINCT FROM agg.baseline_false_positive
     OR NEW."baselineFeedbackEligibleFindingCount" IS DISTINCT FROM agg.baseline_feedback
     OR NEW."candidateWaiverCount" IS DISTINCT FROM agg.candidate_waivers
     OR NEW."baselineWaiverCount" IS DISTINCT FROM agg.baseline_waivers
     OR NEW."candidateSuppressionCount" IS DISTINCT FROM agg.candidate_suppressions
     OR NEW."baselineSuppressionCount" IS DISTINCT FROM agg.baseline_suppressions
     OR NEW."candidateScannerFailureCount" IS DISTINCT FROM agg.candidate_failures
     OR NEW."candidateEligibleScannerAttemptCount" IS DISTINCT FROM agg.candidate_attempts
     OR NEW."baselineScannerFailureCount" IS DISTINCT FROM agg.baseline_failures
     OR NEW."baselineEligibleScannerAttemptCount" IS DISTINCT FROM agg.baseline_attempts
     OR NEW."candidateScannerTimeoutCount" IS DISTINCT FROM agg.candidate_timeouts
     OR NEW."baselineScannerTimeoutCount" IS DISTINCT FROM agg.baseline_timeouts
     OR NEW."candidateP50LatencyMilliseconds" IS DISTINCT FROM agg.candidate_p50_latency
     OR NEW."candidateP95LatencyMilliseconds" IS DISTINCT FROM agg.candidate_p95_latency
     OR NEW."baselineP50LatencyMilliseconds" IS DISTINCT FROM agg.baseline_p50_latency
     OR NEW."baselineP95LatencyMilliseconds" IS DISTINCT FROM agg.baseline_p95_latency
     OR NEW."candidateP95CpuMilliseconds" IS DISTINCT FROM agg.candidate_p95_cpu
     OR NEW."baselineP95CpuMilliseconds" IS DISTINCT FROM agg.baseline_p95_cpu
     OR NEW."candidateP95PeakMemoryBytes" IS DISTINCT FROM agg.candidate_p95_memory
     OR NEW."baselineP95PeakMemoryBytes" IS DISTINCT FROM agg.baseline_p95_memory
     OR NEW."candidateP95DiskBytes" IS DISTINCT FROM agg.candidate_p95_disk
     OR NEW."baselineP95DiskBytes" IS DISTINCT FROM agg.baseline_p95_disk
     OR NEW."candidateArtifactRejectionCount" IS DISTINCT FROM agg.candidate_rejections
     OR NEW."baselineArtifactRejectionCount" IS DISTINCT FROM agg.baseline_rejections
     OR NEW."candidateIncompleteCoverageCount" IS DISTINCT FROM agg.candidate_incomplete
     OR NEW."baselineIncompleteCoverageCount" IS DISTINCT FROM agg.baseline_incomplete
     OR NEW."candidatePublicationDenialCount" IS DISTINCT FROM agg.candidate_denials
     OR NEW."baselinePublicationDenialCount" IS DISTINCT FROM agg.baseline_denials
     OR NEW."candidateEgressDenialCount" IS DISTINCT FROM agg.candidate_egress_denials
     OR NEW."baselineEgressDenialCount" IS DISTINCT FROM agg.baseline_egress_denials
     OR NEW."candidateP95CleanupLagMilliseconds" IS DISTINCT FROM agg.candidate_cleanup
     OR NEW."baselineP95CleanupLagMilliseconds" IS DISTINCT FROM agg.baseline_cleanup
     OR NEW."candidateQuarantineCount" IS DISTINCT FROM agg.candidate_quarantine
     OR NEW."baselineQuarantineCount" IS DISTINCT FROM agg.baseline_quarantine
     OR NEW."candidateKillSwitchSignalCount" IS DISTINCT FROM agg.candidate_kill
     OR NEW."baselineKillSwitchSignalCount" IS DISTINCT FROM agg.baseline_kill
     OR NEW."crossTenantEvents" IS DISTINCT FROM agg.cross_tenant
     OR NEW."secretLeakEvents" IS DISTINCT FROM agg.secret_leak
     OR NEW."sandboxEscapeEvents" IS DISTINCT FROM agg.sandbox_escape
     OR NEW."stalePublicationEvents" IS DISTINCT FROM agg.stale_publication
     OR NEW."unauthorizedEgressEvents" IS DISTINCT FROM agg.unauthorized_egress
     OR NEW."missingDestructionEvidenceEvents" IS DISTINCT FROM agg.missing_destruction
     OR NEW."evidencePolicyViolationEvents" IS DISTINCT FROM agg.evidence_violation
     OR NEW."unsignedArtifactExecutionEvents" IS DISTINCT FROM agg.unsigned_execution
     OR NEW."telemetryComplete" IS DISTINCT FROM coalesce(agg.telemetry_complete, false)
     OR NEW."allProfileSizeBucketsCompared" IS DISTINCT FROM (bucket_count = 6) THEN
    RAISE EXCEPTION 'SAST canary decision aggregate does not match immutable observations';
  END IF;

  IF NEW."step" IN ('PERCENT_25','PERCENT_100') THEN
    minimum_scans := 1000; minimum_interval := INTERVAL '48 hours';
  ELSE
    minimum_scans := 200; minimum_interval := INTERVAL '24 hours';
  END IF;
  window_failed := NEW."windowEndedAt" - NEW."windowStartedAt" < minimum_interval;
  candidate_sample_failed := NEW."candidateCompletedScans" < minimum_scans;
  baseline_sample_failed := NEW."baselineCompletedScans" < minimum_scans;
  telemetry_failed := NOT NEW."telemetryComplete";
  coverage_failed := NEW."candidateIncompleteCoverageCount" <> 0
    OR NEW."baselineIncompleteCoverageCount" <> 0;
  bucket_failed := NOT NEW."allProfileSizeBucketsCompared";
  false_positive_failed := NEW."candidateFeedbackEligibleFindingCount" <= 0
    OR NEW."baselineFeedbackEligibleFindingCount" <= 0
    OR (NEW."candidateFalsePositiveCount"::NUMERIC * NEW."baselineFeedbackEligibleFindingCount"::NUMERIC
      - NEW."baselineFalsePositiveCount"::NUMERIC * NEW."candidateFeedbackEligibleFindingCount"::NUMERIC) * 10000
       > 200::NUMERIC * NEW."candidateFeedbackEligibleFindingCount"::NUMERIC
         * NEW."baselineFeedbackEligibleFindingCount"::NUMERIC;
  scanner_failure_failed := NEW."candidateEligibleScannerAttemptCount" <= 0
    OR NEW."candidateScannerFailureCount"::NUMERIC * 10000
       > 200::NUMERIC * NEW."candidateEligibleScannerAttemptCount"::NUMERIC;
  latency_failed := NEW."candidateP95LatencyMilliseconds" >
      CASE WHEN NEW."profileId" = 'JAVA_FAST_V1' THEN 600000 ELSE 2700000 END
    OR (CASE WHEN NEW."baselineP95LatencyMilliseconds" = 0
         THEN NEW."candidateP95LatencyMilliseconds" <> 0
         ELSE NEW."candidateP95LatencyMilliseconds"::NUMERIC * 10000
              > NEW."baselineP95LatencyMilliseconds"::NUMERIC * 12000 END);
  critical_high_failed := NEW."candidateCompletedScans" <= 0
    OR NEW."baselineCompletedScans" <= 0
    OR NEW."candidateCriticalHighFindingCount"::NUMERIC
         * NEW."baselineCompletedScans"::NUMERIC * 10000
       > NEW."baselineCriticalHighFindingCount"::NUMERIC
         * NEW."candidateCompletedScans"::NUMERIC * 12000;
  zero_event_failed := NEW."crossTenantEvents" + NEW."secretLeakEvents"
    + NEW."sandboxEscapeEvents" + NEW."stalePublicationEvents"
    + NEW."unauthorizedEgressEvents" + NEW."missingDestructionEvidenceEvents"
    + NEW."evidencePolicyViolationEvents" + NEW."unsignedArtifactExecutionEvents" <> 0;
  hard_failed := telemetry_failed OR coverage_failed OR bucket_failed OR false_positive_failed
    OR scanner_failure_failed OR latency_failed OR critical_high_failed OR zero_event_failed;
  insufficient := window_failed OR candidate_sample_failed OR baseline_sample_failed;
  expected_reasons := ARRAY[]::TEXT[];
  IF window_failed THEN expected_reasons := array_append(expected_reasons, 'OBSERVATION_WINDOW_INSUFFICIENT'); END IF;
  IF candidate_sample_failed THEN expected_reasons := array_append(expected_reasons, 'CANDIDATE_SAMPLE_INSUFFICIENT'); END IF;
  IF baseline_sample_failed THEN expected_reasons := array_append(expected_reasons, 'BASELINE_SAMPLE_INSUFFICIENT'); END IF;
  IF telemetry_failed THEN expected_reasons := array_append(expected_reasons, 'TELEMETRY_MISSING'); END IF;
  IF coverage_failed THEN expected_reasons := array_append(expected_reasons, 'COVERAGE_INCOMPLETE'); END IF;
  IF bucket_failed THEN expected_reasons := array_append(expected_reasons, 'PROFILE_SIZE_COMPARISON_INCOMPLETE'); END IF;
  IF false_positive_failed THEN expected_reasons := array_append(expected_reasons, 'FALSE_POSITIVE_GATE_FAILED'); END IF;
  IF scanner_failure_failed THEN expected_reasons := array_append(expected_reasons, 'SCANNER_FAILURE_GATE_FAILED'); END IF;
  IF latency_failed THEN expected_reasons := array_append(expected_reasons, 'LATENCY_GATE_FAILED'); END IF;
  IF critical_high_failed THEN expected_reasons := array_append(expected_reasons, 'CRITICAL_HIGH_VOLUME_GATE_FAILED'); END IF;
  IF zero_event_failed THEN expected_reasons := array_append(expected_reasons, 'ZERO_TOLERANCE_EVENT_RECORDED'); END IF;
  expected_reason_count := cardinality(expected_reasons);

  IF reason_count <> expected_reason_count
     OR actual_reasons IS DISTINCT FROM expected_reasons
     OR EXISTS (
       SELECT 1
       FROM (
         SELECT "position",
                row_number() OVER (ORDER BY "position") - 1 AS expected_position
         FROM public."SastRuleBundleCanaryStepDecisionReason"
         WHERE "decisionId" = NEW."id"
       ) ordered_reasons
       WHERE ordered_reasons."position" <> ordered_reasons.expected_position
     )
     OR window_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='OBSERVATION_WINDOW_INSUFFICIENT')
     OR candidate_sample_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='CANDIDATE_SAMPLE_INSUFFICIENT')
     OR baseline_sample_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='BASELINE_SAMPLE_INSUFFICIENT')
     OR telemetry_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='TELEMETRY_MISSING')
     OR coverage_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='COVERAGE_INCOMPLETE')
     OR bucket_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='PROFILE_SIZE_COMPARISON_INCOMPLETE')
     OR false_positive_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='FALSE_POSITIVE_GATE_FAILED')
     OR scanner_failure_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='SCANNER_FAILURE_GATE_FAILED')
     OR latency_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='LATENCY_GATE_FAILED')
     OR critical_high_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='CRITICAL_HIGH_VOLUME_GATE_FAILED')
     OR zero_event_failed IS DISTINCT FROM EXISTS (SELECT 1 FROM public."SastRuleBundleCanaryStepDecisionReason" WHERE "decisionId"=NEW."id" AND "reasonCode"='ZERO_TOLERANCE_EVENT_RECORDED')
     OR (NEW."outcome" = 'PASSED') IS DISTINCT FROM (NOT hard_failed AND NOT insufficient)
     OR (NEW."outcome" = 'PAUSED') IS DISTINCT FROM hard_failed
     OR (NEW."outcome" = 'PENDING') IS DISTINCT FROM (NOT hard_failed AND insufficient) THEN
    RAISE EXCEPTION 'SAST canary outcome or reason set does not match exact gates';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_canary_final_receipt"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE rollout_record RECORD; head_record RECORD; actual_count INTEGER;
        first_window TIMESTAMP(3); last_window TIMESTAMP(3);
BEGIN
  SELECT * INTO rollout_record FROM public."SastRuleBundleCanaryRollout"
    WHERE "id" = NEW."rolloutId";
  SELECT * INTO head_record FROM public."SastRuleBundleCanaryRolloutHead"
    WHERE "rolloutId" = NEW."rolloutId" FOR UPDATE;
  SELECT count(*), min(d."windowStartedAt"), max(d."windowEndedAt")
    INTO actual_count, first_window, last_window
  FROM public."SastRuleBundleCanaryReceiptPassedStep" p
  JOIN public."SastRuleBundleCanaryStepDecision" d
    ON d."id" = p."decisionId" AND d."decisionDigest" = p."decisionDigest"
  WHERE p."receiptId" = NEW."id"
    AND d."rolloutId" = NEW."rolloutId"
    AND d."rolloutDigest" = NEW."rolloutDigest"
    AND d."outcome" = 'PASSED';
  IF rollout_record."id" IS NULL OR head_record."rolloutId" IS NULL
     OR actual_count <> 6 OR actual_count <> NEW."passedStepCount"
     OR rollout_record."rolloutDigest" IS DISTINCT FROM NEW."rolloutDigest"
     OR rollout_record."candidateManifestId" IS DISTINCT FROM NEW."candidateManifestId"
     OR rollout_record."candidateManifestDigest" IS DISTINCT FROM NEW."candidateManifestDigest"
     OR rollout_record."candidateBundleId" IS DISTINCT FROM NEW."candidateBundleId"
     OR rollout_record."candidateBundleDigest" IS DISTINCT FROM NEW."candidateBundleDigest"
     OR rollout_record."baselineManifestId" IS DISTINCT FROM NEW."baselineManifestId"
     OR rollout_record."baselineManifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR rollout_record."baselineBundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR rollout_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR rollout_record."profileDigest" IS DISTINCT FROM NEW."profileDigest"
     OR rollout_record."promotionEvidenceId" IS DISTINCT FROM NEW."promotionEvidenceId"
     OR rollout_record."promotionEvidenceDigest" IS DISTINCT FROM NEW."promotionEvidenceDigest"
     OR head_record."currentStep" IS DISTINCT FROM 'PERCENT_100'
     OR head_record."latestOutcome" IS DISTINCT FROM 'PASSED'
     OR NOT EXISTS (
       SELECT 1 FROM public."SastRuleBundleCanaryReceiptPassedStep" p
       WHERE p."receiptId" = NEW."id" AND p."position" = 5
         AND p."decisionId" = head_record."latestDecisionId"
         AND p."decisionDigest" = head_record."latestDecisionDigest"
     )
     OR NEW."observedFrom" IS DISTINCT FROM first_window
     OR NEW."observedThrough" IS DISTINCT FROM last_window THEN
    RAISE EXCEPTION 'SAST canary final receipt does not prove all six passed steps';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_canary_decision_child_count"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE decision_record RECORD; observation_count INTEGER; reason_count INTEGER;
BEGIN
  SELECT * INTO decision_record
  FROM public."SastRuleBundleCanaryStepDecision"
  WHERE "id" = NEW."decisionId";
  SELECT count(*) INTO observation_count
  FROM public."SastRuleBundleCanaryStepDecisionObservation"
  WHERE "decisionId" = NEW."decisionId";
  SELECT count(*) INTO reason_count
  FROM public."SastRuleBundleCanaryStepDecisionReason"
  WHERE "decisionId" = NEW."decisionId";
  IF decision_record."id" IS NULL
     OR observation_count <> decision_record."observationCount"
     OR reason_count <> decision_record."reasonCodeCount" THEN
    RAISE EXCEPTION 'SAST canary decision child set is incomplete or was extended';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_queue_rule_bundle_canary_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE bundle_record JSONB; assignment_record JSONB; head_record RECORD;
BEGIN
  IF jsonb_typeof(NEW."immutablePlan"->'scannerSet'->'ruleBundles')
       IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'SAST queue admission requires canary-qualified rule bundles';
  END IF;
  FOR bundle_record IN
    SELECT value FROM jsonb_array_elements(
      NEW."immutablePlan"->'scannerSet'->'ruleBundles'
    ) ORDER BY value->>'manifestId'
  LOOP
    IF bundle_record->'lifecycle'->>'lifecycleState' = 'ACTIVE' THEN
      IF jsonb_typeof(bundle_record->'canaryAssignment') IS DISTINCT FROM 'null' THEN
        RAISE EXCEPTION 'Active SAST bundles cannot carry canary assignments';
      END IF;
      CONTINUE;
    END IF;
    IF bundle_record->'lifecycle'->>'lifecycleState' <> 'CANARY'
       OR jsonb_typeof(bundle_record->'canaryAssignment') IS DISTINCT FROM 'object' THEN
      RAISE EXCEPTION 'SAST canary bundle assignment is missing or malformed';
    END IF;
    assignment_record := bundle_record->'canaryAssignment';
    SELECT * INTO head_record
    FROM public."SastRuleBundleCanaryRolloutHead"
    WHERE "rolloutId" = assignment_record->>'rolloutId'
    FOR UPDATE;
    IF head_record."rolloutId" IS NULL
       OR head_record."rolloutDigest" IS DISTINCT FROM assignment_record->>'rolloutDigest'
       OR head_record."currentStep" IS DISTINCT FROM assignment_record->>'step'
       OR head_record."latestDecisionId" IS DISTINCT FROM assignment_record->>'stepHeadDecisionId'
       OR head_record."latestDecisionDigest" IS DISTINCT FROM assignment_record->>'stepHeadDecisionDigest'
       OR head_record."latestOutcome" IS NOT DISTINCT FROM 'PAUSED'
       OR assignment_record->>'candidateAssigned' IS DISTINCT FROM 'true'
       OR NOT EXISTS (
         SELECT 1
         FROM public."SastRuleBundleCanaryAssignmentReceipt" receipt
         JOIN public."SastRuleBundleCanaryMembership" membership
           ON membership."id" = receipt."membershipId"
          AND membership."membershipDigest" = receipt."membershipDigest"
         JOIN public."SastRuleBundleCanaryRollout" rollout
           ON rollout."id" = receipt."rolloutId"
          AND rollout."rolloutDigest" = receipt."rolloutDigest"
         WHERE receipt."id" = assignment_record->>'assignmentReceiptId'
           AND receipt."assignmentReceiptDigest" = assignment_record->>'assignmentReceiptDigest'
           AND receipt."rolloutId" = head_record."rolloutId"
           AND receipt."membershipId" = assignment_record->>'membershipId'
           AND receipt."membershipDigest" = assignment_record->>'membershipDigest'
           AND receipt."tenantId" = NEW."tenantId"
           AND receipt."repositoryBindingId" = NEW."repositoryBindingId"
           AND receipt."profileId" = NEW."immutablePlan"->'profile'->>'id'
           AND receipt."profileDigest" = NEW."immutablePlan"->>'profileDigest'
           AND receipt."bucketBasisPoints"::TEXT = assignment_record->>'bucketBasisPoints'
           AND receipt."step" = head_record."currentStep"
           AND receipt."stepHeadDecisionId" IS NOT DISTINCT FROM head_record."latestDecisionId"
           AND receipt."stepHeadDecisionDigest" IS NOT DISTINCT FROM head_record."latestDecisionDigest"
           AND receipt."selection" = 'CANDIDATE'
           AND receipt."selectedManifestId" = bundle_record->>'manifestId'
           AND receipt."selectedManifestDigest" = bundle_record->>'manifestDigest'
           AND receipt."selectedBundleDigest" = bundle_record->>'digest'
           AND membership."bucketBasisPoints" = receipt."bucketBasisPoints"
           AND membership."excluded" IS FALSE
           AND rollout."candidateManifestId" = bundle_record->>'manifestId'
           AND rollout."candidateManifestDigest" = bundle_record->>'manifestDigest'
           AND rollout."candidateBundleDigest" = bundle_record->>'digest'
       ) THEN
      RAISE EXCEPTION 'SAST queue admission canary assignment is stale or unauthorized';
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "SastRuleBundleCanaryRollout_binding" BEFORE INSERT ON "SastRuleBundleCanaryRollout" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_rollout_binding"();
CREATE TRIGGER "SastRuleBundleCanaryRolloutHead_protect_insert" BEFORE INSERT ON "SastRuleBundleCanaryRolloutHead" FOR EACH ROW EXECUTE FUNCTION "protect_sast_rule_bundle_canary_head"();
CREATE TRIGGER "SastRuleBundleCanaryRolloutHead_protect_update" BEFORE UPDATE ON "SastRuleBundleCanaryRolloutHead" FOR EACH ROW EXECUTE FUNCTION "protect_sast_rule_bundle_canary_head"();
CREATE TRIGGER "SastRuleBundleCanaryRolloutHead_protect_delete" BEFORE DELETE ON "SastRuleBundleCanaryRolloutHead" FOR EACH ROW EXECUTE FUNCTION "protect_sast_rule_bundle_canary_head"();
CREATE TRIGGER "SastRuleBundleCanaryRollout_initialize_head" AFTER INSERT ON "SastRuleBundleCanaryRollout" FOR EACH ROW EXECUTE FUNCTION "initialize_sast_rule_bundle_canary_head"();
CREATE CONSTRAINT TRIGGER "SastRuleBundleCanaryRollout_progression" AFTER INSERT ON "SastRuleBundleCanaryRollout" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_progression"();
CREATE TRIGGER "SastRuleBundleCanaryEligibilityDecision_binding" BEFORE INSERT ON "SastRuleBundleCanaryEligibilityDecision" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_eligibility"();
CREATE TRIGGER "SastRuleBundleCanaryMembership_binding" BEFORE INSERT ON "SastRuleBundleCanaryMembership" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_membership"();
CREATE TRIGGER "SastRuleBundleCanaryAssignmentReceipt_binding" BEFORE INSERT ON "SastRuleBundleCanaryAssignmentReceipt" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_assignment"();
CREATE TRIGGER "SastRuleBundleCanaryScanObservation_binding" BEFORE INSERT ON "SastRuleBundleCanaryScanObservation" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_observation"();
CREATE TRIGGER "SastRuleBundleCanaryStepDecision_append" BEFORE INSERT ON "SastRuleBundleCanaryStepDecision" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_decision_append"();
CREATE TRIGGER "SastRuleBundleCanaryStepDecision_refresh_head" AFTER INSERT ON "SastRuleBundleCanaryStepDecision" FOR EACH ROW EXECUTE FUNCTION "refresh_sast_rule_bundle_canary_head"();
CREATE CONSTRAINT TRIGGER "SastRuleBundleCanaryStepDecision_evidence" AFTER INSERT ON "SastRuleBundleCanaryStepDecision" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_decision_evidence"();
CREATE CONSTRAINT TRIGGER "SastRuleBundleCanaryStepDecisionObservation_count" AFTER INSERT ON "SastRuleBundleCanaryStepDecisionObservation" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_decision_child_count"();
CREATE CONSTRAINT TRIGGER "SastRuleBundleCanaryStepDecisionReason_count" AFTER INSERT ON "SastRuleBundleCanaryStepDecisionReason" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_decision_child_count"();
CREATE CONSTRAINT TRIGGER "SastRuleBundleCanaryObservationReceipt_complete" AFTER INSERT ON "SastRuleBundleCanaryObservationReceipt" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_canary_final_receipt"();
CREATE TRIGGER "SastQueueReservation_canary_head" BEFORE INSERT ON "SastQueueReservation" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_queue_rule_bundle_canary_head"();

CREATE TRIGGER "SastRuleBundleCanaryRollout_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryRollout" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryRollout_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryRollout" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryRolloutStep_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryRolloutStep" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryRolloutStep_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryRolloutStep" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryEligibilityDecision_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryEligibilityDecision" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryEligibilityDecision_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryEligibilityDecision" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryMembership_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryMembership" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryMembership_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryMembership" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryAssignmentReceipt_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryAssignmentReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryAssignmentReceipt_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryAssignmentReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryScanObservation_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryScanObservation" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryScanObservation_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryScanObservation" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryStepDecision_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryStepDecision" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryStepDecision_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryStepDecision" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryStepDecisionReason_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryStepDecisionReason" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryStepDecisionReason_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryStepDecisionReason" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryStepDecisionObservation_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryStepDecisionObservation" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryStepDecisionObservation_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryStepDecisionObservation" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryObservationReceipt_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryObservationReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryObservationReceipt_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryObservationReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryReceiptPassedStep_immutable_update" BEFORE UPDATE ON "SastRuleBundleCanaryReceiptPassedStep" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();
CREATE TRIGGER "SastRuleBundleCanaryReceiptPassedStep_immutable_delete" BEFORE DELETE ON "SastRuleBundleCanaryReceiptPassedStep" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_canary_mutation"();

COMMENT ON TABLE "SastRuleBundleCanaryRollout" IS 'T048 immutable candidate/baseline/profile/policy rollout identity without HMAC key material or content.';
COMMENT ON TABLE "SastRuleBundleCanaryEligibilityDecision" IS 'T048 platform-owned contractual/residency eligibility decision; customer overrides and finding-derived assignment are forbidden.';
COMMENT ON TABLE "SastRuleBundleCanaryMembership" IS 'T048 stable HMAC-derived tenant/repository/profile membership; only the digest and bucket are stored.';
COMMENT ON TABLE "SastRuleBundleCanaryAssignmentReceipt" IS 'T048 per-planning candidate assignment bound to the current rollout head and persisted membership.';
COMMENT ON TABLE "SastRuleBundleCanaryScanObservation" IS 'T048 content-free terminal scan measurements bound to immutable plan, coverage, and publication authority.';
COMMENT ON TABLE "SastRuleBundleCanaryStepDecision" IS 'T048 append-only quantitative candidate/baseline decision with exact samples, windows, thresholds, and zero-tolerance events.';
COMMENT ON TABLE "SastRuleBundleCanaryRolloutHead" IS 'T048 trigger-maintained current step projection used to fence planning-to-queue races.';
COMMENT ON TABLE "SastRuleBundleCanaryObservationReceipt" IS 'T048 exact six-step pass receipt and sole CANARY to ACTIVE lifecycle authority.';
