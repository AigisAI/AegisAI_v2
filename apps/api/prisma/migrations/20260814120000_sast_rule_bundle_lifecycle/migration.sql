-- T047 adds a content-free, append-only rule-bundle promotion ledger. The
-- ledger stores quantitative evidence, independent human approvals, exact
-- lifecycle transitions, and pre-planning selection receipts. It never stores
-- rule bodies, repository content, customer executable configuration, or secrets.

-- Canonical scan-key v3 binds the immutable lifecycle authorization projection.
-- Selection receipts remain in the immutable plan for audit, but their
-- evaluatedAt-derived identity is excluded from the idempotency key.
-- Non-terminal v2 work must be drained because immutable plan identities are
-- never rewritten during deployment.
DO $t047_canonical_key_cutover$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM "ScanRequest"
    WHERE "status" IN ('QUEUED', 'PLANNING', 'RUNNING')
      AND "sastPlanning" IS NOT NULL
  ) OR EXISTS (
    SELECT 1
    FROM "SastQueueReservation"
    WHERE "terminalStatus" IS NULL
  ) THEN
    RAISE EXCEPTION
      'T047 canonical scan-key v3 cutover requires all existing v2 SAST plans and reservations to be completed, failed, or canceled';
  END IF;
END;
$t047_canonical_key_cutover$;

CREATE TABLE "SastRuleBundlePromotionEvidence" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "evidenceDigest" TEXT NOT NULL,
  "manifestId" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "verificationId" TEXT NOT NULL,
  "verificationDigest" TEXT NOT NULL,
  "bundleId" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "candidateAuthorRef" TEXT NOT NULL,
  "baselineManifestId" TEXT NOT NULL,
  "baselineManifestDigest" TEXT NOT NULL,
  "baselineBundleDigest" TEXT NOT NULL,
  "rollbackTargetDigest" TEXT NOT NULL,
  "environmentRef" TEXT NOT NULL,
  "goldenCorpusRef" TEXT NOT NULL,
  "priorMustDetectCorpusRef" TEXT NOT NULL,
  "maliciousCorpusRef" TEXT NOT NULL,
  "parserCorpusRef" TEXT NOT NULL,
  "fingerprintCorpusRef" TEXT NOT NULL,
  "coverageCorpusRef" TEXT NOT NULL,
  "performanceCorpusRef" TEXT NOT NULL,
  "corpusSetDigest" TEXT NOT NULL,
  "positiveCases" INTEGER NOT NULL,
  "negativeCases" INTEGER NOT NULL,
  "performanceRuns" INTEGER NOT NULL,
  "goldenPassedCases" INTEGER NOT NULL,
  "goldenTotalCases" INTEGER NOT NULL,
  "priorMustDetectPassedCases" INTEGER NOT NULL,
  "priorMustDetectTotalCases" INTEGER NOT NULL,
  "mustDetectTruePositiveCases" INTEGER NOT NULL,
  "mustDetectExpectedCases" INTEGER NOT NULL,
  "criticalHighTruePositiveCases" INTEGER NOT NULL,
  "criticalHighReportedCases" INTEGER NOT NULL,
  "maliciousPassedCases" INTEGER NOT NULL,
  "maliciousTotalCases" INTEGER NOT NULL,
  "parserRejectedCases" INTEGER NOT NULL,
  "parserExpectedRejectCases" INTEGER NOT NULL,
  "fingerprintPassedCases" INTEGER NOT NULL,
  "fingerprintTotalCases" INTEGER NOT NULL,
  "coveragePassedCases" INTEGER NOT NULL,
  "coverageTotalCases" INTEGER NOT NULL,
  "falsePositiveIncreaseBasisPoints" INTEGER NOT NULL,
  "scannerFailureRateBasisPoints" INTEGER NOT NULL,
  "p95LatencyIncreaseBasisPoints" INTEGER NOT NULL,
  "candidateP95LatencyMilliseconds" INTEGER NOT NULL,
  "crossTenantEvents" INTEGER NOT NULL,
  "secretLeakEvents" INTEGER NOT NULL,
  "sandboxEscapeEvents" INTEGER NOT NULL,
  "stalePublicationEvents" INTEGER NOT NULL,
  "measurementDigest" TEXT NOT NULL,
  "measuredAt" TIMESTAMP(3) NOT NULL,
  "gatesPassed" BOOLEAN NOT NULL DEFAULT true,
  "automatedEvidenceOnly" BOOLEAN NOT NULL DEFAULT true,
  "approvalGranted" BOOLEAN NOT NULL DEFAULT false,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT false,
  "executableRuleContentStored" BOOLEAN NOT NULL DEFAULT false,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT false,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleBundlePromotionEvidence_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundlePromotionEvidence_contract_check" CHECK (
    "id" ~ '^sast-rule-bundle-promotion-evidence://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-bundle-promotion-evidence-v1'
    AND "evidenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-promotion-evidence://' || substring("evidenceDigest" FROM 8)
    AND "manifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "baselineManifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "verificationId" ~ '^sast-rule-bundle-verification://[a-f0-9]{64}$'
    AND "manifestId" <> "baselineManifestId"
    AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "verificationDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "baselineManifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "manifestId" = 'sast-rule-bundle-manifest://' || substring("manifestDigest" FROM 8)
    AND "verificationId" = 'sast-rule-bundle-verification://' || substring("manifestDigest" FROM 8)
    AND "baselineManifestId" = 'sast-rule-bundle-manifest://' || substring("baselineManifestDigest" FROM 8)
    AND "baselineBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "rollbackTargetDigest" = "baselineBundleDigest"
    AND "manifestDigest" <> "baselineManifestDigest"
    AND "bundleDigest" <> "baselineBundleDigest"
    AND "bundleId" ~ '^sast-rule-bundle://(opengrep|trivy)/[a-z0-9][a-z0-9._-]{0,127}$'
    AND "profileId" IN ('JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1')
    AND "candidateAuthorRef" ~ '^(spiffe|sast-actor|sast-approver)://[^[:space:]]+$'
    AND octet_length("candidateAuthorRef") BETWEEN 1 AND 512
    AND "corpusSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "measurementDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "environmentRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "goldenCorpusRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "priorMustDetectCorpusRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "maliciousCorpusRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "parserCorpusRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "fingerprintCorpusRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "coverageCorpusRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "performanceCorpusRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "environmentRef" !~ '^https?://'
    AND "goldenCorpusRef" !~ '^https?://' AND "priorMustDetectCorpusRef" !~ '^https?://'
    AND "maliciousCorpusRef" !~ '^https?://' AND "parserCorpusRef" !~ '^https?://'
    AND "fingerprintCorpusRef" !~ '^https?://' AND "coverageCorpusRef" !~ '^https?://'
    AND "performanceCorpusRef" !~ '^https?://'
    AND "positiveCases" BETWEEN 200 AND 1000000000
    AND "negativeCases" BETWEEN 200 AND 1000000000
    AND "performanceRuns" BETWEEN 30 AND 1000000000
    AND "goldenTotalCases" = "positiveCases" + "negativeCases"
    AND "goldenPassedCases" = "goldenTotalCases"
    AND "priorMustDetectTotalCases" > 0 AND "priorMustDetectPassedCases" = "priorMustDetectTotalCases"
    AND "priorMustDetectTotalCases" <= "positiveCases"
    AND "maliciousTotalCases" > 0 AND "maliciousPassedCases" = "maliciousTotalCases"
    AND "parserExpectedRejectCases" > 0 AND "parserRejectedCases" = "parserExpectedRejectCases"
    AND "fingerprintTotalCases" > 0 AND "fingerprintPassedCases" = "fingerprintTotalCases"
    AND "coverageTotalCases" > 0 AND "coveragePassedCases" = "coverageTotalCases"
    AND "mustDetectExpectedCases" > 0
    AND "mustDetectExpectedCases" <= "positiveCases"
    AND "mustDetectTruePositiveCases" BETWEEN 0 AND "mustDetectExpectedCases"
    AND "mustDetectTruePositiveCases"::BIGINT * 10000 >= "mustDetectExpectedCases"::BIGINT * 9500
    AND "criticalHighReportedCases" > 0
    AND "criticalHighReportedCases" <= "positiveCases" + "negativeCases"
    AND "criticalHighTruePositiveCases" BETWEEN 0 AND "criticalHighReportedCases"
    AND "criticalHighTruePositiveCases"::BIGINT * 10000 >= "criticalHighReportedCases"::BIGINT * 9000
    AND "falsePositiveIncreaseBasisPoints" BETWEEN -10000 AND 200
    AND "scannerFailureRateBasisPoints" BETWEEN 0 AND 200
    AND "p95LatencyIncreaseBasisPoints" BETWEEN -10000 AND 2000
    AND (("profileId" = 'JAVA_FAST_V1' AND "candidateP95LatencyMilliseconds" BETWEEN 1 AND 600000)
      OR ("profileId" IN ('JAVA_DEEP_V1','COMMON_DEEP_V1') AND "candidateP95LatencyMilliseconds" BETWEEN 1 AND 2700000))
    AND "crossTenantEvents" = 0 AND "secretLeakEvents" = 0
    AND "sandboxEscapeEvents" = 0 AND "stalePublicationEvents" = 0
    AND "gatesPassed" IS TRUE AND "automatedEvidenceOnly" IS TRUE
    AND "approvalGranted" IS FALSE AND "customerInputAccepted" IS FALSE
    AND "executableRuleContentStored" IS FALSE
    AND "repositoryContentStored" IS FALSE AND "secretValueStored" IS FALSE
  )
);

CREATE TABLE "SastRuleBundlePromotionApproval" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "approvalDigest" TEXT NOT NULL,
  "evidenceId" TEXT NOT NULL,
  "evidenceDigest" TEXT NOT NULL,
  "manifestId" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "candidateAuthorRef" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  "approverRef" TEXT NOT NULL,
  "approvalRef" TEXT NOT NULL,
  "approvedAt" TIMESTAMP(3) NOT NULL,
  "approved" BOOLEAN NOT NULL DEFAULT true,
  "humanApproval" BOOLEAN NOT NULL DEFAULT true,
  "automatedApproval" BOOLEAN NOT NULL DEFAULT false,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleBundlePromotionApproval_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundlePromotionApproval_contract_check" CHECK (
    "id" ~ '^sast-rule-bundle-promotion-approval://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-bundle-promotion-approval-v1'
    AND "approvalDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-promotion-approval://' || substring("approvalDigest" FROM 8)
    AND "evidenceId" ~ '^sast-rule-bundle-promotion-evidence://[a-f0-9]{64}$'
    AND "evidenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "manifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "evidenceId" = 'sast-rule-bundle-promotion-evidence://' || substring("evidenceDigest" FROM 8)
    AND "manifestId" = 'sast-rule-bundle-manifest://' || substring("manifestDigest" FROM 8)
    AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "role" IN ('SECURITY_ENGINEERING', 'SCAN_PLATFORM', 'SECURITY_OPERATIONS')
    AND "approverRef" ~ '^(spiffe|sast-actor|sast-approver)://[^[:space:]]+$'
    AND "candidateAuthorRef" ~ '^(spiffe|sast-actor|sast-approver)://[^[:space:]]+$'
    AND "approverRef" <> "candidateAuthorRef"
    AND octet_length("approverRef") BETWEEN 1 AND 512
    AND "approvalRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "approvalRef" !~ '^https?://'
    AND "approved" IS TRUE AND "humanApproval" IS TRUE
    AND "automatedApproval" IS FALSE AND "customerInputAccepted" IS FALSE
  )
);

CREATE TABLE "SastRuleBundleLifecycleTransition" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "transitionDigest" TEXT NOT NULL,
  "manifestId" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "bundleId" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "sequence" INTEGER NOT NULL,
  "fromState" TEXT NOT NULL,
  "toState" TEXT NOT NULL,
  "previousTransitionId" TEXT,
  "previousTransitionDigest" TEXT,
  "promotionEvidenceId" TEXT NOT NULL,
  "promotionEvidenceDigest" TEXT NOT NULL,
  "candidateAuthorRef" TEXT NOT NULL,
  "approvalSetDigest" TEXT NOT NULL,
  "externalAuthority" TEXT NOT NULL,
  "externalAuthorityReceiptRef" TEXT,
  "externalAuthorityReceiptDigest" TEXT,
  "actorRef" TEXT NOT NULL,
  "reasonRef" TEXT NOT NULL,
  "auditRef" TEXT NOT NULL,
  "transitionedAt" TIMESTAMP(3) NOT NULL,
  "source" TEXT NOT NULL DEFAULT 'PLATFORM_RULE_GOVERNANCE',
  "immutable" BOOLEAN NOT NULL DEFAULT true,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT false,
  "executableRuleContentStored" BOOLEAN NOT NULL DEFAULT false,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT false,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleBundleLifecycleTransition_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleLifecycleTransition_contract_check" CHECK (
    "id" ~ '^sast-rule-bundle-lifecycle-transition://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-bundle-lifecycle-transition-v1'
    AND "transitionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-lifecycle-transition://' || substring("transitionDigest" FROM 8)
    AND "manifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "bundleId" ~ '^sast-rule-bundle://(opengrep|trivy)/[a-z0-9][a-z0-9._-]{0,127}$'
    AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "sequence" BETWEEN 1 AND 1000000
    AND "fromState" IN ('DRAFT','VALIDATED','CANARY','ACTIVE','SUSPENDED','ROLLED_BACK','RETIRED')
    AND "toState" IN ('DRAFT','VALIDATED','CANARY','ACTIVE','SUSPENDED','ROLLED_BACK','RETIRED')
    AND (("fromState" = 'DRAFT' AND "toState" = 'VALIDATED')
      OR ("fromState" = 'VALIDATED' AND "toState" = 'CANARY')
      OR ("fromState" = 'CANARY' AND "toState" = 'ACTIVE')
      OR ("fromState" = 'ACTIVE' AND "toState" = 'RETIRED')
      OR ("fromState" IN ('CANARY','ACTIVE') AND "toState" = 'SUSPENDED')
      OR ("fromState" = 'SUSPENDED' AND "toState" = 'ROLLED_BACK'))
    AND (("sequence" = 1 AND "fromState" = 'DRAFT' AND "previousTransitionId" IS NULL AND "previousTransitionDigest" IS NULL)
      OR ("sequence" > 1 AND "previousTransitionId" ~ '^sast-rule-bundle-lifecycle-transition://[a-f0-9]{64}$' AND "previousTransitionDigest" ~ '^sha256:[a-f0-9]{64}$' AND "previousTransitionId" = 'sast-rule-bundle-lifecycle-transition://' || substring("previousTransitionDigest" FROM 8)))
    AND "promotionEvidenceId" ~ '^sast-rule-bundle-promotion-evidence://[a-f0-9]{64}$'
    AND "promotionEvidenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "manifestId" = 'sast-rule-bundle-manifest://' || substring("manifestDigest" FROM 8)
    AND "promotionEvidenceId" = 'sast-rule-bundle-promotion-evidence://' || substring("promotionEvidenceDigest" FROM 8)
    AND "approvalSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "candidateAuthorRef" ~ '^(spiffe|sast-actor|sast-approver)://[^[:space:]]+$'
    AND "actorRef" ~ '^(spiffe|sast-actor|sast-approver)://[^[:space:]]+$'
    AND "reasonRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "auditRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "reasonRef" !~ '^https?://' AND "auditRef" !~ '^https?://'
    AND (("fromState" = 'CANARY' AND "toState" = 'ACTIVE' AND "externalAuthority" = 'CANARY_OBSERVATION')
      OR ("toState" = 'SUSPENDED' AND "externalAuthority" = 'EMERGENCY_SUSPENSION')
      OR ("fromState" = 'SUSPENDED' AND "toState" = 'ROLLED_BACK' AND "externalAuthority" = 'ROLLBACK')
      OR (NOT (("fromState" = 'CANARY' AND "toState" = 'ACTIVE') OR "toState" = 'SUSPENDED' OR ("fromState" = 'SUSPENDED' AND "toState" = 'ROLLED_BACK')) AND "externalAuthority" = 'NONE'))
    AND (("externalAuthority" = 'NONE' AND "externalAuthorityReceiptRef" IS NULL AND "externalAuthorityReceiptDigest" IS NULL)
      OR ("externalAuthority" <> 'NONE' AND "externalAuthorityReceiptRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$' AND "externalAuthorityReceiptRef" !~ '^https?://' AND "externalAuthorityReceiptDigest" ~ '^sha256:[a-f0-9]{64}$' AND right("externalAuthorityReceiptRef", 71) = "externalAuthorityReceiptDigest"))
    AND "source" = 'PLATFORM_RULE_GOVERNANCE' AND "immutable" IS TRUE
    AND "customerInputAccepted" IS FALSE AND "executableRuleContentStored" IS FALSE
    AND "repositoryContentStored" IS FALSE AND "secretValueStored" IS FALSE
  )
);

CREATE TABLE "SastRuleBundleLifecycleHead" (
  "manifestId" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "bundleId" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "transitionId" TEXT NOT NULL,
  "transitionDigest" TEXT NOT NULL,
  "sequence" INTEGER NOT NULL,
  "lifecycleState" TEXT NOT NULL,
  "promotionEvidenceId" TEXT NOT NULL,
  "promotionEvidenceDigest" TEXT NOT NULL,
  "approvalSetDigest" TEXT NOT NULL,
  "transitionedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleBundleLifecycleHead_pkey" PRIMARY KEY ("manifestId"),
  CONSTRAINT "SastRuleBundleLifecycleHead_contract_check" CHECK (
    "manifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "manifestId" = 'sast-rule-bundle-manifest://' || substring("manifestDigest" FROM 8)
    AND "bundleId" ~ '^sast-rule-bundle://(opengrep|trivy)/[a-z0-9][a-z0-9._-]{0,127}$'
    AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "transitionId" ~ '^sast-rule-bundle-lifecycle-transition://[a-f0-9]{64}$'
    AND "transitionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "transitionId" = 'sast-rule-bundle-lifecycle-transition://' || substring("transitionDigest" FROM 8)
    AND "sequence" BETWEEN 1 AND 1000000
    AND "lifecycleState" IN ('VALIDATED','CANARY','ACTIVE','SUSPENDED','ROLLED_BACK','RETIRED')
    AND "promotionEvidenceId" ~ '^sast-rule-bundle-promotion-evidence://[a-f0-9]{64}$'
    AND "promotionEvidenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "promotionEvidenceId" = 'sast-rule-bundle-promotion-evidence://' || substring("promotionEvidenceDigest" FROM 8)
    AND "approvalSetDigest" ~ '^sha256:[a-f0-9]{64}$'
  )
);

CREATE TABLE "SastRuleBundleLifecycleTransitionApproval" (
  "transitionId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "approvalId" TEXT NOT NULL,
  "approvalDigest" TEXT NOT NULL,
  "evidenceId" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  "approverRef" TEXT NOT NULL,
  "approvedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "SastRuleBundleLifecycleTransitionApproval_pkey" PRIMARY KEY ("transitionId", "position"),
  CONSTRAINT "SastRuleBundleLifecycleTransitionApproval_contract_check" CHECK (
    "transitionId" ~ '^sast-rule-bundle-lifecycle-transition://[a-f0-9]{64}$'
    AND "position" BETWEEN 0 AND 2
    AND "approvalId" ~ '^sast-rule-bundle-promotion-approval://[a-f0-9]{64}$'
    AND "approvalDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "evidenceId" ~ '^sast-rule-bundle-promotion-evidence://[a-f0-9]{64}$'
    AND (("position" = 0 AND "role" = 'SECURITY_ENGINEERING')
      OR ("position" = 1 AND "role" IN ('SCAN_PLATFORM', 'SECURITY_OPERATIONS'))
      OR ("position" = 2 AND "role" = 'SECURITY_OPERATIONS'))
    AND "approverRef" ~ '^(spiffe|sast-actor|sast-approver)://[^[:space:]]+$'
  )
);

CREATE TABLE "SastRuleBundleLifecycleSelectionReceipt" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "receiptDigest" TEXT NOT NULL,
  "manifestId" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "bundleId" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "lifecycleState" TEXT NOT NULL,
  "lifecycleSequence" INTEGER NOT NULL,
  "transitionId" TEXT NOT NULL,
  "transitionDigest" TEXT NOT NULL,
  "promotionEvidenceId" TEXT NOT NULL,
  "promotionEvidenceDigest" TEXT NOT NULL,
  "approvalSetDigest" TEXT NOT NULL,
  "evaluatedAt" TIMESTAMP(3) NOT NULL,
  "selectable" BOOLEAN NOT NULL DEFAULT true,
  "latestTransitionVerified" BOOLEAN NOT NULL DEFAULT true,
  "approvalSeparationVerified" BOOLEAN NOT NULL DEFAULT true,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT false,
  "executableRuleContentStored" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleBundleLifecycleSelectionReceipt_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleLifecycleSelectionReceipt_contract_check" CHECK (
    "id" ~ '^sast-rule-bundle-lifecycle-selection://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-bundle-lifecycle-selection-v1'
    AND "receiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-lifecycle-selection://' || substring("receiptDigest" FROM 8)
    AND "manifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "manifestId" = 'sast-rule-bundle-manifest://' || substring("manifestDigest" FROM 8)
    AND "bundleId" ~ '^sast-rule-bundle://(opengrep|trivy)/[a-z0-9][a-z0-9._-]{0,127}$'
    AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "lifecycleState" IN ('CANARY','ACTIVE')
    AND "lifecycleSequence" BETWEEN 1 AND 1000000
    AND "transitionId" ~ '^sast-rule-bundle-lifecycle-transition://[a-f0-9]{64}$'
    AND "transitionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "promotionEvidenceId" ~ '^sast-rule-bundle-promotion-evidence://[a-f0-9]{64}$'
    AND "promotionEvidenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "transitionId" = 'sast-rule-bundle-lifecycle-transition://' || substring("transitionDigest" FROM 8)
    AND "promotionEvidenceId" = 'sast-rule-bundle-promotion-evidence://' || substring("promotionEvidenceDigest" FROM 8)
    AND "approvalSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "selectable" IS TRUE AND "latestTransitionVerified" IS TRUE
    AND "approvalSeparationVerified" IS TRUE
    AND "customerInputAccepted" IS FALSE AND "executableRuleContentStored" IS FALSE
  )
);

CREATE UNIQUE INDEX "SastRuleBundleManifest_evidence_baseline_key" ON "SastRuleBundleManifest"("id", "manifestDigest", "bundleDigest");
CREATE UNIQUE INDEX "SastRuleBundleManifest_evidence_candidate_key" ON "SastRuleBundleManifest"("id", "manifestDigest", "bundleId", "bundleDigest");
CREATE UNIQUE INDEX "SastRuleBundleSupplyChainAttestation_evidence_key" ON "SastRuleBundleSupplyChainAttestation"("id", "manifestId", "attestationDigest");
CREATE UNIQUE INDEX "SastRuleBundlePromotionEvidence_evidenceDigest_key" ON "SastRuleBundlePromotionEvidence"("evidenceDigest");
CREATE UNIQUE INDEX "SastRuleBundlePromotionEvidence_binding_key" ON "SastRuleBundlePromotionEvidence"("id", "evidenceDigest", "manifestId", "manifestDigest", "bundleDigest", "candidateAuthorRef");
CREATE INDEX "SastRuleBundlePromotionEvidence_manifest_measured_idx" ON "SastRuleBundlePromotionEvidence"("manifestId", "measuredAt");
CREATE INDEX "SastRuleBundlePromotionEvidence_baseline_idx" ON "SastRuleBundlePromotionEvidence"("baselineManifestId");
CREATE UNIQUE INDEX "SastRuleBundlePromotionApproval_approvalDigest_key" ON "SastRuleBundlePromotionApproval"("approvalDigest");
CREATE UNIQUE INDEX "SastRuleBundlePromotionApproval_evidence_role_key" ON "SastRuleBundlePromotionApproval"("evidenceId", "role");
CREATE UNIQUE INDEX "SastRuleBundlePromotionApproval_evidence_approver_key" ON "SastRuleBundlePromotionApproval"("evidenceId", "approverRef");
CREATE UNIQUE INDEX "SastRuleBundlePromotionApproval_transition_key" ON "SastRuleBundlePromotionApproval"("id", "approvalDigest", "evidenceId", "role", "approverRef", "approvedAt");
CREATE INDEX "SastRuleBundlePromotionApproval_manifest_approved_idx" ON "SastRuleBundlePromotionApproval"("manifestId", "approvedAt");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleTransition_transitionDigest_key" ON "SastRuleBundleLifecycleTransition"("transitionDigest");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleTransition_id_transitionDigest_key" ON "SastRuleBundleLifecycleTransition"("id", "transitionDigest");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleTransition_manifest_sequence_key" ON "SastRuleBundleLifecycleTransition"("manifestId", "sequence");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleTransition_approval_evidence_key" ON "SastRuleBundleLifecycleTransition"("id", "promotionEvidenceId");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleTransition_selection_key" ON "SastRuleBundleLifecycleTransition"("id", "transitionDigest", "manifestId", "manifestDigest", "bundleId", "bundleDigest", "sequence", "toState", "promotionEvidenceId", "promotionEvidenceDigest", "approvalSetDigest");
CREATE INDEX "SastRuleBundleLifecycleTransition_manifest_time_idx" ON "SastRuleBundleLifecycleTransition"("manifestId", "transitionedAt");
CREATE INDEX "SastRuleBundleLifecycleTransition_evidence_idx" ON "SastRuleBundleLifecycleTransition"("promotionEvidenceId");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleHead_transitionId_key" ON "SastRuleBundleLifecycleHead"("transitionId");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleHead_transitionDigest_key" ON "SastRuleBundleLifecycleHead"("transitionDigest");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleHead_manifest_key" ON "SastRuleBundleLifecycleHead"("manifestId", "manifestDigest", "bundleId", "bundleDigest");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleHead_transition_key" ON "SastRuleBundleLifecycleHead"("transitionId", "transitionDigest", "manifestId", "manifestDigest", "bundleId", "bundleDigest", "sequence", "lifecycleState", "promotionEvidenceId", "promotionEvidenceDigest", "approvalSetDigest");
CREATE INDEX "SastRuleBundleLifecycleHead_state_updated_idx" ON "SastRuleBundleLifecycleHead"("lifecycleState", "updatedAt");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleTransitionApproval_id_key" ON "SastRuleBundleLifecycleTransitionApproval"("transitionId", "approvalId");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleTransitionApproval_role_key" ON "SastRuleBundleLifecycleTransitionApproval"("transitionId", "role");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleTransitionApproval_approver_key" ON "SastRuleBundleLifecycleTransitionApproval"("transitionId", "approverRef");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleSelectionReceipt_receiptDigest_key" ON "SastRuleBundleLifecycleSelectionReceipt"("receiptDigest");
CREATE UNIQUE INDEX "SastRuleBundleLifecycleSelectionReceipt_transition_time_key" ON "SastRuleBundleLifecycleSelectionReceipt"("transitionId", "evaluatedAt");
CREATE INDEX "SastRuleBundleLifecycleSelectionReceipt_manifest_time_idx" ON "SastRuleBundleLifecycleSelectionReceipt"("manifestId", "evaluatedAt");

ALTER TABLE "SastRuleBundlePromotionEvidence" ADD CONSTRAINT "SastRuleBundlePromotionEvidence_candidate_manifest_fkey" FOREIGN KEY ("manifestId", "manifestDigest", "bundleId", "bundleDigest") REFERENCES "SastRuleBundleManifest"("id", "manifestDigest", "bundleId", "bundleDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundlePromotionEvidence" ADD CONSTRAINT "SastRuleBundlePromotionEvidence_baseline_manifest_fkey" FOREIGN KEY ("baselineManifestId", "baselineManifestDigest", "baselineBundleDigest") REFERENCES "SastRuleBundleManifest"("id", "manifestDigest", "bundleDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundlePromotionEvidence" ADD CONSTRAINT "SastRuleBundlePromotionEvidence_verification_fkey" FOREIGN KEY ("verificationId", "manifestId", "verificationDigest") REFERENCES "SastRuleBundleSupplyChainAttestation"("id", "manifestId", "attestationDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundlePromotionApproval" ADD CONSTRAINT "SastRuleBundlePromotionApproval_evidence_fkey" FOREIGN KEY ("evidenceId", "evidenceDigest", "manifestId", "manifestDigest", "bundleDigest", "candidateAuthorRef") REFERENCES "SastRuleBundlePromotionEvidence"("id", "evidenceDigest", "manifestId", "manifestDigest", "bundleDigest", "candidateAuthorRef") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleLifecycleTransition" ADD CONSTRAINT "SastRuleBundleLifecycleTransition_manifest_fkey" FOREIGN KEY ("manifestId", "manifestDigest", "bundleId", "bundleDigest") REFERENCES "SastRuleBundleManifest"("id", "manifestDigest", "bundleId", "bundleDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleLifecycleTransition" ADD CONSTRAINT "SastRuleBundleLifecycleTransition_evidence_fkey" FOREIGN KEY ("promotionEvidenceId", "promotionEvidenceDigest", "manifestId", "manifestDigest", "bundleDigest", "candidateAuthorRef") REFERENCES "SastRuleBundlePromotionEvidence"("id", "evidenceDigest", "manifestId", "manifestDigest", "bundleDigest", "candidateAuthorRef") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleLifecycleTransition" ADD CONSTRAINT "SastRuleBundleLifecycleTransition_previousTransition_fkey" FOREIGN KEY ("previousTransitionId", "previousTransitionDigest") REFERENCES "SastRuleBundleLifecycleTransition"("id", "transitionDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleLifecycleHead" ADD CONSTRAINT "SastRuleBundleLifecycleHead_manifest_fkey" FOREIGN KEY ("manifestId", "manifestDigest", "bundleId", "bundleDigest") REFERENCES "SastRuleBundleManifest"("id", "manifestDigest", "bundleId", "bundleDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleLifecycleHead" ADD CONSTRAINT "SastRuleBundleLifecycleHead_transition_fkey" FOREIGN KEY ("transitionId", "transitionDigest", "manifestId", "manifestDigest", "bundleId", "bundleDigest", "sequence", "lifecycleState", "promotionEvidenceId", "promotionEvidenceDigest", "approvalSetDigest") REFERENCES "SastRuleBundleLifecycleTransition"("id", "transitionDigest", "manifestId", "manifestDigest", "bundleId", "bundleDigest", "sequence", "toState", "promotionEvidenceId", "promotionEvidenceDigest", "approvalSetDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleLifecycleTransitionApproval" ADD CONSTRAINT "SastRuleBundleLifecycleTransitionApproval_transition_fkey" FOREIGN KEY ("transitionId", "evidenceId") REFERENCES "SastRuleBundleLifecycleTransition"("id", "promotionEvidenceId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleLifecycleTransitionApproval" ADD CONSTRAINT "SastRuleBundleLifecycleTransitionApproval_approval_fkey" FOREIGN KEY ("approvalId", "approvalDigest", "evidenceId", "role", "approverRef", "approvedAt") REFERENCES "SastRuleBundlePromotionApproval"("id", "approvalDigest", "evidenceId", "role", "approverRef", "approvedAt") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleLifecycleSelectionReceipt" ADD CONSTRAINT "SastRuleBundleLifecycleSelectionReceipt_transition_fkey" FOREIGN KEY ("transitionId", "transitionDigest", "manifestId", "manifestDigest", "bundleId", "bundleDigest", "lifecycleSequence", "lifecycleState", "promotionEvidenceId", "promotionEvidenceDigest", "approvalSetDigest") REFERENCES "SastRuleBundleLifecycleTransition"("id", "transitionDigest", "manifestId", "manifestDigest", "bundleId", "bundleDigest", "sequence", "toState", "promotionEvidenceId", "promotionEvidenceDigest", "approvalSetDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;

CREATE FUNCTION "enforce_sast_rule_bundle_promotion_evidence_binding"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE candidate_record RECORD; baseline_record RECORD;
        candidate_verified_at TIMESTAMP(3); baseline_verified_at TIMESTAMP(3);
BEGIN
  SELECT "rollbackTargetDigest", "scanner", "builtAt" INTO candidate_record
  FROM public."SastRuleBundleManifest" WHERE "id" = NEW."manifestId";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST promotion evidence candidate manifest is unavailable';
  END IF;
  SELECT "bundleId", "scanner", "builtAt" INTO baseline_record
  FROM public."SastRuleBundleManifest" WHERE "id" = NEW."baselineManifestId";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST promotion evidence baseline manifest is unavailable';
  END IF;
  SELECT "verifiedAt" INTO candidate_verified_at
  FROM public."SastRuleBundleSupplyChainAttestation"
  WHERE "id" = NEW."verificationId" AND "manifestId" = NEW."manifestId";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST promotion evidence candidate verification is unavailable';
  END IF;
  SELECT "verifiedAt" INTO baseline_verified_at
  FROM public."SastRuleBundleSupplyChainAttestation"
  WHERE "manifestId" = NEW."baselineManifestId";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST promotion evidence baseline verification is unavailable';
  END IF;
  IF NOT EXISTS (
       SELECT 1 FROM public."SastRuleBundleCompatibilityEntry"
       WHERE "manifestId" = NEW."manifestId" AND "kind" = 'PROFILE_ID' AND "value" = NEW."profileId"
     )
     OR NOT EXISTS (
       SELECT 1 FROM public."SastRuleBundleCompatibilityEntry"
       WHERE "manifestId" = NEW."baselineManifestId" AND "kind" = 'PROFILE_ID' AND "value" = NEW."profileId"
     )
     OR candidate_record."rollbackTargetDigest" <> NEW."baselineBundleDigest"
     OR baseline_record."bundleId" <> NEW."bundleId"
     OR baseline_record."scanner" <> candidate_record."scanner"
     OR NEW."measuredAt" < candidate_record."builtAt"
     OR NEW."measuredAt" < baseline_record."builtAt"
     OR NEW."measuredAt" < candidate_verified_at
     OR NEW."measuredAt" < baseline_verified_at THEN
    RAISE EXCEPTION 'SAST promotion evidence does not match its candidate and baseline manifests';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_lifecycle_append"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE latest_record RECORD; evidence_time TIMESTAMP(3);
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW."manifestId", 0));
  SELECT "id", "transitionDigest", "sequence", "toState", "transitionedAt"
    INTO latest_record
  FROM public."SastRuleBundleLifecycleTransition"
  WHERE "manifestId" = NEW."manifestId"
  ORDER BY "sequence" DESC LIMIT 1;
  IF NOT FOUND THEN
    IF NEW."sequence" <> 1 OR NEW."fromState" <> 'DRAFT'
       OR NEW."previousTransitionId" IS NOT NULL
       OR NEW."previousTransitionDigest" IS NOT NULL THEN
      RAISE EXCEPTION 'SAST lifecycle transition must start at DRAFT sequence one';
    END IF;
  ELSIF NEW."sequence" <> latest_record."sequence" + 1
     OR NEW."fromState" <> latest_record."toState"
     OR NEW."previousTransitionId" <> latest_record."id"
     OR NEW."previousTransitionDigest" <> latest_record."transitionDigest"
     OR NEW."transitionedAt" < latest_record."transitionedAt" THEN
    RAISE EXCEPTION 'SAST lifecycle transition is stale or breaks the append-only chain';
  END IF;
  SELECT "measuredAt" INTO evidence_time
  FROM public."SastRuleBundlePromotionEvidence"
  WHERE "id" = NEW."promotionEvidenceId";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST lifecycle transition promotion evidence is unavailable';
  END IF;
  IF NEW."transitionedAt" < evidence_time THEN
    RAISE EXCEPTION 'SAST lifecycle transition predates its promotion evidence';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "refresh_sast_rule_bundle_lifecycle_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  INSERT INTO public."SastRuleBundleLifecycleHead" AS lifecycle_head (
    "manifestId", "manifestDigest", "bundleId", "bundleDigest",
    "transitionId", "transitionDigest", "sequence", "lifecycleState",
    "promotionEvidenceId", "promotionEvidenceDigest", "approvalSetDigest",
    "transitionedAt", "createdAt", "updatedAt"
  ) VALUES (
    NEW."manifestId", NEW."manifestDigest", NEW."bundleId", NEW."bundleDigest",
    NEW."id", NEW."transitionDigest", NEW."sequence", NEW."toState",
    NEW."promotionEvidenceId", NEW."promotionEvidenceDigest", NEW."approvalSetDigest",
    NEW."transitionedAt", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
  )
  ON CONFLICT ("manifestId") DO UPDATE SET
    "manifestDigest" = EXCLUDED."manifestDigest",
    "bundleId" = EXCLUDED."bundleId",
    "bundleDigest" = EXCLUDED."bundleDigest",
    "transitionId" = EXCLUDED."transitionId",
    "transitionDigest" = EXCLUDED."transitionDigest",
    "sequence" = EXCLUDED."sequence",
    "lifecycleState" = EXCLUDED."lifecycleState",
    "promotionEvidenceId" = EXCLUDED."promotionEvidenceId",
    "promotionEvidenceDigest" = EXCLUDED."promotionEvidenceDigest",
    "approvalSetDigest" = EXCLUDED."approvalSetDigest",
    "transitionedAt" = EXCLUDED."transitionedAt",
    "updatedAt" = CURRENT_TIMESTAMP
  WHERE lifecycle_head."sequence" < EXCLUDED."sequence";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST lifecycle head rejected a stale transition';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "protect_sast_rule_bundle_lifecycle_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF pg_trigger_depth() < 2 THEN
    RAISE EXCEPTION 'SAST lifecycle head is a trigger-maintained projection';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_promotion_approval_time"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE evidence_time TIMESTAMP(3);
BEGIN
  SELECT "measuredAt" INTO evidence_time
  FROM public."SastRuleBundlePromotionEvidence"
  WHERE "id" = NEW."evidenceId";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST promotion approval evidence is unavailable';
  END IF;
  IF NEW."approvedAt" < evidence_time THEN
    RAISE EXCEPTION 'SAST promotion approval predates its evidence';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_transition_approval_time"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE transition_time TIMESTAMP(3);
BEGIN
  SELECT "transitionedAt" INTO transition_time
  FROM public."SastRuleBundleLifecycleTransition"
  WHERE "id" = NEW."transitionId";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST lifecycle approval transition is unavailable';
  END IF;
  IF NEW."approvedAt" > transition_time THEN
    RAISE EXCEPTION 'SAST lifecycle approval postdates its transition';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_lifecycle_approval_set"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE approval_count INTEGER; security_count INTEGER; independent_count INTEGER;
BEGIN
  SELECT count(*),
         count(*) FILTER (WHERE "role" = 'SECURITY_ENGINEERING'),
         count(*) FILTER (WHERE "role" IN ('SCAN_PLATFORM','SECURITY_OPERATIONS'))
    INTO approval_count, security_count, independent_count
  FROM public."SastRuleBundleLifecycleTransitionApproval"
  WHERE "transitionId" = NEW."id";
  IF approval_count < 1 OR approval_count > 3 OR security_count <> 1
     OR (NEW."toState" IN ('ACTIVE','RETIRED') AND independent_count < 1) THEN
    RAISE EXCEPTION 'SAST lifecycle transition approval separation is incomplete';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_lifecycle_selection"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE latest_record RECORD;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW."manifestId", 0));
  SELECT "id", "transitionDigest", "sequence", "toState", "transitionedAt"
    INTO latest_record
  FROM public."SastRuleBundleLifecycleTransition"
  WHERE "manifestId" = NEW."manifestId"
  ORDER BY "sequence" DESC LIMIT 1;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST lifecycle selection transition is unavailable';
  END IF;
  IF NEW."transitionId" <> latest_record."id"
     OR NEW."transitionDigest" <> latest_record."transitionDigest"
     OR NEW."lifecycleSequence" <> latest_record."sequence"
     OR NEW."lifecycleState" <> latest_record."toState"
     OR latest_record."toState" NOT IN ('CANARY','ACTIVE')
     OR NEW."evaluatedAt" < latest_record."transitionedAt" THEN
    RAISE EXCEPTION 'SAST lifecycle selection is stale or not selectable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_queue_rule_bundle_lifecycle_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE bundle_record JSONB; head_record RECORD;
        bundle_count INTEGER; distinct_manifest_count INTEGER;
BEGIN
  IF jsonb_typeof(NEW."immutablePlan"->'scannerSet'->'ruleBundles')
       IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'SAST queue admission requires rule-bundle lifecycle projections';
  END IF;

  SELECT count(*), count(DISTINCT value->>'manifestId')
    INTO bundle_count, distinct_manifest_count
  FROM jsonb_array_elements(
    NEW."immutablePlan"->'scannerSet'->'ruleBundles'
  );
  IF bundle_count < 1 OR bundle_count <> distinct_manifest_count THEN
    RAISE EXCEPTION 'SAST queue admission lifecycle manifests are empty or duplicated';
  END IF;

  FOR bundle_record IN
    SELECT value
    FROM jsonb_array_elements(
      NEW."immutablePlan"->'scannerSet'->'ruleBundles'
    )
    ORDER BY value->>'manifestId'
  LOOP
    IF jsonb_typeof(bundle_record->'lifecycle') IS DISTINCT FROM 'object' THEN
      RAISE EXCEPTION 'SAST queue admission lifecycle projection is malformed';
    END IF;

    SELECT * INTO head_record
    FROM public."SastRuleBundleLifecycleHead"
    WHERE "manifestId" = bundle_record->>'manifestId'
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'SAST queue admission lifecycle head is unavailable';
    END IF;

    IF head_record."manifestDigest" IS DISTINCT FROM bundle_record->>'manifestDigest'
       OR head_record."bundleId" IS DISTINCT FROM bundle_record->>'bundleId'
       OR head_record."bundleDigest" IS DISTINCT FROM bundle_record->>'digest'
       OR head_record."lifecycleState" NOT IN ('CANARY','ACTIVE')
       OR head_record."lifecycleState" IS DISTINCT FROM bundle_record->'lifecycle'->>'lifecycleState'
       OR head_record."sequence"::TEXT IS DISTINCT FROM bundle_record->'lifecycle'->>'lifecycleSequence'
       OR head_record."transitionId" IS DISTINCT FROM bundle_record->'lifecycle'->>'lifecycleTransitionId'
       OR head_record."transitionDigest" IS DISTINCT FROM bundle_record->'lifecycle'->>'lifecycleTransitionDigest'
       OR head_record."promotionEvidenceId" IS DISTINCT FROM bundle_record->'lifecycle'->>'promotionEvidenceId'
       OR head_record."promotionEvidenceDigest" IS DISTINCT FROM bundle_record->'lifecycle'->>'promotionEvidenceDigest'
       OR head_record."approvalSetDigest" IS DISTINCT FROM bundle_record->'lifecycle'->>'approvalSetDigest'
       OR NOT EXISTS (
         SELECT 1
         FROM public."SastRuleBundleLifecycleSelectionReceipt" receipt
         WHERE receipt."id" = bundle_record->'lifecycle'->>'selectionReceiptId'
           AND receipt."receiptDigest" = bundle_record->'lifecycle'->>'selectionReceiptDigest'
           AND receipt."manifestId" = head_record."manifestId"
           AND receipt."manifestDigest" = head_record."manifestDigest"
           AND receipt."bundleId" = head_record."bundleId"
           AND receipt."bundleDigest" = head_record."bundleDigest"
           AND receipt."lifecycleState" = head_record."lifecycleState"
           AND receipt."lifecycleSequence" = head_record."sequence"
           AND receipt."transitionId" = head_record."transitionId"
           AND receipt."transitionDigest" = head_record."transitionDigest"
           AND receipt."promotionEvidenceId" = head_record."promotionEvidenceId"
           AND receipt."promotionEvidenceDigest" = head_record."promotionEvidenceDigest"
           AND receipt."approvalSetDigest" = head_record."approvalSetDigest"
       ) THEN
      RAISE EXCEPTION 'SAST queue admission lifecycle projection is stale or unauthorized';
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "SastRuleBundlePromotionEvidence_binding" BEFORE INSERT ON "SastRuleBundlePromotionEvidence" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_promotion_evidence_binding"();
CREATE TRIGGER "SastRuleBundlePromotionApproval_time" BEFORE INSERT ON "SastRuleBundlePromotionApproval" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_promotion_approval_time"();
CREATE TRIGGER "SastRuleBundleLifecycleTransition_append" BEFORE INSERT ON "SastRuleBundleLifecycleTransition" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_lifecycle_append"();
CREATE TRIGGER "SastRuleBundleLifecycleHead_protect_insert" BEFORE INSERT ON "SastRuleBundleLifecycleHead" FOR EACH ROW EXECUTE FUNCTION "protect_sast_rule_bundle_lifecycle_head"();
CREATE TRIGGER "SastRuleBundleLifecycleHead_protect_update" BEFORE UPDATE ON "SastRuleBundleLifecycleHead" FOR EACH ROW EXECUTE FUNCTION "protect_sast_rule_bundle_lifecycle_head"();
CREATE TRIGGER "SastRuleBundleLifecycleHead_protect_delete" BEFORE DELETE ON "SastRuleBundleLifecycleHead" FOR EACH ROW EXECUTE FUNCTION "protect_sast_rule_bundle_lifecycle_head"();
CREATE TRIGGER "SastRuleBundleLifecycleTransition_refresh_head" AFTER INSERT ON "SastRuleBundleLifecycleTransition" FOR EACH ROW EXECUTE FUNCTION "refresh_sast_rule_bundle_lifecycle_head"();
CREATE TRIGGER "SastRuleBundleLifecycleTransitionApproval_time" BEFORE INSERT ON "SastRuleBundleLifecycleTransitionApproval" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_transition_approval_time"();
CREATE CONSTRAINT TRIGGER "SastRuleBundleLifecycleTransition_approval_set" AFTER INSERT ON "SastRuleBundleLifecycleTransition" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_lifecycle_approval_set"();
CREATE TRIGGER "SastRuleBundleLifecycleSelectionReceipt_latest" BEFORE INSERT ON "SastRuleBundleLifecycleSelectionReceipt" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_lifecycle_selection"();
CREATE TRIGGER "SastQueueReservation_lifecycle_head" BEFORE INSERT ON "SastQueueReservation" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_queue_rule_bundle_lifecycle_head"();

CREATE TRIGGER "SastRuleBundlePromotionEvidence_immutable_update" BEFORE UPDATE ON "SastRuleBundlePromotionEvidence" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundlePromotionEvidence_immutable_delete" BEFORE DELETE ON "SastRuleBundlePromotionEvidence" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundlePromotionApproval_immutable_update" BEFORE UPDATE ON "SastRuleBundlePromotionApproval" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundlePromotionApproval_immutable_delete" BEFORE DELETE ON "SastRuleBundlePromotionApproval" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleLifecycleTransition_immutable_update" BEFORE UPDATE ON "SastRuleBundleLifecycleTransition" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleLifecycleTransition_immutable_delete" BEFORE DELETE ON "SastRuleBundleLifecycleTransition" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleLifecycleTransitionApproval_immutable_update" BEFORE UPDATE ON "SastRuleBundleLifecycleTransitionApproval" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleLifecycleTransitionApproval_immutable_delete" BEFORE DELETE ON "SastRuleBundleLifecycleTransitionApproval" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleLifecycleSelectionReceipt_immutable_update" BEFORE UPDATE ON "SastRuleBundleLifecycleSelectionReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleLifecycleSelectionReceipt_immutable_delete" BEFORE DELETE ON "SastRuleBundleLifecycleSelectionReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();

COMMENT ON TABLE "SastRuleBundlePromotionEvidence" IS 'T047 quantitative, automated, content-free qualification evidence; every gate passes and no approval authority is granted.';
COMMENT ON TABLE "SastRuleBundlePromotionApproval" IS 'T047 immutable human approval bound to one evidence digest with candidate-author separation.';
COMMENT ON TABLE "SastRuleBundleLifecycleTransition" IS 'T047 append-only lifecycle hash chain; external T048/T049/T050 authorities are required at their exact seams.';
COMMENT ON TABLE "SastRuleBundleLifecycleHead" IS 'T047 trigger-maintained latest-transition projection used to fence queue admission against concurrent lifecycle changes.';
COMMENT ON TABLE "SastRuleBundleLifecycleSelectionReceipt" IS 'T047 latest CANARY/ACTIVE transition receipt issued immediately before canonical planning.';
