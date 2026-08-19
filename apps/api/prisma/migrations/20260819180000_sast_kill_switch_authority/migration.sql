CREATE TABLE "SastKillSwitchDecision" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "selectorKey" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "runtime" TEXT,
  "scanner" TEXT,
  "scannerVersion" TEXT,
  "bundleDigest" TEXT,
  "ruleSemanticId" TEXT,
  "profileId" TEXT,
  "profileDigest" TEXT,
  "tenantId" TEXT,
  "repositoryBindingId" TEXT,
  "capability" TEXT,
  "publicationTargetScope" TEXT,
  "sequence" INTEGER NOT NULL,
  "previousDecisionId" TEXT,
  "previousDecisionDigest" TEXT,
  "action" TEXT NOT NULL,
  "reasonCode" TEXT NOT NULL,
  "incidentRef" TEXT NOT NULL,
  "actorRef" TEXT NOT NULL,
  "actorRole" TEXT NOT NULL,
  "effectiveAt" TIMESTAMP(3) NOT NULL,
  "reviewBy" TIMESTAMP(3) NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "rollbackTargetRef" TEXT NOT NULL,
  "signatureRef" TEXT NOT NULL,
  "provenanceRef" TEXT NOT NULL,
  "auditRef" TEXT NOT NULL,
  "source" TEXT NOT NULL DEFAULT 'PLATFORM_MANAGED',
  "immutable" BOOLEAN NOT NULL DEFAULT TRUE,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT FALSE,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "findingContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "arbitraryPayloadStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastKillSwitchDecision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastKillSwitchDecision_contract_check" CHECK (
    "contractVersion" = 'sast-kill-switch-decision-v1'
    AND "id" ~ '^sast-kill-switch-decision://[a-f0-9]{64}$'
    AND "decisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "selectorKey" ~ '^sast-kill-switch-selector://[a-f0-9]{64}$'
    AND "scope" IN ('SCANNER_VERSION','RULE_BUNDLE','SEMANTIC_RULE','TENANT','REPOSITORY_BINDING','CAPABILITY','PROFILE','EXTERNAL_PUBLICATION','GLOBAL')
    AND "sequence" > 0
    AND (("sequence" = 1 AND "previousDecisionId" IS NULL AND "previousDecisionDigest" IS NULL)
      OR ("sequence" > 1 AND "previousDecisionId" ~ '^sast-kill-switch-decision://[a-f0-9]{64}$' AND "previousDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'))
    AND "action" IN ('ACTIVATE','DEACTIVATE')
    AND "reasonCode" IN ('SECURITY_INCIDENT','SCANNER_DEFECT','SUPPLY_CHAIN_RISK','FALSE_POSITIVE_REGRESSION','RELIABILITY_REGRESSION','PRIVACY_RISK','POLICY_EMERGENCY','OPERATOR_DRILL')
    AND "actorRole" IN ('SECURITY_ON_CALL','PLATFORM_ON_CALL')
    AND "reviewBy" > "effectiveAt"
    AND "reviewBy" <= "effectiveAt" + INTERVAL '24 hours'
    AND "expiresAt" >= "reviewBy"
    AND "expiresAt" <= "effectiveAt" + INTERVAL '30 days'
    AND "incidentRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "actorRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "rollbackTargetRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "signatureRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "provenanceRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "auditRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "incidentRef" !~ '^https?://' AND "actorRef" !~ '^https?://'
    AND "rollbackTargetRef" !~ '^https?://' AND "signatureRef" !~ '^https?://'
    AND "provenanceRef" !~ '^https?://' AND "auditRef" !~ '^https?://'
    AND "source" = 'PLATFORM_MANAGED' AND "immutable" IS TRUE
    AND "customerInputAccepted" IS FALSE
    AND "repositoryContentStored" IS FALSE
    AND "findingContentStored" IS FALSE
    AND "secretValueStored" IS FALSE
    AND "arbitraryPayloadStored" IS FALSE
    AND (
      ("scope" = 'GLOBAL' AND "runtime" = 'SAST' AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'SCANNER_VERSION' AND "runtime" IS NULL AND "scanner" IN ('OPENGREP','TRIVY','SYFT') AND length("scannerVersion") BETWEEN 1 AND 512 AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'RULE_BUNDLE' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$' AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'SEMANTIC_RULE' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND length("ruleSemanticId") BETWEEN 1 AND 512 AND "profileId" IS NULL AND "profileDigest" IS NULL AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'PROFILE' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1') AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$' AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'TENANT' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND length("tenantId") BETWEEN 1 AND 512 AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'REPOSITORY_BINDING' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND length("tenantId") BETWEEN 1 AND 512 AND length("repositoryBindingId") BETWEEN 1 AND 512 AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'CAPABILITY' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IN ('SAST','DEPENDENCY_VULNERABILITY','SECRET_DETECTION','IAC_MISCONFIGURATION','SBOM') AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'EXTERNAL_PUBLICATION' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND "capability" IS NULL AND (("publicationTargetScope" = 'GLOBAL' AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL) OR ("publicationTargetScope" = 'TENANT' AND length("tenantId") BETWEEN 1 AND 512 AND "repositoryBindingId" IS NULL) OR ("publicationTargetScope" = 'REPOSITORY_BINDING' AND length("tenantId") BETWEEN 1 AND 512 AND length("repositoryBindingId") BETWEEN 1 AND 512)))
    )
  )
);

CREATE UNIQUE INDEX "SastKillSwitchDecision_decisionDigest_key" ON "SastKillSwitchDecision"("decisionDigest");
CREATE UNIQUE INDEX "SastKillSwitchDecision_selector_sequence_key" ON "SastKillSwitchDecision"("selectorKey","sequence");
CREATE UNIQUE INDEX "SastKillSwitchDecision_id_digest_key" ON "SastKillSwitchDecision"("id","decisionDigest");
CREATE UNIQUE INDEX "SastKillSwitchDecision_identity_key" ON "SastKillSwitchDecision"("id","decisionDigest","selectorKey");
CREATE UNIQUE INDEX "SastKillSwitchDecision_binding_key" ON "SastKillSwitchDecision"("id","decisionDigest","selectorKey","sequence","action");
CREATE INDEX "SastKillSwitchDecision_scope_action_idx" ON "SastKillSwitchDecision"("scope","action","effectiveAt");
CREATE INDEX "SastKillSwitchDecision_tenant_repository_idx" ON "SastKillSwitchDecision"("tenantId","repositoryBindingId","scope");

CREATE TABLE "SastKillSwitchVerification" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "verificationDigest" TEXT NOT NULL,
  "decisionId" TEXT NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "selectorKey" TEXT NOT NULL,
  "signerIdentity" TEXT NOT NULL,
  "signatureRef" TEXT NOT NULL,
  "provenanceRef" TEXT NOT NULL,
  "signatureVerified" BOOLEAN NOT NULL DEFAULT TRUE,
  "provenanceVerified" BOOLEAN NOT NULL DEFAULT TRUE,
  "trustedSigner" BOOLEAN NOT NULL DEFAULT TRUE,
  "signatureBytesStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "provenancePayloadStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "verifiedAt" TIMESTAMP(3) NOT NULL,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastKillSwitchVerification_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastKillSwitchVerification_contract_check" CHECK (
    "contractVersion" = 'sast-kill-switch-verification-v1'
    AND "id" ~ '^sast-kill-switch-verification://[a-f0-9]{64}$'
    AND "verificationDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "decisionId" ~ '^sast-kill-switch-decision://[a-f0-9]{64}$'
    AND "decisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "selectorKey" ~ '^sast-kill-switch-selector://[a-f0-9]{64}$'
    AND length("signerIdentity") BETWEEN 1 AND 512
    AND "signatureRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "provenanceRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "signatureRef" !~ '^https?://' AND "provenanceRef" !~ '^https?://'
    AND "signatureVerified" IS TRUE AND "provenanceVerified" IS TRUE AND "trustedSigner" IS TRUE
    AND "signatureBytesStored" IS FALSE AND "provenancePayloadStored" IS FALSE
    AND "repositoryContentStored" IS FALSE AND "secretValueStored" IS FALSE
  )
);
CREATE UNIQUE INDEX "SastKillSwitchVerification_verificationDigest_key" ON "SastKillSwitchVerification"("verificationDigest");
CREATE UNIQUE INDEX "SastKillSwitchVerification_decisionId_key" ON "SastKillSwitchVerification"("decisionId");
CREATE UNIQUE INDEX "SastKillSwitchVerification_binding_key" ON "SastKillSwitchVerification"("id","verificationDigest","decisionId","decisionDigest");
CREATE INDEX "SastKillSwitchVerification_signer_idx" ON "SastKillSwitchVerification"("signerIdentity","verifiedAt");

CREATE TABLE "SastKillSwitchHead" (
  "selectorKey" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "runtime" TEXT,
  "scanner" TEXT,
  "scannerVersion" TEXT,
  "bundleDigest" TEXT,
  "ruleSemanticId" TEXT,
  "profileId" TEXT,
  "profileDigest" TEXT,
  "tenantId" TEXT,
  "repositoryBindingId" TEXT,
  "capability" TEXT,
  "publicationTargetScope" TEXT,
  "sequence" INTEGER NOT NULL DEFAULT 0,
  "currentDecisionId" TEXT,
  "currentDecisionDigest" TEXT,
  "currentAction" TEXT,
  "active" BOOLEAN NOT NULL DEFAULT FALSE,
  "effectiveAt" TIMESTAMP(3),
  "reviewBy" TIMESTAMP(3),
  "expiresAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastKillSwitchHead_pkey" PRIMARY KEY ("selectorKey"),
  CONSTRAINT "SastKillSwitchHead_contract_check" CHECK (
    "selectorKey" ~ '^sast-kill-switch-selector://[a-f0-9]{64}$'
    AND "scope" IN ('SCANNER_VERSION','RULE_BUNDLE','SEMANTIC_RULE','TENANT','REPOSITORY_BINDING','CAPABILITY','PROFILE','EXTERNAL_PUBLICATION','GLOBAL')
    AND "sequence" >= 0
    AND (("sequence" = 0 AND "currentDecisionId" IS NULL AND "currentDecisionDigest" IS NULL AND "currentAction" IS NULL AND "active" IS FALSE AND "effectiveAt" IS NULL AND "reviewBy" IS NULL AND "expiresAt" IS NULL)
      OR ("sequence" > 0 AND "currentDecisionId" ~ '^sast-kill-switch-decision://[a-f0-9]{64}$' AND "currentDecisionDigest" ~ '^sha256:[a-f0-9]{64}$' AND "currentAction" IN ('ACTIVATE','DEACTIVATE') AND "active" = ("currentAction" = 'ACTIVATE') AND "effectiveAt" IS NOT NULL AND "reviewBy" IS NOT NULL AND "expiresAt" IS NOT NULL))
    AND (
      ("scope" = 'GLOBAL' AND "runtime" = 'SAST' AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'SCANNER_VERSION' AND "runtime" IS NULL AND "scanner" IN ('OPENGREP','TRIVY','SYFT') AND length("scannerVersion") BETWEEN 1 AND 512 AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'RULE_BUNDLE' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$' AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'SEMANTIC_RULE' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND length("ruleSemanticId") BETWEEN 1 AND 512 AND "profileId" IS NULL AND "profileDigest" IS NULL AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'PROFILE' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1') AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$' AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'TENANT' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND length("tenantId") BETWEEN 1 AND 512 AND "repositoryBindingId" IS NULL AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'REPOSITORY_BINDING' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND length("tenantId") BETWEEN 1 AND 512 AND length("repositoryBindingId") BETWEEN 1 AND 512 AND "capability" IS NULL AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'CAPABILITY' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL AND "capability" IN ('SAST','DEPENDENCY_VULNERABILITY','SECRET_DETECTION','IAC_MISCONFIGURATION','SBOM') AND "publicationTargetScope" IS NULL)
      OR ("scope" = 'EXTERNAL_PUBLICATION' AND "runtime" IS NULL AND "scanner" IS NULL AND "scannerVersion" IS NULL AND "bundleDigest" IS NULL AND "ruleSemanticId" IS NULL AND "profileId" IS NULL AND "profileDigest" IS NULL AND "capability" IS NULL AND (("publicationTargetScope" = 'GLOBAL' AND "tenantId" IS NULL AND "repositoryBindingId" IS NULL) OR ("publicationTargetScope" = 'TENANT' AND length("tenantId") BETWEEN 1 AND 512 AND "repositoryBindingId" IS NULL) OR ("publicationTargetScope" = 'REPOSITORY_BINDING' AND length("tenantId") BETWEEN 1 AND 512 AND length("repositoryBindingId") BETWEEN 1 AND 512)))
    )
  )
);
CREATE UNIQUE INDEX "SastKillSwitchHead_currentDecisionId_key" ON "SastKillSwitchHead"("currentDecisionId");
CREATE UNIQUE INDEX "SastKillSwitchHead_currentDecisionDigest_key" ON "SastKillSwitchHead"("currentDecisionDigest");
CREATE UNIQUE INDEX "SastKillSwitchHead_binding_key" ON "SastKillSwitchHead"("selectorKey","sequence","currentDecisionId","currentDecisionDigest","currentAction","active");
CREATE INDEX "SastKillSwitchHead_active_scope_idx" ON "SastKillSwitchHead"("scope","active","updatedAt");
CREATE INDEX "SastKillSwitchHead_tenant_repository_idx" ON "SastKillSwitchHead"("tenantId","repositoryBindingId","active");

CREATE TABLE "SastKillSwitchEvaluation" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "receiptDigest" TEXT NOT NULL,
  "gate" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scanRequestId" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "scannerSetDigest" TEXT NOT NULL,
  "contextDigest" TEXT NOT NULL,
  "snapshotDigest" TEXT NOT NULL,
  "headCount" INTEGER NOT NULL,
  "headSetDigest" TEXT NOT NULL,
  "matchedDecisionCount" INTEGER NOT NULL,
  "matchedDecisionSetDigest" TEXT NOT NULL,
  "outcome" TEXT NOT NULL,
  "coverageEffect" TEXT NOT NULL,
  "evaluatedAt" TIMESTAMP(3) NOT NULL,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT FALSE,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "findingContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "arbitraryPayloadStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastKillSwitchEvaluation_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastKillSwitchEvaluation_contract_check" CHECK (
    "contractVersion" = 'sast-kill-switch-evaluation-v1'
    AND "id" ~ '^sast-kill-switch-evaluation://[a-f0-9]{64}$'
    AND "receiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "gate" IN ('PLANNING','QUEUE_ADMISSION','SCANNER_START','ARTIFACT_ACCEPTANCE','RETRY_ADMISSION','COVERAGE','EXTERNAL_PUBLICATION','AI_ADVISORY')
    AND length("tenantId") BETWEEN 1 AND 512 AND length("repositoryBindingId") BETWEEN 1 AND 512 AND length("scanRequestId") BETWEEN 1 AND 512
    AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1')
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$' AND "scannerSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "contextDigest" ~ '^sha256:[a-f0-9]{64}$' AND "snapshotDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "headCount" > 0 AND "headSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "matchedDecisionCount" BETWEEN 0 AND "headCount"
    AND "matchedDecisionSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "outcome" IN ('CLEAR','ACTIVE') AND "coverageEffect" IN ('UNCHANGED','PARTIAL','FAILED')
    AND (("outcome" = 'CLEAR' AND "matchedDecisionCount" = 0 AND "coverageEffect" = 'UNCHANGED') OR ("outcome" = 'ACTIVE' AND "matchedDecisionCount" > 0))
    AND "customerInputAccepted" IS FALSE AND "repositoryContentStored" IS FALSE AND "findingContentStored" IS FALSE AND "secretValueStored" IS FALSE AND "arbitraryPayloadStored" IS FALSE
  )
);
CREATE UNIQUE INDEX "SastKillSwitchEvaluation_receiptDigest_key" ON "SastKillSwitchEvaluation"("receiptDigest");
CREATE UNIQUE INDEX "SastKillSwitchEvaluation_binding_key" ON "SastKillSwitchEvaluation"("id","receiptDigest","contextDigest","snapshotDigest");
CREATE INDEX "SastKillSwitchEvaluation_scan_gate_idx" ON "SastKillSwitchEvaluation"("scanRequestId","gate","evaluatedAt");
CREATE INDEX "SastKillSwitchEvaluation_scope_outcome_idx" ON "SastKillSwitchEvaluation"("tenantId","repositoryBindingId","outcome","evaluatedAt");

CREATE TABLE "SastKillSwitchEvaluationHead" (
  "evaluationId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "selectorKey" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "sequence" INTEGER NOT NULL,
  "decisionId" TEXT,
  "decisionDigest" TEXT,
  "action" TEXT,
  "active" BOOLEAN NOT NULL,
  "effectiveAt" TIMESTAMP(3),
  "expiresAt" TIMESTAMP(3),
  "bindingDigest" TEXT NOT NULL,
  CONSTRAINT "SastKillSwitchEvaluationHead_pkey" PRIMARY KEY ("evaluationId","position"),
  CONSTRAINT "SastKillSwitchEvaluationHead_contract_check" CHECK (
    "position" >= 0 AND "selectorKey" ~ '^sast-kill-switch-selector://[a-f0-9]{64}$'
    AND "scope" IN ('SCANNER_VERSION','RULE_BUNDLE','SEMANTIC_RULE','TENANT','REPOSITORY_BINDING','CAPABILITY','PROFILE','EXTERNAL_PUBLICATION','GLOBAL')
    AND "sequence" >= 0 AND "bindingDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND (("sequence" = 0 AND "decisionId" IS NULL AND "decisionDigest" IS NULL AND "action" IS NULL AND "active" IS FALSE AND "effectiveAt" IS NULL AND "expiresAt" IS NULL)
      OR ("sequence" > 0 AND "decisionId" ~ '^sast-kill-switch-decision://[a-f0-9]{64}$' AND "decisionDigest" ~ '^sha256:[a-f0-9]{64}$' AND "action" IN ('ACTIVATE','DEACTIVATE') AND "active" = ("action" = 'ACTIVATE') AND "effectiveAt" IS NOT NULL AND "expiresAt" IS NOT NULL))
  )
);
CREATE UNIQUE INDEX "SastKillSwitchEvaluationHead_selector_key" ON "SastKillSwitchEvaluationHead"("evaluationId","selectorKey");
CREATE UNIQUE INDEX "SastKillSwitchEvaluationHead_digest_key" ON "SastKillSwitchEvaluationHead"("evaluationId","bindingDigest");
CREATE INDEX "SastKillSwitchEvaluationHead_head_idx" ON "SastKillSwitchEvaluationHead"("selectorKey","sequence");

CREATE TABLE "SastKillSwitchEvaluationMatch" (
  "evaluationId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "selectorKey" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "decisionId" TEXT NOT NULL,
  "decisionDigest" TEXT NOT NULL,
  "bindingDigest" TEXT NOT NULL,
  CONSTRAINT "SastKillSwitchEvaluationMatch_pkey" PRIMARY KEY ("evaluationId","position"),
  CONSTRAINT "SastKillSwitchEvaluationMatch_contract_check" CHECK (
    "position" >= 0 AND "selectorKey" ~ '^sast-kill-switch-selector://[a-f0-9]{64}$'
    AND "scope" IN ('SCANNER_VERSION','RULE_BUNDLE','SEMANTIC_RULE','TENANT','REPOSITORY_BINDING','CAPABILITY','PROFILE','EXTERNAL_PUBLICATION','GLOBAL')
    AND "decisionId" ~ '^sast-kill-switch-decision://[a-f0-9]{64}$'
    AND "decisionDigest" ~ '^sha256:[a-f0-9]{64}$' AND "bindingDigest" ~ '^sha256:[a-f0-9]{64}$'
  )
);
CREATE UNIQUE INDEX "SastKillSwitchEvaluationMatch_selector_key" ON "SastKillSwitchEvaluationMatch"("evaluationId","selectorKey");
CREATE UNIQUE INDEX "SastKillSwitchEvaluationMatch_decision_key" ON "SastKillSwitchEvaluationMatch"("evaluationId","decisionId");
CREATE INDEX "SastKillSwitchEvaluationMatch_decision_idx" ON "SastKillSwitchEvaluationMatch"("decisionId","decisionDigest");

CREATE TABLE "SastKillSwitchEmergencySuspensionReceipt" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "receiptDigest" TEXT NOT NULL,
  "manifestId" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "bundleId" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "fromState" TEXT NOT NULL,
  "toState" TEXT NOT NULL,
  "lifecycleSequence" INTEGER NOT NULL,
  "lifecycleTransitionId" TEXT NOT NULL,
  "lifecycleTransitionDigest" TEXT NOT NULL,
  "promotionEvidenceId" TEXT NOT NULL,
  "promotionEvidenceDigest" TEXT NOT NULL,
  "triggerSelectorKey" TEXT NOT NULL,
  "triggerDecisionId" TEXT NOT NULL,
  "triggerDecisionDigest" TEXT NOT NULL,
  "activeDecisionCount" INTEGER NOT NULL,
  "activeDecisionSetDigest" TEXT NOT NULL,
  "requestedAt" TIMESTAMP(3) NOT NULL,
  "verifiedAt" TIMESTAMP(3) NOT NULL,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT FALSE,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "findingContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastKillSwitchEmergencySuspensionReceipt_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastKillSwitchEmergencySuspensionReceipt_contract_check" CHECK (
    "contractVersion" = 'sast-kill-switch-emergency-suspension-v1'
    AND "id" ~ '^sast-kill-switch-suspension://authority/sha256:[a-f0-9]{64}$'
    AND "receiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND length("manifestId") BETWEEN 1 AND 512 AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND length("bundleId") BETWEEN 1 AND 512 AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "fromState" IN ('CANARY','ACTIVE') AND "toState" = 'SUSPENDED'
    AND "lifecycleSequence" > 0 AND length("lifecycleTransitionId") BETWEEN 1 AND 512 AND "lifecycleTransitionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND length("promotionEvidenceId") BETWEEN 1 AND 512 AND "promotionEvidenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "triggerSelectorKey" ~ '^sast-kill-switch-selector://[a-f0-9]{64}$'
    AND "triggerDecisionId" ~ '^sast-kill-switch-decision://[a-f0-9]{64}$' AND "triggerDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "activeDecisionCount" > 0 AND "activeDecisionSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "verifiedAt" = "requestedAt"
    AND "customerInputAccepted" IS FALSE AND "repositoryContentStored" IS FALSE AND "findingContentStored" IS FALSE AND "secretValueStored" IS FALSE
  )
);
CREATE UNIQUE INDEX "SastKillSwitchEmergencySuspensionReceipt_receiptDigest_key" ON "SastKillSwitchEmergencySuspensionReceipt"("receiptDigest");
CREATE UNIQUE INDEX "SastKillSwitchEmergencySuspensionReceipt_binding_key" ON "SastKillSwitchEmergencySuspensionReceipt"("id","receiptDigest","manifestId","bundleDigest");
CREATE INDEX "SastKillSwitchEmergencySuspensionReceipt_lifecycle_idx" ON "SastKillSwitchEmergencySuspensionReceipt"("manifestId","lifecycleSequence","verifiedAt");
CREATE INDEX "SastKillSwitchEmergencySuspensionReceipt_decision_idx" ON "SastKillSwitchEmergencySuspensionReceipt"("triggerDecisionId","triggerDecisionDigest");

ALTER TABLE "SastKillSwitchDecision" ADD CONSTRAINT "SastKillSwitchDecision_previous_fkey" FOREIGN KEY ("previousDecisionId","previousDecisionDigest") REFERENCES "SastKillSwitchDecision"("id","decisionDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchVerification" ADD CONSTRAINT "SastKillSwitchVerification_decision_fkey" FOREIGN KEY ("decisionId","decisionDigest","selectorKey") REFERENCES "SastKillSwitchDecision"("id","decisionDigest","selectorKey") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchHead" ADD CONSTRAINT "SastKillSwitchHead_current_fkey" FOREIGN KEY ("currentDecisionId","currentDecisionDigest","selectorKey","sequence","currentAction") REFERENCES "SastKillSwitchDecision"("id","decisionDigest","selectorKey","sequence","action") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchEvaluation" ADD CONSTRAINT "SastKillSwitchEvaluation_scan_fkey" FOREIGN KEY ("scanRequestId","tenantId","repositoryBindingId") REFERENCES "ScanRequest"("id","tenantId","repositoryBindingId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchEvaluationHead" ADD CONSTRAINT "SastKillSwitchEvaluationHead_evaluation_fkey" FOREIGN KEY ("evaluationId") REFERENCES "SastKillSwitchEvaluation"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchEvaluationHead" ADD CONSTRAINT "SastKillSwitchEvaluationHead_selector_fkey" FOREIGN KEY ("selectorKey") REFERENCES "SastKillSwitchHead"("selectorKey") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchEvaluationHead" ADD CONSTRAINT "SastKillSwitchEvaluationHead_decision_fkey" FOREIGN KEY ("decisionId","decisionDigest","selectorKey","sequence","action") REFERENCES "SastKillSwitchDecision"("id","decisionDigest","selectorKey","sequence","action") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchEvaluationMatch" ADD CONSTRAINT "SastKillSwitchEvaluationMatch_evaluation_fkey" FOREIGN KEY ("evaluationId") REFERENCES "SastKillSwitchEvaluation"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchEvaluationMatch" ADD CONSTRAINT "SastKillSwitchEvaluationMatch_decision_fkey" FOREIGN KEY ("decisionId","decisionDigest","selectorKey") REFERENCES "SastKillSwitchDecision"("id","decisionDigest","selectorKey") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchEmergencySuspensionReceipt" ADD CONSTRAINT "SastKillSwitchEmergencySuspensionReceipt_manifest_fkey" FOREIGN KEY ("manifestId","manifestDigest","bundleId","bundleDigest") REFERENCES "SastRuleBundleManifest"("id","manifestDigest","bundleId","bundleDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchEmergencySuspensionReceipt" ADD CONSTRAINT "SastKillSwitchEmergencySuspensionReceipt_lifecycle_fkey" FOREIGN KEY ("lifecycleTransitionId","lifecycleTransitionDigest") REFERENCES "SastRuleBundleLifecycleTransition"("id","transitionDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastKillSwitchEmergencySuspensionReceipt" ADD CONSTRAINT "SastKillSwitchEmergencySuspensionReceipt_decision_fkey" FOREIGN KEY ("triggerDecisionId","triggerDecisionDigest","triggerSelectorKey") REFERENCES "SastKillSwitchDecision"("id","decisionDigest","selectorKey") ON DELETE RESTRICT ON UPDATE RESTRICT;

CREATE FUNCTION "reject_sast_kill_switch_ledger_mutation"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'SAST kill-switch ledgers are append-only';
END;
$$;

CREATE FUNCTION "protect_sast_kill_switch_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF current_setting('aegis.kill_switch_head_writer', TRUE) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'SAST kill-switch head is a protected projection';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_kill_switch_decision_append"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE head_record RECORD;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW."selectorKey", 0));
  PERFORM set_config('aegis.kill_switch_head_writer', 'on', TRUE);
  INSERT INTO public."SastKillSwitchHead" (
    "selectorKey","scope","runtime","scanner","scannerVersion","bundleDigest","ruleSemanticId","profileId","profileDigest","tenantId","repositoryBindingId","capability","publicationTargetScope","sequence","active","createdAt","updatedAt"
  ) VALUES (
    NEW."selectorKey",NEW."scope",NEW."runtime",NEW."scanner",NEW."scannerVersion",NEW."bundleDigest",NEW."ruleSemanticId",NEW."profileId",NEW."profileDigest",NEW."tenantId",NEW."repositoryBindingId",NEW."capability",NEW."publicationTargetScope",0,FALSE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
  ) ON CONFLICT ("selectorKey") DO NOTHING;
  SELECT * INTO head_record FROM public."SastKillSwitchHead" WHERE "selectorKey" = NEW."selectorKey" FOR UPDATE;
  IF NOT FOUND
     OR head_record."scope" IS DISTINCT FROM NEW."scope"
     OR head_record."runtime" IS DISTINCT FROM NEW."runtime"
     OR head_record."scanner" IS DISTINCT FROM NEW."scanner"
     OR head_record."scannerVersion" IS DISTINCT FROM NEW."scannerVersion"
     OR head_record."bundleDigest" IS DISTINCT FROM NEW."bundleDigest"
     OR head_record."ruleSemanticId" IS DISTINCT FROM NEW."ruleSemanticId"
     OR head_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR head_record."profileDigest" IS DISTINCT FROM NEW."profileDigest"
     OR head_record."tenantId" IS DISTINCT FROM NEW."tenantId"
     OR head_record."repositoryBindingId" IS DISTINCT FROM NEW."repositoryBindingId"
     OR head_record."capability" IS DISTINCT FROM NEW."capability"
     OR head_record."publicationTargetScope" IS DISTINCT FROM NEW."publicationTargetScope" THEN
    RAISE EXCEPTION 'SAST kill-switch selector identity conflicts with its durable head';
  END IF;
  IF NEW."sequence" <> head_record."sequence" + 1
     OR (NEW."sequence" = 1 AND (NEW."previousDecisionId" IS NOT NULL OR NEW."previousDecisionDigest" IS NOT NULL))
     OR (NEW."sequence" > 1 AND (NEW."previousDecisionId" IS DISTINCT FROM head_record."currentDecisionId" OR NEW."previousDecisionDigest" IS DISTINCT FROM head_record."currentDecisionDigest")) THEN
    RAISE EXCEPTION 'SAST kill-switch decision is stale or forks its selector chain';
  END IF;
  IF NEW."action" = 'DEACTIVATE' AND head_record."active" IS NOT TRUE THEN
    RAISE EXCEPTION 'SAST kill-switch deactivation requires one active current head';
  END IF;
  IF NEW."effectiveAt" > CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'SAST kill-switch decision cannot become effective in the future';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "refresh_sast_kill_switch_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  PERFORM set_config('aegis.kill_switch_head_writer', 'on', TRUE);
  UPDATE public."SastKillSwitchHead" SET
    "sequence" = NEW."sequence",
    "currentDecisionId" = NEW."id",
    "currentDecisionDigest" = NEW."decisionDigest",
    "currentAction" = NEW."action",
    "active" = (NEW."action" = 'ACTIVATE'),
    "effectiveAt" = NEW."effectiveAt",
    "reviewBy" = NEW."reviewBy",
    "expiresAt" = NEW."expiresAt",
    "updatedAt" = CURRENT_TIMESTAMP
  WHERE "selectorKey" = NEW."selectorKey" AND "sequence" = NEW."sequence" - 1;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST kill-switch head rejected a stale decision';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_kill_switch_verification"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public."SastKillSwitchVerification" verification
    WHERE verification."decisionId" = NEW."id"
      AND verification."decisionDigest" = NEW."decisionDigest"
      AND verification."selectorKey" = NEW."selectorKey"
      AND verification."signatureRef" = NEW."signatureRef"
      AND verification."provenanceRef" = NEW."provenanceRef"
      AND verification."verifiedAt" >= NEW."effectiveAt"
      AND verification."signatureVerified" IS TRUE
      AND verification."provenanceVerified" IS TRUE
      AND verification."trustedSigner" IS TRUE
  ) THEN
    RAISE EXCEPTION 'SAST kill-switch decision lacks exact trusted signature verification';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_kill_switch_evaluation_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE current_head RECORD; evaluation_time TIMESTAMP(3);
BEGIN
  SELECT "evaluatedAt" INTO evaluation_time FROM public."SastKillSwitchEvaluation" WHERE "id" = NEW."evaluationId";
  IF NOT FOUND THEN RAISE EXCEPTION 'SAST kill-switch evaluation is unavailable'; END IF;
  SELECT * INTO current_head FROM public."SastKillSwitchHead" WHERE "selectorKey" = NEW."selectorKey" FOR UPDATE;
  IF NOT FOUND
     OR current_head."scope" IS DISTINCT FROM NEW."scope"
     OR current_head."sequence" IS DISTINCT FROM NEW."sequence"
     OR current_head."currentDecisionId" IS DISTINCT FROM NEW."decisionId"
     OR current_head."currentDecisionDigest" IS DISTINCT FROM NEW."decisionDigest"
     OR current_head."currentAction" IS DISTINCT FROM NEW."action"
     OR current_head."active" IS DISTINCT FROM NEW."active"
     OR current_head."effectiveAt" IS DISTINCT FROM NEW."effectiveAt"
     OR current_head."expiresAt" IS DISTINCT FROM NEW."expiresAt" THEN
    RAISE EXCEPTION 'SAST kill-switch evaluation head is stale';
  END IF;
  IF NEW."active" IS TRUE AND NEW."expiresAt" <= evaluation_time THEN
    RAISE EXCEPTION 'SAST kill-switch active authority expired without explicit deactivation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_kill_switch_evaluation_match"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public."SastKillSwitchEvaluationHead" head
    WHERE head."evaluationId" = NEW."evaluationId"
      AND head."selectorKey" = NEW."selectorKey"
      AND head."scope" = NEW."scope"
      AND head."decisionId" = NEW."decisionId"
      AND head."decisionDigest" = NEW."decisionDigest"
      AND head."active" IS TRUE
  ) THEN
    RAISE EXCEPTION 'SAST kill-switch match does not bind one active evaluation head';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_kill_switch_evaluation_complete"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE head_count INTEGER; match_count INTEGER; active_count INTEGER;
BEGIN
  SELECT count(*), count(*) FILTER (WHERE "active" IS TRUE) INTO head_count, active_count
  FROM public."SastKillSwitchEvaluationHead" WHERE "evaluationId" = NEW."id";
  SELECT count(*) INTO match_count FROM public."SastKillSwitchEvaluationMatch" WHERE "evaluationId" = NEW."id";
  IF head_count <> NEW."headCount" OR match_count <> NEW."matchedDecisionCount" OR active_count <> match_count
     OR (NEW."outcome" = 'CLEAR' AND active_count <> 0)
     OR (NEW."outcome" = 'ACTIVE' AND active_count = 0) THEN
    RAISE EXCEPTION 'SAST kill-switch evaluation child set is incomplete or inconsistent';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_kill_switch_suspension_receipt"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE lifecycle_head RECORD; switch_head RECORD; manifest_record RECORD; applicable_head RECORD; lifecycle_found BOOLEAN; switch_found BOOLEAN; actual_active_count INTEGER;
BEGIN
  SELECT * INTO lifecycle_head FROM public."SastRuleBundleLifecycleHead" WHERE "manifestId" = NEW."manifestId" FOR UPDATE;
  lifecycle_found := FOUND;
  SELECT * INTO switch_head FROM public."SastKillSwitchHead" WHERE "selectorKey" = NEW."triggerSelectorKey" FOR UPDATE;
  switch_found := FOUND;
  SELECT "scanner" INTO manifest_record FROM public."SastRuleBundleManifest" WHERE "id" = NEW."manifestId";
  IF lifecycle_found IS NOT TRUE
     OR switch_found IS NOT TRUE
     OR lifecycle_head."manifestDigest" IS DISTINCT FROM NEW."manifestDigest"
     OR lifecycle_head."bundleId" IS DISTINCT FROM NEW."bundleId"
     OR lifecycle_head."bundleDigest" IS DISTINCT FROM NEW."bundleDigest"
     OR lifecycle_head."lifecycleState" IS DISTINCT FROM NEW."fromState"
     OR lifecycle_head."sequence" IS DISTINCT FROM NEW."lifecycleSequence"
     OR lifecycle_head."transitionId" IS DISTINCT FROM NEW."lifecycleTransitionId"
     OR lifecycle_head."transitionDigest" IS DISTINCT FROM NEW."lifecycleTransitionDigest"
     OR lifecycle_head."promotionEvidenceId" IS DISTINCT FROM NEW."promotionEvidenceId"
     OR lifecycle_head."promotionEvidenceDigest" IS DISTINCT FROM NEW."promotionEvidenceDigest"
     OR switch_head."currentDecisionId" IS DISTINCT FROM NEW."triggerDecisionId"
     OR switch_head."currentDecisionDigest" IS DISTINCT FROM NEW."triggerDecisionDigest"
     OR switch_head."active" IS NOT TRUE
     OR switch_head."effectiveAt" > NEW."verifiedAt"
     OR switch_head."expiresAt" <= NEW."verifiedAt" THEN
    RAISE EXCEPTION 'SAST emergency suspension receipt is stale or lacks active authority';
  END IF;
  IF NOT (
    (switch_head."scope" = 'GLOBAL' AND switch_head."runtime" = 'SAST')
    OR (switch_head."scope" = 'RULE_BUNDLE' AND switch_head."bundleDigest" = NEW."bundleDigest")
    OR (switch_head."scope" = 'SCANNER_VERSION' AND switch_head."scanner" = manifest_record."scanner" AND EXISTS (
      SELECT 1 FROM public."SastRuleBundleCompatibilityEntry" entry
      WHERE entry."manifestId" = NEW."manifestId" AND entry."kind" = 'SCANNER_VERSION' AND entry."value" = switch_head."scannerVersion"
    ))
    OR (switch_head."scope" = 'SEMANTIC_RULE' AND EXISTS (
      SELECT 1 FROM public."SastRuleBundleManifestRule" rule
      WHERE rule."manifestId" = NEW."manifestId" AND rule."ruleSemanticId" = switch_head."ruleSemanticId"
    ))
    OR (switch_head."scope" = 'PROFILE' AND EXISTS (
      SELECT 1 FROM public."SastRuleBundleCompatibilityEntry" entry
      WHERE entry."manifestId" = NEW."manifestId" AND entry."kind" = 'PROFILE_ID' AND entry."value" = switch_head."profileId"
    ) AND switch_head."profileDigest" = CASE switch_head."profileId"
      WHEN 'JAVA_FAST_V1' THEN 'sha256:19743211685c76ac7c63cb8c829823c45bf458da3aee5dac4f5eaba2b44bbe74'
      WHEN 'JAVA_DEEP_V1' THEN 'sha256:df79726b0d32cf7b1c5987f73a3b1f510b29ba57c67567083c94ad77f7a4b321'
      WHEN 'COMMON_DEEP_V1' THEN 'sha256:2751b8dcd7b4ca7a44fba24a940800c557a03279efc47ba6cf67d6c1151cc8e9'
      ELSE NULL
    END)
  ) THEN
    RAISE EXCEPTION 'SAST emergency suspension selector does not apply to the lifecycle bundle';
  END IF;
  actual_active_count := 0;
  FOR applicable_head IN
    SELECT head.* FROM public."SastKillSwitchHead" head
    WHERE (
      (head."scope" = 'GLOBAL' AND head."runtime" = 'SAST')
      OR (head."scope" = 'RULE_BUNDLE' AND head."bundleDigest" = NEW."bundleDigest")
      OR (head."scope" = 'SCANNER_VERSION' AND head."scanner" = manifest_record."scanner" AND EXISTS (
        SELECT 1 FROM public."SastRuleBundleCompatibilityEntry" entry
        WHERE entry."manifestId" = NEW."manifestId" AND entry."kind" = 'SCANNER_VERSION' AND entry."value" = head."scannerVersion"
      ))
      OR (head."scope" = 'SEMANTIC_RULE' AND EXISTS (
        SELECT 1 FROM public."SastRuleBundleManifestRule" rule
        WHERE rule."manifestId" = NEW."manifestId" AND rule."ruleSemanticId" = head."ruleSemanticId"
      ))
      OR (head."scope" = 'PROFILE' AND EXISTS (
        SELECT 1 FROM public."SastRuleBundleCompatibilityEntry" entry
        WHERE entry."manifestId" = NEW."manifestId" AND entry."kind" = 'PROFILE_ID' AND entry."value" = head."profileId"
      ) AND head."profileDigest" = CASE head."profileId"
        WHEN 'JAVA_FAST_V1' THEN 'sha256:19743211685c76ac7c63cb8c829823c45bf458da3aee5dac4f5eaba2b44bbe74'
        WHEN 'JAVA_DEEP_V1' THEN 'sha256:df79726b0d32cf7b1c5987f73a3b1f510b29ba57c67567083c94ad77f7a4b321'
        WHEN 'COMMON_DEEP_V1' THEN 'sha256:2751b8dcd7b4ca7a44fba24a940800c557a03279efc47ba6cf67d6c1151cc8e9'
        ELSE NULL
      END)
    )
    ORDER BY head."selectorKey"
    FOR UPDATE
  LOOP
    IF applicable_head."active" IS TRUE
       AND applicable_head."effectiveAt" <= NEW."verifiedAt"
       AND applicable_head."expiresAt" > NEW."verifiedAt" THEN
      actual_active_count := actual_active_count + 1;
    END IF;
  END LOOP;
  IF actual_active_count <> NEW."activeDecisionCount" THEN
    RAISE EXCEPTION 'SAST emergency suspension active decision set is incomplete';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_queue_kill_switch_head"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  projection JSONB;
  evaluation_record RECORD;
  binding_record RECORD;
  current_head RECORD;
  actual_count INTEGER;
  expected_count INTEGER;
  scanner_count INTEGER;
  bundle_count INTEGER;
  semantic_rule_count INTEGER;
  capability_count INTEGER;
BEGIN
  projection := NEW."immutablePlan"->'killSwitchEvaluation';
  IF jsonb_typeof(projection) IS DISTINCT FROM 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(projection)) <> 8
     OR projection->>'version' IS DISTINCT FROM 'sast-kill-switch-planning-v1'
     OR projection->>'outcome' IS DISTINCT FROM 'CLEAR' THEN
    RAISE EXCEPTION 'SAST queue admission requires one clear T049 kill-switch projection';
  END IF;
  SELECT * INTO evaluation_record FROM public."SastKillSwitchEvaluation"
  WHERE "id" = projection->>'evaluationId'
    AND "receiptDigest" = projection->>'evaluationReceiptDigest'
    AND "contextDigest" = projection->>'contextDigest'
    AND "snapshotDigest" = projection->>'snapshotDigest'
    AND "headSetDigest" = projection->>'headSetDigest'
    AND "evaluatedAt" = (projection->>'evaluatedAt')::TIMESTAMP(3)
    AND "gate" = 'PLANNING' AND "outcome" = 'CLEAR'
    AND "tenantId" = NEW."tenantId" AND "repositoryBindingId" = NEW."repositoryBindingId" AND "scanRequestId" = NEW."scanRequestId"
    AND "profileId" = NEW."immutablePlan"->'profile'->>'id'
    AND "profileDigest" = NEW."immutablePlan"->>'profileDigest'
    AND "scannerSetDigest" = NEW."immutablePlan"->'scannerSet'->>'scannerSetDigest';
  IF NOT FOUND THEN RAISE EXCEPTION 'SAST queue admission kill-switch receipt is unavailable or mismatched'; END IF;

  IF jsonb_typeof(NEW."immutablePlan"->'profile') IS DISTINCT FROM 'object'
     OR jsonb_typeof(NEW."immutablePlan"->'profile'->'requiredCapabilities') IS DISTINCT FROM 'array'
     OR jsonb_typeof(NEW."immutablePlan"->'scannerSet') IS DISTINCT FROM 'object'
     OR jsonb_typeof(NEW."immutablePlan"->'scannerSet'->'scanners') IS DISTINCT FROM 'object'
     OR jsonb_typeof(NEW."immutablePlan"->'scannerSet'->'ruleBundles') IS DISTINCT FROM 'array'
     OR EXISTS (
       SELECT 1
       FROM jsonb_array_elements(NEW."immutablePlan"->'scannerSet'->'ruleBundles') bundle(value)
       WHERE jsonb_typeof(bundle.value->'rules') IS DISTINCT FROM 'array'
     ) THEN
    RAISE EXCEPTION 'SAST queue admission kill-switch selector context is malformed';
  END IF;

  SELECT count(*) INTO scanner_count
  FROM jsonb_each(NEW."immutablePlan"->'scannerSet'->'scanners');
  SELECT count(DISTINCT bundle.value->>'digest') INTO bundle_count
  FROM jsonb_array_elements(NEW."immutablePlan"->'scannerSet'->'ruleBundles') bundle(value);
  SELECT count(DISTINCT rule.value->>'ruleSemanticId') INTO semantic_rule_count
  FROM jsonb_array_elements(NEW."immutablePlan"->'scannerSet'->'ruleBundles') bundle(value)
  CROSS JOIN LATERAL jsonb_array_elements(bundle.value->'rules') rule(value);
  SELECT count(DISTINCT capability.value) INTO capability_count
  FROM jsonb_array_elements_text(NEW."immutablePlan"->'profile'->'requiredCapabilities') capability(value);
  expected_count := 4 + scanner_count + bundle_count + semantic_rule_count + capability_count;

  SELECT count(*) INTO actual_count FROM public."SastKillSwitchEvaluationHead" WHERE "evaluationId" = evaluation_record."id";
  IF actual_count <> evaluation_record."headCount"
     OR actual_count <> expected_count
     OR evaluation_record."matchedDecisionCount" <> 0 THEN
    RAISE EXCEPTION 'SAST queue admission kill-switch receipt is incomplete';
  END IF;

  IF NOT EXISTS (
       SELECT 1
       FROM public."SastKillSwitchEvaluationHead" binding
       JOIN public."SastKillSwitchHead" head ON head."selectorKey" = binding."selectorKey"
       WHERE binding."evaluationId" = evaluation_record."id"
         AND head."scope" = 'GLOBAL' AND head."runtime" = 'SAST'
     )
     OR NOT EXISTS (
       SELECT 1
       FROM public."SastKillSwitchEvaluationHead" binding
       JOIN public."SastKillSwitchHead" head ON head."selectorKey" = binding."selectorKey"
       WHERE binding."evaluationId" = evaluation_record."id"
         AND head."scope" = 'TENANT' AND head."tenantId" = NEW."tenantId"
     )
     OR NOT EXISTS (
       SELECT 1
       FROM public."SastKillSwitchEvaluationHead" binding
       JOIN public."SastKillSwitchHead" head ON head."selectorKey" = binding."selectorKey"
       WHERE binding."evaluationId" = evaluation_record."id"
         AND head."scope" = 'REPOSITORY_BINDING'
         AND head."tenantId" = NEW."tenantId"
         AND head."repositoryBindingId" = NEW."repositoryBindingId"
     )
     OR NOT EXISTS (
       SELECT 1
       FROM public."SastKillSwitchEvaluationHead" binding
       JOIN public."SastKillSwitchHead" head ON head."selectorKey" = binding."selectorKey"
       WHERE binding."evaluationId" = evaluation_record."id"
         AND head."scope" = 'PROFILE'
         AND head."profileId" = NEW."immutablePlan"->'profile'->>'id'
         AND head."profileDigest" = NEW."immutablePlan"->>'profileDigest'
     )
     OR EXISTS (
       SELECT 1
       FROM jsonb_each(NEW."immutablePlan"->'scannerSet'->'scanners') scanner(scanner_name, descriptor)
       WHERE NOT EXISTS (
         SELECT 1
         FROM public."SastKillSwitchEvaluationHead" binding
         JOIN public."SastKillSwitchHead" head ON head."selectorKey" = binding."selectorKey"
         WHERE binding."evaluationId" = evaluation_record."id"
           AND head."scope" = 'SCANNER_VERSION'
           AND head."scanner" = scanner.scanner_name
           AND head."scannerVersion" = scanner.descriptor->>'version'
       )
     )
     OR EXISTS (
       SELECT 1
       FROM jsonb_array_elements(NEW."immutablePlan"->'scannerSet'->'ruleBundles') bundle(value)
       WHERE NOT EXISTS (
         SELECT 1
         FROM public."SastKillSwitchEvaluationHead" binding
         JOIN public."SastKillSwitchHead" head ON head."selectorKey" = binding."selectorKey"
         WHERE binding."evaluationId" = evaluation_record."id"
           AND head."scope" = 'RULE_BUNDLE'
           AND head."bundleDigest" = bundle.value->>'digest'
       )
     )
     OR EXISTS (
       SELECT 1
       FROM jsonb_array_elements(NEW."immutablePlan"->'scannerSet'->'ruleBundles') bundle(value)
       CROSS JOIN LATERAL jsonb_array_elements(bundle.value->'rules') rule(value)
       WHERE NOT EXISTS (
         SELECT 1
         FROM public."SastKillSwitchEvaluationHead" binding
         JOIN public."SastKillSwitchHead" head ON head."selectorKey" = binding."selectorKey"
         WHERE binding."evaluationId" = evaluation_record."id"
           AND head."scope" = 'SEMANTIC_RULE'
           AND head."ruleSemanticId" = rule.value->>'ruleSemanticId'
       )
     )
     OR EXISTS (
       SELECT 1
       FROM jsonb_array_elements_text(NEW."immutablePlan"->'profile'->'requiredCapabilities') capability(value)
       WHERE NOT EXISTS (
         SELECT 1
         FROM public."SastKillSwitchEvaluationHead" binding
         JOIN public."SastKillSwitchHead" head ON head."selectorKey" = binding."selectorKey"
         WHERE binding."evaluationId" = evaluation_record."id"
           AND head."scope" = 'CAPABILITY'
           AND head."capability" = capability.value
       )
     ) THEN
    RAISE EXCEPTION 'SAST queue admission kill-switch selector set does not match the immutable plan';
  END IF;

  FOR binding_record IN SELECT * FROM public."SastKillSwitchEvaluationHead" WHERE "evaluationId" = evaluation_record."id" ORDER BY "selectorKey" LOOP
    SELECT * INTO current_head FROM public."SastKillSwitchHead" WHERE "selectorKey" = binding_record."selectorKey" FOR UPDATE;
    IF NOT FOUND
       OR current_head."sequence" IS DISTINCT FROM binding_record."sequence"
       OR current_head."currentDecisionId" IS DISTINCT FROM binding_record."decisionId"
       OR current_head."currentDecisionDigest" IS DISTINCT FROM binding_record."decisionDigest"
       OR current_head."currentAction" IS DISTINCT FROM binding_record."action"
       OR current_head."active" IS DISTINCT FROM binding_record."active"
       OR current_head."effectiveAt" IS DISTINCT FROM binding_record."effectiveAt"
       OR current_head."expiresAt" IS DISTINCT FROM binding_record."expiresAt"
       OR current_head."active" IS TRUE THEN
      RAISE EXCEPTION 'SAST kill-switch state changed before queue admission';
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION "enforce_sast_rule_bundle_lifecycle_append"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE latest_record RECORD; evidence_time TIMESTAMP(3); suspension_record RECORD; switch_head RECORD;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW."manifestId", 0));
  SELECT "id", "transitionDigest", "sequence", "toState", "transitionedAt" INTO latest_record
  FROM public."SastRuleBundleLifecycleTransition" WHERE "manifestId" = NEW."manifestId" ORDER BY "sequence" DESC LIMIT 1;
  IF NOT FOUND THEN
    IF NEW."sequence" <> 1 OR NEW."fromState" <> 'DRAFT' OR NEW."previousTransitionId" IS NOT NULL OR NEW."previousTransitionDigest" IS NOT NULL THEN
      RAISE EXCEPTION 'SAST lifecycle transition must start at DRAFT sequence one';
    END IF;
  ELSIF NEW."sequence" <> latest_record."sequence" + 1 OR NEW."fromState" <> latest_record."toState" OR NEW."previousTransitionId" <> latest_record."id" OR NEW."previousTransitionDigest" <> latest_record."transitionDigest" OR NEW."transitionedAt" < latest_record."transitionedAt" THEN
    RAISE EXCEPTION 'SAST lifecycle transition is stale or breaks the append-only chain';
  END IF;
  SELECT "measuredAt" INTO evidence_time FROM public."SastRuleBundlePromotionEvidence" WHERE "id" = NEW."promotionEvidenceId";
  IF NOT FOUND THEN RAISE EXCEPTION 'SAST lifecycle transition promotion evidence is unavailable'; END IF;
  IF NEW."transitionedAt" < evidence_time THEN RAISE EXCEPTION 'SAST lifecycle transition predates its promotion evidence'; END IF;
  IF NEW."externalAuthority" = 'EMERGENCY_SUSPENSION' THEN
    SELECT * INTO suspension_record FROM public."SastKillSwitchEmergencySuspensionReceipt"
    WHERE "id" = NEW."externalAuthorityReceiptRef" AND "receiptDigest" = NEW."externalAuthorityReceiptDigest"
      AND "manifestId" = NEW."manifestId" AND "manifestDigest" = NEW."manifestDigest"
      AND "bundleId" = NEW."bundleId" AND "bundleDigest" = NEW."bundleDigest"
      AND "fromState" = NEW."fromState" AND "toState" = NEW."toState"
      AND "promotionEvidenceId" = NEW."promotionEvidenceId" AND "promotionEvidenceDigest" = NEW."promotionEvidenceDigest"
      AND "requestedAt" = NEW."transitionedAt";
    IF NOT FOUND THEN RAISE EXCEPTION 'SAST emergency suspension authority receipt is unavailable'; END IF;
    SELECT * INTO switch_head FROM public."SastKillSwitchHead" WHERE "selectorKey" = suspension_record."triggerSelectorKey" FOR UPDATE;
    IF NOT FOUND OR switch_head."currentDecisionId" IS DISTINCT FROM suspension_record."triggerDecisionId" OR switch_head."currentDecisionDigest" IS DISTINCT FROM suspension_record."triggerDecisionDigest" OR switch_head."active" IS NOT TRUE OR switch_head."expiresAt" <= NEW."transitionedAt" THEN
      RAISE EXCEPTION 'SAST emergency suspension authority is no longer active';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "SastKillSwitchDecision_append" BEFORE INSERT ON "SastKillSwitchDecision" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_kill_switch_decision_append"();
CREATE TRIGGER "SastKillSwitchDecision_refresh_head" AFTER INSERT ON "SastKillSwitchDecision" FOR EACH ROW EXECUTE FUNCTION "refresh_sast_kill_switch_head"();
CREATE CONSTRAINT TRIGGER "SastKillSwitchDecision_verification" AFTER INSERT ON "SastKillSwitchDecision" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "enforce_sast_kill_switch_verification"();
CREATE TRIGGER "SastKillSwitchHead_protect_insert" BEFORE INSERT ON "SastKillSwitchHead" FOR EACH ROW EXECUTE FUNCTION "protect_sast_kill_switch_head"();
CREATE TRIGGER "SastKillSwitchHead_protect_update" BEFORE UPDATE ON "SastKillSwitchHead" FOR EACH ROW EXECUTE FUNCTION "protect_sast_kill_switch_head"();
CREATE TRIGGER "SastKillSwitchHead_protect_delete" BEFORE DELETE ON "SastKillSwitchHead" FOR EACH ROW EXECUTE FUNCTION "protect_sast_kill_switch_head"();
CREATE TRIGGER "SastKillSwitchEvaluationHead_binding" BEFORE INSERT ON "SastKillSwitchEvaluationHead" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_kill_switch_evaluation_head"();
CREATE TRIGGER "SastKillSwitchEvaluationMatch_binding" BEFORE INSERT ON "SastKillSwitchEvaluationMatch" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_kill_switch_evaluation_match"();
CREATE CONSTRAINT TRIGGER "SastKillSwitchEvaluation_complete" AFTER INSERT ON "SastKillSwitchEvaluation" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "enforce_sast_kill_switch_evaluation_complete"();
CREATE TRIGGER "SastKillSwitchEmergencySuspensionReceipt_binding" BEFORE INSERT ON "SastKillSwitchEmergencySuspensionReceipt" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_kill_switch_suspension_receipt"();
CREATE TRIGGER "SastQueueReservation_zz_kill_switch_head" BEFORE INSERT ON "SastQueueReservation" FOR EACH ROW EXECUTE FUNCTION "enforce_sast_queue_kill_switch_head"();

CREATE TRIGGER "SastKillSwitchDecision_immutable_update" BEFORE UPDATE ON "SastKillSwitchDecision" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchDecision_immutable_delete" BEFORE DELETE ON "SastKillSwitchDecision" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchVerification_immutable_update" BEFORE UPDATE ON "SastKillSwitchVerification" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchVerification_immutable_delete" BEFORE DELETE ON "SastKillSwitchVerification" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchEvaluation_immutable_update" BEFORE UPDATE ON "SastKillSwitchEvaluation" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchEvaluation_immutable_delete" BEFORE DELETE ON "SastKillSwitchEvaluation" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchEvaluationHead_immutable_update" BEFORE UPDATE ON "SastKillSwitchEvaluationHead" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchEvaluationHead_immutable_delete" BEFORE DELETE ON "SastKillSwitchEvaluationHead" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchEvaluationMatch_immutable_update" BEFORE UPDATE ON "SastKillSwitchEvaluationMatch" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchEvaluationMatch_immutable_delete" BEFORE DELETE ON "SastKillSwitchEvaluationMatch" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchEmergencySuspensionReceipt_immutable_update" BEFORE UPDATE ON "SastKillSwitchEmergencySuspensionReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
CREATE TRIGGER "SastKillSwitchEmergencySuspensionReceipt_immutable_delete" BEFORE DELETE ON "SastKillSwitchEmergencySuspensionReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_kill_switch_ledger_mutation"();
