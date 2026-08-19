CREATE TABLE "SastRuleBundleRollbackCommand" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "commandDigest" TEXT NOT NULL,
  "candidateManifestId" TEXT NOT NULL,
  "candidateManifestDigest" TEXT NOT NULL,
  "candidateVerificationId" TEXT NOT NULL,
  "candidateVerificationDigest" TEXT NOT NULL,
  "candidateBundleId" TEXT NOT NULL,
  "candidateBundleDigest" TEXT NOT NULL,
  "suspendedTransitionId" TEXT NOT NULL,
  "suspendedTransitionDigest" TEXT NOT NULL,
  "suspendedSequence" INTEGER NOT NULL,
  "suspendedTransitionedAt" TIMESTAMP(3) NOT NULL,
  "suspensionAuthorityReceiptRef" TEXT NOT NULL,
  "suspensionAuthorityReceiptDigest" TEXT NOT NULL,
  "promotionEvidenceId" TEXT NOT NULL,
  "promotionEvidenceDigest" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "baselineManifestId" TEXT NOT NULL,
  "baselineManifestDigest" TEXT NOT NULL,
  "baselineVerificationId" TEXT NOT NULL,
  "baselineVerificationDigest" TEXT NOT NULL,
  "baselineBundleId" TEXT NOT NULL,
  "baselineBundleDigest" TEXT NOT NULL,
  "baselineTransitionId" TEXT NOT NULL,
  "baselineTransitionDigest" TEXT NOT NULL,
  "baselineSequence" INTEGER NOT NULL,
  "baselineTransitionedAt" TIMESTAMP(3) NOT NULL,
  "baselineState" TEXT NOT NULL DEFAULT 'ACTIVE',
  "incidentRef" TEXT NOT NULL,
  "actorRef" TEXT NOT NULL,
  "actorRole" TEXT NOT NULL,
  "reasonRef" TEXT NOT NULL,
  "auditRef" TEXT NOT NULL,
  "signatureRef" TEXT NOT NULL,
  "provenanceRef" TEXT NOT NULL,
  "commandedAt" TIMESTAMP(3) NOT NULL,
  "rollbackTargetDerived" BOOLEAN NOT NULL DEFAULT TRUE,
  "customerTargetAccepted" BOOLEAN NOT NULL DEFAULT FALSE,
  "source" TEXT NOT NULL DEFAULT 'PLATFORM_RULE_GOVERNANCE',
  "immutable" BOOLEAN NOT NULL DEFAULT TRUE,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "findingContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "arbitraryPayloadStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleRollbackCommand_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleRollbackCommand_contract_check" CHECK (
    "contractVersion" = 'sast-rule-bundle-rollback-command-v1'
    AND "commandDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-rollback-command://' || substring("commandDigest" from 8)
    AND "candidateManifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "candidateManifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "candidateVerificationId" ~ '^sast-rule-bundle-verification://[a-f0-9]{64}$'
    AND "candidateVerificationDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND length("candidateBundleId") BETWEEN 1 AND 512
    AND "candidateBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "suspendedTransitionId" ~ '^sast-rule-bundle-lifecycle-transition://[a-f0-9]{64}$'
    AND "suspendedTransitionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "suspendedSequence" BETWEEN 1 AND 1000000
    AND "suspensionAuthorityReceiptRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "suspensionAuthorityReceiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND right("suspensionAuthorityReceiptRef", 71) = "suspensionAuthorityReceiptDigest"
    AND "promotionEvidenceId" ~ '^sast-rule-bundle-promotion-evidence://[a-f0-9]{64}$'
    AND "promotionEvidenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1')
    AND "baselineManifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "baselineManifestId" <> "candidateManifestId"
    AND "baselineManifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "baselineVerificationId" ~ '^sast-rule-bundle-verification://[a-f0-9]{64}$'
    AND "baselineVerificationDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND length("baselineBundleId") BETWEEN 1 AND 512
    AND "baselineBundleId" = "candidateBundleId"
    AND "baselineBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "baselineBundleDigest" <> "candidateBundleDigest"
    AND "baselineTransitionId" ~ '^sast-rule-bundle-lifecycle-transition://[a-f0-9]{64}$'
    AND "baselineTransitionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "baselineSequence" BETWEEN 1 AND 1000000
    AND "baselineState" = 'ACTIVE'
    AND "actorRole" IN ('SECURITY_ON_CALL','PLATFORM_ON_CALL')
    AND length("actorRef") BETWEEN 1 AND 2048
    AND "actorRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+$'
    AND "actorRef" !~ '^https?://'
    AND "incidentRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "reasonRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "auditRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "signatureRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "provenanceRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "incidentRef" !~ '^https?://' AND "reasonRef" !~ '^https?://'
    AND "auditRef" !~ '^https?://' AND "signatureRef" !~ '^https?://'
    AND "provenanceRef" !~ '^https?://'
    AND "commandedAt" >= "suspendedTransitionedAt"
    AND "commandedAt" >= "baselineTransitionedAt"
    AND "rollbackTargetDerived" IS TRUE
    AND "customerTargetAccepted" IS FALSE
    AND "source" = 'PLATFORM_RULE_GOVERNANCE' AND "immutable" IS TRUE
    AND "repositoryContentStored" IS FALSE AND "findingContentStored" IS FALSE
    AND "secretValueStored" IS FALSE AND "arbitraryPayloadStored" IS FALSE
  )
);

CREATE UNIQUE INDEX "SastRuleBundleRollbackCommand_commandDigest_key" ON "SastRuleBundleRollbackCommand"("commandDigest");
CREATE UNIQUE INDEX "SastRuleBundleRollbackCommand_candidateManifestId_key" ON "SastRuleBundleRollbackCommand"("candidateManifestId");
CREATE UNIQUE INDEX "SastRuleBundleRollbackCommand_suspendedTransitionId_key" ON "SastRuleBundleRollbackCommand"("suspendedTransitionId");
CREATE UNIQUE INDEX "SastRuleBundleRollbackCommand_binding_key" ON "SastRuleBundleRollbackCommand"("id","commandDigest");
CREATE INDEX "SastRuleBundleRollbackCommand_candidate_idx" ON "SastRuleBundleRollbackCommand"("candidateBundleId","candidateBundleDigest","commandedAt");
CREATE INDEX "SastRuleBundleRollbackCommand_baseline_idx" ON "SastRuleBundleRollbackCommand"("baselineManifestId","baselineBundleDigest");

CREATE TABLE "SastRuleBundleRollbackVerification" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "verificationDigest" TEXT NOT NULL,
  "commandId" TEXT NOT NULL,
  "commandDigest" TEXT NOT NULL,
  "signerIdentity" TEXT NOT NULL,
  "signatureRef" TEXT NOT NULL,
  "provenanceRef" TEXT NOT NULL,
  "verifiedAt" TIMESTAMP(3) NOT NULL,
  "signatureVerified" BOOLEAN NOT NULL DEFAULT TRUE,
  "provenanceVerified" BOOLEAN NOT NULL DEFAULT TRUE,
  "trustedSigner" BOOLEAN NOT NULL DEFAULT TRUE,
  "signatureBytesStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "provenancePayloadStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleRollbackVerification_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleRollbackVerification_contract_check" CHECK (
    "contractVersion" = 'sast-rule-bundle-rollback-verification-v1'
    AND "verificationDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-rollback-verification://' || substring("verificationDigest" from 8)
    AND "commandId" ~ '^sast-rule-bundle-rollback-command://[a-f0-9]{64}$'
    AND "commandDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND length("signerIdentity") BETWEEN 1 AND 2048
    AND "signerIdentity" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+$'
    AND "signerIdentity" !~ '^https?://'
    AND "signatureRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "provenanceRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "signatureRef" !~ '^https?://' AND "provenanceRef" !~ '^https?://'
    AND "signatureVerified" IS TRUE AND "provenanceVerified" IS TRUE
    AND "trustedSigner" IS TRUE AND "signatureBytesStored" IS FALSE
    AND "provenancePayloadStored" IS FALSE
    AND "repositoryContentStored" IS FALSE AND "secretValueStored" IS FALSE
  )
);

CREATE UNIQUE INDEX "SastRuleBundleRollbackVerification_verificationDigest_key" ON "SastRuleBundleRollbackVerification"("verificationDigest");
CREATE UNIQUE INDEX "SastRuleBundleRollbackVerification_commandId_key" ON "SastRuleBundleRollbackVerification"("commandId");
CREATE UNIQUE INDEX "SastRuleBundleRollbackVerification_binding_key" ON "SastRuleBundleRollbackVerification"("id","verificationDigest","commandId","commandDigest");
CREATE INDEX "SastRuleBundleRollbackVerification_signer_idx" ON "SastRuleBundleRollbackVerification"("signerIdentity","verifiedAt");

CREATE TABLE "SastRuleBundleRollbackApproval" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "approvalDigest" TEXT NOT NULL,
  "commandId" TEXT NOT NULL,
  "commandDigest" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  "approverRef" TEXT NOT NULL,
  "approvalRef" TEXT NOT NULL,
  "approvedAt" TIMESTAMP(3) NOT NULL,
  "approved" BOOLEAN NOT NULL DEFAULT TRUE,
  "humanApproval" BOOLEAN NOT NULL DEFAULT TRUE,
  "automatedApproval" BOOLEAN NOT NULL DEFAULT FALSE,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT FALSE,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleRollbackApproval_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleRollbackApproval_contract_check" CHECK (
    "contractVersion" = 'sast-rule-bundle-rollback-approval-v1'
    AND "approvalDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-rollback-approval://' || substring("approvalDigest" from 8)
    AND "commandId" ~ '^sast-rule-bundle-rollback-command://[a-f0-9]{64}$'
    AND "commandDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "role" IN ('SECURITY_ENGINEERING','SCAN_PLATFORM','SECURITY_OPERATIONS')
    AND length("approverRef") BETWEEN 1 AND 2048
    AND "approverRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+$'
    AND "approverRef" !~ '^https?://'
    AND "approvalRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "approvalRef" !~ '^https?://'
    AND "approved" IS TRUE AND "humanApproval" IS TRUE
    AND "automatedApproval" IS FALSE AND "customerInputAccepted" IS FALSE
  )
);

CREATE UNIQUE INDEX "SastRuleBundleRollbackApproval_approvalDigest_key" ON "SastRuleBundleRollbackApproval"("approvalDigest");
CREATE UNIQUE INDEX "SastRuleBundleRollbackApproval_command_role_key" ON "SastRuleBundleRollbackApproval"("commandId","role");
CREATE UNIQUE INDEX "SastRuleBundleRollbackApproval_command_approver_key" ON "SastRuleBundleRollbackApproval"("commandId","approverRef");
CREATE UNIQUE INDEX "SastRuleBundleRollbackApproval_binding_key" ON "SastRuleBundleRollbackApproval"("id","approvalDigest","commandId","commandDigest","role","approverRef","approvedAt");
CREATE INDEX "SastRuleBundleRollbackApproval_command_time_idx" ON "SastRuleBundleRollbackApproval"("commandId","approvedAt");

CREATE TABLE "SastRuleBundleRollbackReceipt" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "receiptDigest" TEXT NOT NULL,
  "commandId" TEXT NOT NULL,
  "commandDigest" TEXT NOT NULL,
  "commandVerificationId" TEXT NOT NULL,
  "commandVerificationDigest" TEXT NOT NULL,
  "candidateManifestId" TEXT NOT NULL,
  "candidateManifestDigest" TEXT NOT NULL,
  "candidateBundleId" TEXT NOT NULL,
  "candidateBundleDigest" TEXT NOT NULL,
  "suspendedTransitionId" TEXT NOT NULL,
  "suspendedTransitionDigest" TEXT NOT NULL,
  "suspendedSequence" INTEGER NOT NULL,
  "suspendedTransitionedAt" TIMESTAMP(3) NOT NULL,
  "suspensionAuthorityReceiptRef" TEXT NOT NULL,
  "suspensionAuthorityReceiptDigest" TEXT NOT NULL,
  "promotionEvidenceId" TEXT NOT NULL,
  "promotionEvidenceDigest" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "baselineManifestId" TEXT NOT NULL,
  "baselineManifestDigest" TEXT NOT NULL,
  "baselineVerificationId" TEXT NOT NULL,
  "baselineVerificationDigest" TEXT NOT NULL,
  "baselineBundleId" TEXT NOT NULL,
  "baselineBundleDigest" TEXT NOT NULL,
  "baselineTransitionId" TEXT NOT NULL,
  "baselineTransitionDigest" TEXT NOT NULL,
  "baselineSequence" INTEGER NOT NULL,
  "baselineTransitionedAt" TIMESTAMP(3) NOT NULL,
  "baselineState" TEXT NOT NULL DEFAULT 'ACTIVE',
  "approvalCount" INTEGER NOT NULL DEFAULT 2,
  "approvalSetDigest" TEXT NOT NULL,
  "actorRef" TEXT NOT NULL,
  "reasonRef" TEXT NOT NULL,
  "auditRef" TEXT NOT NULL,
  "commandedAt" TIMESTAMP(3) NOT NULL,
  "requestedAt" TIMESTAMP(3) NOT NULL,
  "issuedAt" TIMESTAMP(3) NOT NULL,
  "fromState" TEXT NOT NULL DEFAULT 'SUSPENDED',
  "toState" TEXT NOT NULL DEFAULT 'ROLLED_BACK',
  "rollbackTargetDerived" BOOLEAN NOT NULL DEFAULT TRUE,
  "baselineMutationAuthorized" BOOLEAN NOT NULL DEFAULT FALSE,
  "historicalMutationAuthorized" BOOLEAN NOT NULL DEFAULT FALSE,
  "scannerSetMutationAuthorized" BOOLEAN NOT NULL DEFAULT FALSE,
  "findingAuthority" BOOLEAN NOT NULL DEFAULT FALSE,
  "policyAuthority" BOOLEAN NOT NULL DEFAULT FALSE,
  "publicationAuthority" BOOLEAN NOT NULL DEFAULT FALSE,
  "scmWriteAuthority" BOOLEAN NOT NULL DEFAULT FALSE,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT FALSE,
  "repositoryContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "findingContentStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "arbitraryPayloadStored" BOOLEAN NOT NULL DEFAULT FALSE,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SastRuleBundleRollbackReceipt_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleRollbackReceipt_contract_check" CHECK (
    "contractVersion" = 'sast-rule-bundle-rollback-receipt-v1'
    AND "receiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-rollback-receipt://authority/' || "receiptDigest"
    AND "commandId" ~ '^sast-rule-bundle-rollback-command://[a-f0-9]{64}$'
    AND "commandDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "commandVerificationId" ~ '^sast-rule-bundle-rollback-verification://[a-f0-9]{64}$'
    AND "commandVerificationDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "candidateManifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "candidateManifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND length("candidateBundleId") BETWEEN 1 AND 512
    AND "candidateBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "suspendedTransitionId" ~ '^sast-rule-bundle-lifecycle-transition://[a-f0-9]{64}$'
    AND "suspendedTransitionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "suspendedSequence" BETWEEN 1 AND 1000000
    AND "suspensionAuthorityReceiptRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "suspensionAuthorityReceiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND right("suspensionAuthorityReceiptRef", 71) = "suspensionAuthorityReceiptDigest"
    AND "promotionEvidenceId" ~ '^sast-rule-bundle-promotion-evidence://[a-f0-9]{64}$'
    AND "promotionEvidenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "profileId" IN ('JAVA_FAST_V1','JAVA_DEEP_V1','COMMON_DEEP_V1')
    AND "baselineManifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "baselineManifestId" <> "candidateManifestId"
    AND "baselineManifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "baselineVerificationId" ~ '^sast-rule-bundle-verification://[a-f0-9]{64}$'
    AND "baselineVerificationDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND length("baselineBundleId") BETWEEN 1 AND 512
    AND "baselineBundleId" = "candidateBundleId"
    AND "baselineBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "baselineBundleDigest" <> "candidateBundleDigest"
    AND "baselineTransitionId" ~ '^sast-rule-bundle-lifecycle-transition://[a-f0-9]{64}$'
    AND "baselineTransitionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "baselineSequence" BETWEEN 1 AND 1000000 AND "baselineState" = 'ACTIVE'
    AND "approvalCount" = 2 AND "approvalSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND length("actorRef") BETWEEN 1 AND 2048
    AND "actorRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+$' AND "actorRef" !~ '^https?://'
    AND "reasonRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "auditRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]*sha256:[a-f0-9]{64}$'
    AND "reasonRef" !~ '^https?://' AND "auditRef" !~ '^https?://'
    AND "commandedAt" >= "suspendedTransitionedAt"
    AND "commandedAt" >= "baselineTransitionedAt"
    AND "requestedAt" >= "commandedAt"
    AND "requestedAt" <= "commandedAt" + INTERVAL '15 minutes'
    AND "issuedAt" = "requestedAt"
    AND "fromState" = 'SUSPENDED' AND "toState" = 'ROLLED_BACK'
    AND "rollbackTargetDerived" IS TRUE
    AND "baselineMutationAuthorized" IS FALSE
    AND "historicalMutationAuthorized" IS FALSE
    AND "scannerSetMutationAuthorized" IS FALSE
    AND "findingAuthority" IS FALSE AND "policyAuthority" IS FALSE
    AND "publicationAuthority" IS FALSE AND "scmWriteAuthority" IS FALSE
    AND "customerInputAccepted" IS FALSE
    AND "repositoryContentStored" IS FALSE AND "findingContentStored" IS FALSE
    AND "secretValueStored" IS FALSE AND "arbitraryPayloadStored" IS FALSE
  )
);

CREATE UNIQUE INDEX "SastRuleBundleRollbackReceipt_receiptDigest_key" ON "SastRuleBundleRollbackReceipt"("receiptDigest");
CREATE UNIQUE INDEX "SastRuleBundleRollbackReceipt_commandId_key" ON "SastRuleBundleRollbackReceipt"("commandId");
CREATE UNIQUE INDEX "SastRuleBundleRollbackReceipt_candidateManifestId_key" ON "SastRuleBundleRollbackReceipt"("candidateManifestId");
CREATE UNIQUE INDEX "SastRuleBundleRollbackReceipt_suspendedTransitionId_key" ON "SastRuleBundleRollbackReceipt"("suspendedTransitionId");
CREATE UNIQUE INDEX "SastRuleBundleRollbackReceipt_binding_key" ON "SastRuleBundleRollbackReceipt"("id","receiptDigest","commandId","candidateManifestId","baselineManifestId");
CREATE INDEX "SastRuleBundleRollbackReceipt_candidate_idx" ON "SastRuleBundleRollbackReceipt"("candidateManifestId","suspendedSequence","issuedAt");
CREATE INDEX "SastRuleBundleRollbackReceipt_baseline_idx" ON "SastRuleBundleRollbackReceipt"("baselineManifestId","baselineSequence");

CREATE TABLE "SastRuleBundleRollbackReceiptApproval" (
  "receiptId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "approvalId" TEXT NOT NULL,
  "approvalDigest" TEXT NOT NULL,
  "commandId" TEXT NOT NULL,
  "commandDigest" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  "approverRef" TEXT NOT NULL,
  "approvedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "SastRuleBundleRollbackReceiptApproval_pkey" PRIMARY KEY ("receiptId","position"),
  CONSTRAINT "SastRuleBundleRollbackReceiptApproval_contract_check" CHECK (
    "position" IN (0,1)
    AND "approvalId" ~ '^sast-rule-bundle-rollback-approval://[a-f0-9]{64}$'
    AND "approvalDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "commandId" ~ '^sast-rule-bundle-rollback-command://[a-f0-9]{64}$'
    AND "commandDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "role" IN ('SECURITY_ENGINEERING','SCAN_PLATFORM','SECURITY_OPERATIONS')
    AND length("approverRef") BETWEEN 1 AND 2048
    AND "approverRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+$'
    AND "approverRef" !~ '^https?://'
  )
);

CREATE UNIQUE INDEX "SastRuleBundleRollbackReceiptApproval_id_key" ON "SastRuleBundleRollbackReceiptApproval"("receiptId","approvalId");
CREATE UNIQUE INDEX "SastRuleBundleRollbackReceiptApproval_role_key" ON "SastRuleBundleRollbackReceiptApproval"("receiptId","role");
CREATE UNIQUE INDEX "SastRuleBundleRollbackReceiptApproval_approver_key" ON "SastRuleBundleRollbackReceiptApproval"("receiptId","approverRef");
CREATE INDEX "SastRuleBundleRollbackReceiptApproval_command_idx" ON "SastRuleBundleRollbackReceiptApproval"("commandId","commandDigest");

ALTER TABLE "SastRuleBundleRollbackCommand" ADD CONSTRAINT "SastRuleBundleRollbackCommand_candidate_manifest_fkey"
  FOREIGN KEY ("candidateManifestId","candidateManifestDigest","candidateBundleId","candidateBundleDigest")
  REFERENCES "SastRuleBundleManifest"("id","manifestDigest","bundleId","bundleDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackCommand" ADD CONSTRAINT "SastRuleBundleRollbackCommand_baseline_manifest_fkey"
  FOREIGN KEY ("baselineManifestId","baselineManifestDigest","baselineBundleId","baselineBundleDigest")
  REFERENCES "SastRuleBundleManifest"("id","manifestDigest","bundleId","bundleDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackCommand" ADD CONSTRAINT "SastRuleBundleRollbackCommand_candidate_verification_fkey"
  FOREIGN KEY ("candidateVerificationId","candidateManifestId","candidateVerificationDigest")
  REFERENCES "SastRuleBundleSupplyChainAttestation"("id","manifestId","attestationDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackCommand" ADD CONSTRAINT "SastRuleBundleRollbackCommand_baseline_verification_fkey"
  FOREIGN KEY ("baselineVerificationId","baselineManifestId","baselineVerificationDigest")
  REFERENCES "SastRuleBundleSupplyChainAttestation"("id","manifestId","attestationDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackCommand" ADD CONSTRAINT "SastRuleBundleRollbackCommand_suspended_transition_fkey"
  FOREIGN KEY ("suspendedTransitionId","suspendedTransitionDigest")
  REFERENCES "SastRuleBundleLifecycleTransition"("id","transitionDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackCommand" ADD CONSTRAINT "SastRuleBundleRollbackCommand_baseline_transition_fkey"
  FOREIGN KEY ("baselineTransitionId","baselineTransitionDigest")
  REFERENCES "SastRuleBundleLifecycleTransition"("id","transitionDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackCommand" ADD CONSTRAINT "SastRuleBundleRollbackCommand_evidence_id_fkey"
  FOREIGN KEY ("promotionEvidenceId")
  REFERENCES "SastRuleBundlePromotionEvidence"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackCommand" ADD CONSTRAINT "SastRuleBundleRollbackCommand_evidence_digest_fkey"
  FOREIGN KEY ("promotionEvidenceDigest")
  REFERENCES "SastRuleBundlePromotionEvidence"("evidenceDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackCommand" ADD CONSTRAINT "SastRuleBundleRollbackCommand_suspension_receipt_fkey"
  FOREIGN KEY ("suspensionAuthorityReceiptRef","suspensionAuthorityReceiptDigest","candidateManifestId","candidateBundleDigest")
  REFERENCES "SastKillSwitchEmergencySuspensionReceipt"("id","receiptDigest","manifestId","bundleDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "SastRuleBundleRollbackVerification" ADD CONSTRAINT "SastRuleBundleRollbackVerification_command_fkey"
  FOREIGN KEY ("commandId","commandDigest")
  REFERENCES "SastRuleBundleRollbackCommand"("id","commandDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackApproval" ADD CONSTRAINT "SastRuleBundleRollbackApproval_command_fkey"
  FOREIGN KEY ("commandId","commandDigest")
  REFERENCES "SastRuleBundleRollbackCommand"("id","commandDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackReceipt" ADD CONSTRAINT "SastRuleBundleRollbackReceipt_command_fkey"
  FOREIGN KEY ("commandId","commandDigest")
  REFERENCES "SastRuleBundleRollbackCommand"("id","commandDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackReceipt" ADD CONSTRAINT "SastRuleBundleRollbackReceipt_verification_fkey"
  FOREIGN KEY ("commandVerificationId","commandVerificationDigest","commandId","commandDigest")
  REFERENCES "SastRuleBundleRollbackVerification"("id","verificationDigest","commandId","commandDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackReceiptApproval" ADD CONSTRAINT "SastRuleBundleRollbackReceiptApproval_receipt_fkey"
  FOREIGN KEY ("receiptId") REFERENCES "SastRuleBundleRollbackReceipt"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleRollbackReceiptApproval" ADD CONSTRAINT "SastRuleBundleRollbackReceiptApproval_approval_fkey"
  FOREIGN KEY ("approvalId","approvalDigest","commandId","commandDigest","role","approverRef","approvedAt")
  REFERENCES "SastRuleBundleRollbackApproval"("id","approvalDigest","commandId","commandDigest","role","approverRef","approvedAt") ON DELETE RESTRICT ON UPDATE RESTRICT;

CREATE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'SAST rule-bundle rollback records are append-only';
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_rollback_command_state"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  locked_count INTEGER;
  candidate_head RECORD;
  baseline_head RECORD;
  candidate_transition RECORD;
  baseline_transition RECORD;
  evidence_record RECORD;
  candidate_manifest RECORD;
  baseline_manifest RECORD;
  candidate_verification RECORD;
  baseline_verification RECORD;
  suspension_receipt RECORD;
BEGIN
  PERFORM 1
  FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" IN (NEW."candidateManifestId", NEW."baselineManifestId")
  ORDER BY "manifestId" COLLATE "C"
  FOR UPDATE;
  GET DIAGNOSTICS locked_count = ROW_COUNT;
  IF locked_count <> 2 THEN
    RAISE EXCEPTION 'SAST rollback candidate or baseline head is unavailable';
  END IF;

  SELECT * INTO candidate_head FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" = NEW."candidateManifestId";
  SELECT * INTO baseline_head FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" = NEW."baselineManifestId";
  IF candidate_head."lifecycleState" IS DISTINCT FROM 'SUSPENDED'
     OR candidate_head."manifestDigest" IS DISTINCT FROM NEW."candidateManifestDigest"
     OR candidate_head."bundleId" IS DISTINCT FROM NEW."candidateBundleId"
     OR candidate_head."bundleDigest" IS DISTINCT FROM NEW."candidateBundleDigest"
     OR candidate_head."transitionId" IS DISTINCT FROM NEW."suspendedTransitionId"
     OR candidate_head."transitionDigest" IS DISTINCT FROM NEW."suspendedTransitionDigest"
     OR candidate_head."sequence" IS DISTINCT FROM NEW."suspendedSequence"
     OR candidate_head."promotionEvidenceId" IS DISTINCT FROM NEW."promotionEvidenceId"
     OR candidate_head."promotionEvidenceDigest" IS DISTINCT FROM NEW."promotionEvidenceDigest" THEN
    RAISE EXCEPTION 'SAST rollback candidate suspension is stale';
  END IF;
  IF baseline_head."lifecycleState" IS DISTINCT FROM 'ACTIVE'
     OR baseline_head."manifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR baseline_head."bundleId" IS DISTINCT FROM NEW."baselineBundleId"
     OR baseline_head."bundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR baseline_head."transitionId" IS DISTINCT FROM NEW."baselineTransitionId"
     OR baseline_head."transitionDigest" IS DISTINCT FROM NEW."baselineTransitionDigest"
     OR baseline_head."sequence" IS DISTINCT FROM NEW."baselineSequence"
     OR baseline_head."transitionedAt" IS DISTINCT FROM NEW."baselineTransitionedAt" THEN
    RAISE EXCEPTION 'SAST rollback baseline is not the current active head';
  END IF;

  SELECT * INTO candidate_transition FROM public."SastRuleBundleLifecycleTransition"
  WHERE "id" = NEW."suspendedTransitionId" AND "transitionDigest" = NEW."suspendedTransitionDigest";
  IF NOT FOUND
     OR candidate_transition."manifestId" IS DISTINCT FROM NEW."candidateManifestId"
     OR candidate_transition."manifestDigest" IS DISTINCT FROM NEW."candidateManifestDigest"
     OR candidate_transition."bundleId" IS DISTINCT FROM NEW."candidateBundleId"
     OR candidate_transition."bundleDigest" IS DISTINCT FROM NEW."candidateBundleDigest"
     OR candidate_transition."sequence" IS DISTINCT FROM NEW."suspendedSequence"
     OR candidate_transition."transitionedAt" IS DISTINCT FROM NEW."suspendedTransitionedAt"
     OR candidate_transition."fromState" NOT IN ('CANARY','ACTIVE')
     OR candidate_transition."toState" IS DISTINCT FROM 'SUSPENDED'
     OR candidate_transition."externalAuthority" IS DISTINCT FROM 'EMERGENCY_SUSPENSION'
     OR candidate_transition."externalAuthorityReceiptRef" IS DISTINCT FROM NEW."suspensionAuthorityReceiptRef"
     OR candidate_transition."externalAuthorityReceiptDigest" IS DISTINCT FROM NEW."suspensionAuthorityReceiptDigest"
     OR candidate_transition."promotionEvidenceId" IS DISTINCT FROM NEW."promotionEvidenceId"
     OR candidate_transition."promotionEvidenceDigest" IS DISTINCT FROM NEW."promotionEvidenceDigest" THEN
    RAISE EXCEPTION 'SAST rollback command is not tied to the exact emergency suspension';
  END IF;

  SELECT * INTO baseline_transition FROM public."SastRuleBundleLifecycleTransition"
  WHERE "id" = NEW."baselineTransitionId" AND "transitionDigest" = NEW."baselineTransitionDigest";
  IF NOT FOUND
     OR baseline_transition."manifestId" IS DISTINCT FROM NEW."baselineManifestId"
     OR baseline_transition."manifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR baseline_transition."bundleId" IS DISTINCT FROM NEW."baselineBundleId"
     OR baseline_transition."bundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR baseline_transition."sequence" IS DISTINCT FROM NEW."baselineSequence"
     OR baseline_transition."transitionedAt" IS DISTINCT FROM NEW."baselineTransitionedAt"
     OR baseline_transition."toState" IS DISTINCT FROM 'ACTIVE' THEN
    RAISE EXCEPTION 'SAST rollback baseline transition is stale';
  END IF;

  SELECT * INTO evidence_record FROM public."SastRuleBundlePromotionEvidence"
  WHERE "id" = NEW."promotionEvidenceId" AND "evidenceDigest" = NEW."promotionEvidenceDigest";
  IF NOT FOUND
     OR evidence_record."manifestId" IS DISTINCT FROM NEW."candidateManifestId"
     OR evidence_record."manifestDigest" IS DISTINCT FROM NEW."candidateManifestDigest"
     OR evidence_record."verificationId" IS DISTINCT FROM NEW."candidateVerificationId"
     OR evidence_record."verificationDigest" IS DISTINCT FROM NEW."candidateVerificationDigest"
     OR evidence_record."bundleId" IS DISTINCT FROM NEW."candidateBundleId"
     OR evidence_record."bundleDigest" IS DISTINCT FROM NEW."candidateBundleDigest"
     OR evidence_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR evidence_record."baselineManifestId" IS DISTINCT FROM NEW."baselineManifestId"
     OR evidence_record."baselineManifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR evidence_record."baselineBundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR evidence_record."rollbackTargetDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR evidence_record."gatesPassed" IS NOT TRUE
     OR evidence_record."automatedEvidenceOnly" IS NOT TRUE
     OR evidence_record."approvalGranted" IS NOT FALSE THEN
    RAISE EXCEPTION 'SAST rollback target was not derived from the original promotion evidence';
  END IF;

  SELECT * INTO candidate_manifest FROM public."SastRuleBundleManifest"
  WHERE "id" = NEW."candidateManifestId";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST rollback candidate manifest is unavailable';
  END IF;
  SELECT * INTO baseline_manifest FROM public."SastRuleBundleManifest"
  WHERE "id" = NEW."baselineManifestId";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST rollback baseline manifest is unavailable';
  END IF;
  IF candidate_manifest."manifestDigest" IS DISTINCT FROM NEW."candidateManifestDigest"
     OR candidate_manifest."bundleId" IS DISTINCT FROM NEW."candidateBundleId"
     OR candidate_manifest."bundleDigest" IS DISTINCT FROM NEW."candidateBundleDigest"
     OR candidate_manifest."rollbackTargetDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR baseline_manifest."manifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR baseline_manifest."bundleId" IS DISTINCT FROM NEW."baselineBundleId"
     OR baseline_manifest."bundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR candidate_manifest."scanner" IS DISTINCT FROM baseline_manifest."scanner"
     OR NOT EXISTS (
       SELECT 1 FROM public."SastRuleBundleCompatibilityEntry"
       WHERE "manifestId" = NEW."candidateManifestId" AND "kind" = 'PROFILE_ID' AND "value" = NEW."profileId"
     )
     OR NOT EXISTS (
       SELECT 1 FROM public."SastRuleBundleCompatibilityEntry"
       WHERE "manifestId" = NEW."baselineManifestId" AND "kind" = 'PROFILE_ID' AND "value" = NEW."profileId"
     ) THEN
    RAISE EXCEPTION 'SAST rollback candidate and baseline manifests are incompatible';
  END IF;

  SELECT * INTO candidate_verification FROM public."SastRuleBundleSupplyChainAttestation"
  WHERE "id" = NEW."candidateVerificationId" AND "manifestId" = NEW."candidateManifestId"
    AND "attestationDigest" = NEW."candidateVerificationDigest";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST rollback candidate supply-chain verification is unavailable';
  END IF;
  SELECT * INTO baseline_verification FROM public."SastRuleBundleSupplyChainAttestation"
  WHERE "id" = NEW."baselineVerificationId" AND "manifestId" = NEW."baselineManifestId"
    AND "attestationDigest" = NEW."baselineVerificationDigest";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST rollback baseline supply-chain verification is unavailable';
  END IF;
  IF candidate_verification."signatureVerified" IS NOT TRUE
     OR candidate_verification."provenanceVerified" IS NOT TRUE
     OR candidate_verification."trustedSigner" IS NOT TRUE
     OR baseline_verification."signatureVerified" IS NOT TRUE
     OR baseline_verification."provenanceVerified" IS NOT TRUE
     OR baseline_verification."trustedSigner" IS NOT TRUE THEN
    RAISE EXCEPTION 'SAST rollback supply-chain verification is unavailable';
  END IF;

  SELECT * INTO suspension_receipt FROM public."SastKillSwitchEmergencySuspensionReceipt"
  WHERE "id" = NEW."suspensionAuthorityReceiptRef"
    AND "receiptDigest" = NEW."suspensionAuthorityReceiptDigest"
    AND "manifestId" = NEW."candidateManifestId"
    AND "manifestDigest" = NEW."candidateManifestDigest"
    AND "bundleId" = NEW."candidateBundleId"
    AND "bundleDigest" = NEW."candidateBundleDigest"
    AND "lifecycleTransitionId" = candidate_transition."previousTransitionId"
    AND "promotionEvidenceId" = NEW."promotionEvidenceId"
    AND "promotionEvidenceDigest" = NEW."promotionEvidenceDigest"
    AND "fromState" = candidate_transition."fromState"
    AND "toState" = 'SUSPENDED'
    AND "requestedAt" = candidate_transition."transitionedAt";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST rollback emergency suspension receipt is unavailable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_rollback_command_verification"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE verification_record RECORD;
BEGIN
  SELECT * INTO verification_record FROM public."SastRuleBundleRollbackVerification"
  WHERE "commandId" = NEW."id" AND "commandDigest" = NEW."commandDigest";
  IF NOT FOUND
     OR verification_record."signatureRef" IS DISTINCT FROM NEW."signatureRef"
     OR verification_record."provenanceRef" IS DISTINCT FROM NEW."provenanceRef"
     OR verification_record."verifiedAt" < NEW."commandedAt"
     OR verification_record."signatureVerified" IS NOT TRUE
     OR verification_record."provenanceVerified" IS NOT TRUE
     OR verification_record."trustedSigner" IS NOT TRUE THEN
    RAISE EXCEPTION 'SAST rollback command verification is unavailable';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_rollback_approval"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE command_record RECORD; existing_count INTEGER; platform_count INTEGER;
BEGIN
  SELECT * INTO command_record FROM public."SastRuleBundleRollbackCommand"
  WHERE "id" = NEW."commandId" FOR UPDATE;
  IF NOT FOUND OR command_record."commandDigest" IS DISTINCT FROM NEW."commandDigest" THEN
    RAISE EXCEPTION 'SAST rollback approval command is unavailable';
  END IF;
  IF EXISTS (SELECT 1 FROM public."SastRuleBundleRollbackReceipt" WHERE "commandId" = NEW."commandId") THEN
    RAISE EXCEPTION 'SAST rollback approval cannot be appended after receipt issuance';
  END IF;
  IF NEW."approverRef" = command_record."actorRef"
     OR NEW."approvedAt" < command_record."commandedAt"
     OR NEW."approvedAt" > command_record."commandedAt" + INTERVAL '15 minutes' THEN
    RAISE EXCEPTION 'SAST rollback approval is stale or not independent';
  END IF;
  SELECT count(*), count(*) FILTER (WHERE "role" IN ('SCAN_PLATFORM','SECURITY_OPERATIONS'))
    INTO existing_count, platform_count
  FROM public."SastRuleBundleRollbackApproval" WHERE "commandId" = NEW."commandId";
  IF existing_count >= 2
     OR (NEW."role" IN ('SCAN_PLATFORM','SECURITY_OPERATIONS') AND platform_count > 0) THEN
    RAISE EXCEPTION 'SAST rollback approval set exceeds the independent dual-control contract';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_rollback_receipt_state"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  locked_count INTEGER;
  command_record RECORD;
  verification_record RECORD;
  candidate_head RECORD;
  baseline_head RECORD;
  candidate_transition RECORD;
BEGIN
  PERFORM 1 FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" IN (NEW."candidateManifestId", NEW."baselineManifestId")
  ORDER BY "manifestId" COLLATE "C" FOR UPDATE;
  GET DIAGNOSTICS locked_count = ROW_COUNT;
  IF locked_count <> 2 THEN
    RAISE EXCEPTION 'SAST rollback receipt candidate or baseline head is unavailable';
  END IF;

  SELECT * INTO command_record FROM public."SastRuleBundleRollbackCommand"
  WHERE "id" = NEW."commandId" FOR UPDATE;
  IF NOT FOUND
     OR command_record."commandDigest" IS DISTINCT FROM NEW."commandDigest"
     OR command_record."candidateManifestId" IS DISTINCT FROM NEW."candidateManifestId"
     OR command_record."candidateManifestDigest" IS DISTINCT FROM NEW."candidateManifestDigest"
     OR command_record."candidateBundleId" IS DISTINCT FROM NEW."candidateBundleId"
     OR command_record."candidateBundleDigest" IS DISTINCT FROM NEW."candidateBundleDigest"
     OR command_record."suspendedTransitionId" IS DISTINCT FROM NEW."suspendedTransitionId"
     OR command_record."suspendedTransitionDigest" IS DISTINCT FROM NEW."suspendedTransitionDigest"
     OR command_record."suspendedSequence" IS DISTINCT FROM NEW."suspendedSequence"
     OR command_record."suspendedTransitionedAt" IS DISTINCT FROM NEW."suspendedTransitionedAt"
     OR command_record."suspensionAuthorityReceiptRef" IS DISTINCT FROM NEW."suspensionAuthorityReceiptRef"
     OR command_record."suspensionAuthorityReceiptDigest" IS DISTINCT FROM NEW."suspensionAuthorityReceiptDigest"
     OR command_record."promotionEvidenceId" IS DISTINCT FROM NEW."promotionEvidenceId"
     OR command_record."promotionEvidenceDigest" IS DISTINCT FROM NEW."promotionEvidenceDigest"
     OR command_record."profileId" IS DISTINCT FROM NEW."profileId"
     OR command_record."baselineManifestId" IS DISTINCT FROM NEW."baselineManifestId"
     OR command_record."baselineManifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR command_record."baselineVerificationId" IS DISTINCT FROM NEW."baselineVerificationId"
     OR command_record."baselineVerificationDigest" IS DISTINCT FROM NEW."baselineVerificationDigest"
     OR command_record."baselineBundleId" IS DISTINCT FROM NEW."baselineBundleId"
     OR command_record."baselineBundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR command_record."baselineTransitionId" IS DISTINCT FROM NEW."baselineTransitionId"
     OR command_record."baselineTransitionDigest" IS DISTINCT FROM NEW."baselineTransitionDigest"
     OR command_record."baselineSequence" IS DISTINCT FROM NEW."baselineSequence"
     OR command_record."baselineTransitionedAt" IS DISTINCT FROM NEW."baselineTransitionedAt"
     OR command_record."actorRef" IS DISTINCT FROM NEW."actorRef"
     OR command_record."reasonRef" IS DISTINCT FROM NEW."reasonRef"
     OR command_record."auditRef" IS DISTINCT FROM NEW."auditRef"
     OR command_record."commandedAt" IS DISTINCT FROM NEW."commandedAt" THEN
    RAISE EXCEPTION 'SAST rollback receipt does not match its immutable command';
  END IF;

  SELECT * INTO verification_record FROM public."SastRuleBundleRollbackVerification"
  WHERE "id" = NEW."commandVerificationId"
    AND "verificationDigest" = NEW."commandVerificationDigest"
    AND "commandId" = NEW."commandId" AND "commandDigest" = NEW."commandDigest";
  IF NOT FOUND
     OR verification_record."signatureRef" IS DISTINCT FROM command_record."signatureRef"
     OR verification_record."provenanceRef" IS DISTINCT FROM command_record."provenanceRef"
     OR verification_record."signatureVerified" IS NOT TRUE
     OR verification_record."provenanceVerified" IS NOT TRUE
     OR verification_record."trustedSigner" IS NOT TRUE THEN
    RAISE EXCEPTION 'SAST rollback receipt command verification is unavailable';
  END IF;

  SELECT * INTO candidate_head FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" = NEW."candidateManifestId";
  SELECT * INTO baseline_head FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" = NEW."baselineManifestId";
  IF candidate_head."lifecycleState" IS DISTINCT FROM 'SUSPENDED'
     OR candidate_head."manifestDigest" IS DISTINCT FROM NEW."candidateManifestDigest"
     OR candidate_head."bundleId" IS DISTINCT FROM NEW."candidateBundleId"
     OR candidate_head."bundleDigest" IS DISTINCT FROM NEW."candidateBundleDigest"
     OR candidate_head."transitionId" IS DISTINCT FROM NEW."suspendedTransitionId"
     OR candidate_head."transitionDigest" IS DISTINCT FROM NEW."suspendedTransitionDigest"
     OR candidate_head."sequence" IS DISTINCT FROM NEW."suspendedSequence"
     OR candidate_head."promotionEvidenceId" IS DISTINCT FROM NEW."promotionEvidenceId"
     OR candidate_head."promotionEvidenceDigest" IS DISTINCT FROM NEW."promotionEvidenceDigest" THEN
    RAISE EXCEPTION 'SAST rollback candidate changed before receipt issuance';
  END IF;
  IF baseline_head."lifecycleState" IS DISTINCT FROM 'ACTIVE'
     OR baseline_head."manifestDigest" IS DISTINCT FROM NEW."baselineManifestDigest"
     OR baseline_head."bundleId" IS DISTINCT FROM NEW."baselineBundleId"
     OR baseline_head."bundleDigest" IS DISTINCT FROM NEW."baselineBundleDigest"
     OR baseline_head."transitionId" IS DISTINCT FROM NEW."baselineTransitionId"
     OR baseline_head."transitionDigest" IS DISTINCT FROM NEW."baselineTransitionDigest"
     OR baseline_head."sequence" IS DISTINCT FROM NEW."baselineSequence"
     OR baseline_head."transitionedAt" IS DISTINCT FROM NEW."baselineTransitionedAt" THEN
    RAISE EXCEPTION 'SAST rollback baseline changed before receipt issuance';
  END IF;

  SELECT * INTO candidate_transition FROM public."SastRuleBundleLifecycleTransition"
  WHERE "id" = NEW."suspendedTransitionId" AND "transitionDigest" = NEW."suspendedTransitionDigest";
  IF NOT FOUND
     OR candidate_transition."externalAuthority" IS DISTINCT FROM 'EMERGENCY_SUSPENSION'
     OR candidate_transition."externalAuthorityReceiptRef" IS DISTINCT FROM NEW."suspensionAuthorityReceiptRef"
     OR candidate_transition."externalAuthorityReceiptDigest" IS DISTINCT FROM NEW."suspensionAuthorityReceiptDigest"
     OR candidate_transition."transitionedAt" IS DISTINCT FROM NEW."suspendedTransitionedAt"
     OR candidate_transition."toState" IS DISTINCT FROM 'SUSPENDED' THEN
    RAISE EXCEPTION 'SAST rollback receipt suspension authority is invalid';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_rollback_receipt_approvals"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  approval_count INTEGER;
  security_count INTEGER;
  platform_count INTEGER;
  actual_set_json TEXT;
  actual_set_digest TEXT;
BEGIN
  SELECT count(*),
         count(*) FILTER (WHERE binding."role" = 'SECURITY_ENGINEERING'),
         count(*) FILTER (WHERE binding."role" IN ('SCAN_PLATFORM','SECURITY_OPERATIONS'))
    INTO approval_count, security_count, platform_count
  FROM public."SastRuleBundleRollbackReceiptApproval" binding
  JOIN public."SastRuleBundleRollbackApproval" approval
    ON approval."id" = binding."approvalId"
   AND approval."approvalDigest" = binding."approvalDigest"
   AND approval."commandId" = binding."commandId"
   AND approval."commandDigest" = binding."commandDigest"
   AND approval."role" = binding."role"
   AND approval."approverRef" = binding."approverRef"
   AND approval."approvedAt" = binding."approvedAt"
  WHERE binding."receiptId" = NEW."id"
    AND binding."commandId" = NEW."commandId"
    AND binding."commandDigest" = NEW."commandDigest"
    AND binding."approvedAt" >= NEW."commandedAt"
    AND binding."approvedAt" <= NEW."requestedAt"
    AND binding."approverRef" <> NEW."actorRef"
    AND approval."approved" IS TRUE
    AND approval."humanApproval" IS TRUE
    AND approval."automatedApproval" IS FALSE
    AND approval."customerInputAccepted" IS FALSE;
  IF approval_count <> 2 OR security_count <> 1 OR platform_count <> 1
     OR NOT EXISTS (
       SELECT 1 FROM public."SastRuleBundleRollbackReceiptApproval"
       WHERE "receiptId" = NEW."id" AND "position" = 0 AND "role" = 'SECURITY_ENGINEERING'
     )
     OR NOT EXISTS (
       SELECT 1 FROM public."SastRuleBundleRollbackReceiptApproval"
       WHERE "receiptId" = NEW."id" AND "position" = 1 AND "role" IN ('SCAN_PLATFORM','SECURITY_OPERATIONS')
     ) THEN
    RAISE EXCEPTION 'SAST rollback receipt requires exact fresh independent dual approval';
  END IF;

  SELECT '[' || string_agg(
    '{"approvalDigest":' || to_json(binding."approvalDigest")::TEXT
    || ',"approvalId":' || to_json(binding."approvalId")::TEXT
    || ',"approvedAt":' || to_json(to_char(binding."approvedAt", 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::TEXT
    || ',"approverRef":' || to_json(binding."approverRef")::TEXT
    || ',"role":' || to_json(binding."role")::TEXT || '}',
    ',' ORDER BY binding."position"
  ) || ']' INTO actual_set_json
  FROM public."SastRuleBundleRollbackReceiptApproval" binding
  WHERE binding."receiptId" = NEW."id";
  actual_set_digest := 'sha256:' || encode(sha256(convert_to(actual_set_json, 'UTF8')), 'hex');
  IF actual_set_digest IS DISTINCT FROM NEW."approvalSetDigest" THEN
    RAISE EXCEPTION 'SAST rollback receipt approval-set digest is invalid';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION "enforce_sast_rule_bundle_rollback_lifecycle_authority"()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  receipt_record RECORD;
  candidate_head RECORD;
  baseline_head RECORD;
  locked_count INTEGER;
  approval_count INTEGER;
BEGIN
  IF NEW."externalAuthority" <> 'ROLLBACK' THEN
    IF NEW."fromState" = 'SUSPENDED' AND NEW."toState" = 'ROLLED_BACK' THEN
      RAISE EXCEPTION 'SAST rollback lifecycle edge requires rollback authority';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW."fromState" <> 'SUSPENDED' OR NEW."toState" <> 'ROLLED_BACK' THEN
    RAISE EXCEPTION 'SAST rollback authority cannot authorize another lifecycle edge';
  END IF;

  SELECT * INTO receipt_record FROM public."SastRuleBundleRollbackReceipt"
  WHERE "id" = NEW."externalAuthorityReceiptRef"
    AND "receiptDigest" = NEW."externalAuthorityReceiptDigest"
    AND "candidateManifestId" = NEW."manifestId"
    AND "candidateManifestDigest" = NEW."manifestDigest"
    AND "candidateBundleId" = NEW."bundleId"
    AND "candidateBundleDigest" = NEW."bundleDigest"
    AND "promotionEvidenceId" = NEW."promotionEvidenceId"
    AND "promotionEvidenceDigest" = NEW."promotionEvidenceDigest"
    AND "actorRef" = NEW."actorRef"
    AND "reasonRef" = NEW."reasonRef"
    AND "auditRef" = NEW."auditRef"
    AND "requestedAt" = NEW."transitionedAt"
    AND "fromState" = NEW."fromState" AND "toState" = NEW."toState";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SAST rollback lifecycle authority receipt is unavailable';
  END IF;

  PERFORM 1 FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" IN (receipt_record."candidateManifestId", receipt_record."baselineManifestId")
  ORDER BY "manifestId" COLLATE "C" FOR UPDATE;
  GET DIAGNOSTICS locked_count = ROW_COUNT;
  IF locked_count <> 2 THEN
    RAISE EXCEPTION 'SAST rollback lifecycle candidate or baseline head is unavailable';
  END IF;
  SELECT * INTO candidate_head FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" = receipt_record."candidateManifestId";
  SELECT * INTO baseline_head FROM public."SastRuleBundleLifecycleHead"
  WHERE "manifestId" = receipt_record."baselineManifestId";

  IF candidate_head."lifecycleState" IS DISTINCT FROM 'SUSPENDED'
     OR candidate_head."transitionId" IS DISTINCT FROM receipt_record."suspendedTransitionId"
     OR candidate_head."transitionDigest" IS DISTINCT FROM receipt_record."suspendedTransitionDigest"
     OR candidate_head."sequence" IS DISTINCT FROM receipt_record."suspendedSequence"
     OR candidate_head."manifestDigest" IS DISTINCT FROM receipt_record."candidateManifestDigest"
     OR candidate_head."bundleId" IS DISTINCT FROM receipt_record."candidateBundleId"
     OR candidate_head."bundleDigest" IS DISTINCT FROM receipt_record."candidateBundleDigest"
     OR candidate_head."promotionEvidenceId" IS DISTINCT FROM receipt_record."promotionEvidenceId"
     OR candidate_head."promotionEvidenceDigest" IS DISTINCT FROM receipt_record."promotionEvidenceDigest"
     OR NEW."previousTransitionId" IS DISTINCT FROM receipt_record."suspendedTransitionId"
     OR NEW."previousTransitionDigest" IS DISTINCT FROM receipt_record."suspendedTransitionDigest"
     OR NEW."sequence" IS DISTINCT FROM receipt_record."suspendedSequence" + 1 THEN
    RAISE EXCEPTION 'SAST rollback candidate changed before lifecycle commit';
  END IF;
  IF baseline_head."lifecycleState" IS DISTINCT FROM 'ACTIVE'
     OR baseline_head."transitionId" IS DISTINCT FROM receipt_record."baselineTransitionId"
     OR baseline_head."transitionDigest" IS DISTINCT FROM receipt_record."baselineTransitionDigest"
     OR baseline_head."sequence" IS DISTINCT FROM receipt_record."baselineSequence"
     OR baseline_head."transitionedAt" IS DISTINCT FROM receipt_record."baselineTransitionedAt"
     OR baseline_head."manifestDigest" IS DISTINCT FROM receipt_record."baselineManifestDigest"
     OR baseline_head."bundleId" IS DISTINCT FROM receipt_record."baselineBundleId"
     OR baseline_head."bundleDigest" IS DISTINCT FROM receipt_record."baselineBundleDigest" THEN
    RAISE EXCEPTION 'SAST rollback baseline changed before lifecycle commit';
  END IF;
  SELECT count(*) INTO approval_count
  FROM public."SastRuleBundleRollbackReceiptApproval"
  WHERE "receiptId" = receipt_record."id";
  IF approval_count <> 2 THEN
    RAISE EXCEPTION 'SAST rollback approval set is incomplete at lifecycle commit';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "SastRuleBundleRollbackCommand_state" BEFORE INSERT ON "SastRuleBundleRollbackCommand"
  FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_rollback_command_state"();
CREATE CONSTRAINT TRIGGER "SastRuleBundleRollbackCommand_verification" AFTER INSERT ON "SastRuleBundleRollbackCommand"
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_rollback_command_verification"();
CREATE TRIGGER "SastRuleBundleRollbackApproval_binding" BEFORE INSERT ON "SastRuleBundleRollbackApproval"
  FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_rollback_approval"();
CREATE TRIGGER "SastRuleBundleRollbackReceipt_state" BEFORE INSERT ON "SastRuleBundleRollbackReceipt"
  FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_rollback_receipt_state"();
CREATE CONSTRAINT TRIGGER "SastRuleBundleRollbackReceipt_approvals" AFTER INSERT ON "SastRuleBundleRollbackReceipt"
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_rollback_receipt_approvals"();
CREATE TRIGGER "SastRuleBundleLifecycleTransition_rollback_authority" BEFORE INSERT ON "SastRuleBundleLifecycleTransition"
  FOR EACH ROW EXECUTE FUNCTION "enforce_sast_rule_bundle_rollback_lifecycle_authority"();

CREATE TRIGGER "SastRuleBundleRollbackCommand_immutable_update" BEFORE UPDATE ON "SastRuleBundleRollbackCommand" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackCommand_immutable_delete" BEFORE DELETE ON "SastRuleBundleRollbackCommand" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackCommand_immutable_truncate" BEFORE TRUNCATE ON "SastRuleBundleRollbackCommand" FOR EACH STATEMENT EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackVerification_immutable_update" BEFORE UPDATE ON "SastRuleBundleRollbackVerification" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackVerification_immutable_delete" BEFORE DELETE ON "SastRuleBundleRollbackVerification" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackVerification_immutable_truncate" BEFORE TRUNCATE ON "SastRuleBundleRollbackVerification" FOR EACH STATEMENT EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackApproval_immutable_update" BEFORE UPDATE ON "SastRuleBundleRollbackApproval" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackApproval_immutable_delete" BEFORE DELETE ON "SastRuleBundleRollbackApproval" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackApproval_immutable_truncate" BEFORE TRUNCATE ON "SastRuleBundleRollbackApproval" FOR EACH STATEMENT EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackReceipt_immutable_update" BEFORE UPDATE ON "SastRuleBundleRollbackReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackReceipt_immutable_delete" BEFORE DELETE ON "SastRuleBundleRollbackReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackReceipt_immutable_truncate" BEFORE TRUNCATE ON "SastRuleBundleRollbackReceipt" FOR EACH STATEMENT EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackReceiptApproval_immutable_update" BEFORE UPDATE ON "SastRuleBundleRollbackReceiptApproval" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackReceiptApproval_immutable_delete" BEFORE DELETE ON "SastRuleBundleRollbackReceiptApproval" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleRollbackReceiptApproval_immutable_truncate" BEFORE TRUNCATE ON "SastRuleBundleRollbackReceiptApproval" FOR EACH STATEMENT EXECUTE FUNCTION "reject_sast_rule_bundle_rollback_ledger_mutation"();

COMMENT ON TABLE "SastRuleBundleRollbackCommand" IS 'T050 signed rollback command whose last-known-good target is derived only from original T047 promotion evidence.';
COMMENT ON TABLE "SastRuleBundleRollbackApproval" IS 'T050 fresh independent Security Engineering plus Scan Platform or Security Operations human approval ledger.';
COMMENT ON TABLE "SastRuleBundleRollbackReceipt" IS 'T050 content-free rollback authority receipt; it authorizes only SUSPENDED to ROLLED_BACK and never mutates the baseline or historical records.';
