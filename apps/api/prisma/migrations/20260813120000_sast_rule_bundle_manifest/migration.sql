-- T045 stores only immutable platform-owned rule-bundle metadata, trusted
-- supply-chain verification facts, and exact runtime compatibility receipts.
-- Executable rule content, customer source, signature bytes, provenance
-- payloads, credentials, and secrets are intentionally absent.
CREATE TABLE "SastRuleBundleManifest" (
  "id" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "bundleId" TEXT NOT NULL,
  "bundleVersion" TEXT NOT NULL,
  "lifecycleState" TEXT NOT NULL,
  "scanner" TEXT NOT NULL,
  "builtAt" TIMESTAMP(3) NOT NULL,
  "sourceRevision" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "memberCount" INTEGER NOT NULL,
  "memberSetDigest" TEXT NOT NULL,
  "ruleCount" INTEGER NOT NULL,
  "ruleSetDigest" TEXT NOT NULL,
  "scannerVersionCount" INTEGER NOT NULL,
  "scannerImageDigestCount" INTEGER NOT NULL,
  "wrapperDigestCount" INTEGER NOT NULL,
  "schemaBundleDigestCount" INTEGER NOT NULL,
  "normalizerBundleDigestCount" INTEGER NOT NULL,
  "profileIdCount" INTEGER NOT NULL,
  "compatibilityDigest" TEXT NOT NULL,
  "goldenCorpusResultRef" TEXT NOT NULL,
  "regressionCorpusResultRef" TEXT NOT NULL,
  "maliciousCorpusResultRef" TEXT NOT NULL,
  "performanceCorpusResultRef" TEXT NOT NULL,
  "qualityEvidenceDigest" TEXT NOT NULL,
  "signerIdentity" TEXT NOT NULL,
  "signatureRef" TEXT NOT NULL,
  "provenanceRef" TEXT NOT NULL,
  "compatibilityRef" TEXT NOT NULL,
  "rolloutPolicyRef" TEXT NOT NULL,
  "killSwitchNamespace" TEXT NOT NULL,
  "killSwitchRef" TEXT NOT NULL,
  "rollbackTargetDigest" TEXT NOT NULL,
  "source" TEXT NOT NULL DEFAULT 'PLATFORM_MANAGED',
  "immutable" BOOLEAN NOT NULL DEFAULT true,
  "customerExecutableConfigAllowed" BOOLEAN NOT NULL DEFAULT false,
  "executableRuleContentStored" BOOLEAN NOT NULL DEFAULT false,
  "customerSourceStored" BOOLEAN NOT NULL DEFAULT false,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleBundleManifest_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleManifest_contract_check" CHECK (
    "id" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-manifest://' || substring("manifestDigest" FROM 8)
    AND "contractVersion" = 'sast-rule-bundle-manifest-v1'
    AND "bundleId" ~ '^sast-rule-bundle://(opengrep|trivy)/[a-z0-9][a-z0-9._-]{0,127}$'
    AND "bundleVersion" ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$'
    AND "lifecycleState" IN ('DRAFT', 'VALIDATED', 'CANARY', 'ACTIVE', 'SUSPENDED', 'ROLLED_BACK', 'RETIRED')
    AND "scanner" IN ('OPENGREP', 'TRIVY')
    AND "sourceRevision" ~ '^([a-f0-9]{40}|[a-f0-9]{64})$'
    AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "memberCount" BETWEEN 1 AND 25000
    AND "ruleCount" BETWEEN 1 AND 25000
    AND "scannerVersionCount" BETWEEN 1 AND 64
    AND "scannerImageDigestCount" BETWEEN 1 AND 64
    AND "wrapperDigestCount" BETWEEN 1 AND 64
    AND "schemaBundleDigestCount" BETWEEN 1 AND 64
    AND "normalizerBundleDigestCount" BETWEEN 1 AND 64
    AND "profileIdCount" BETWEEN 1 AND 64
    AND "memberSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "ruleSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "compatibilityDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "qualityEvidenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "rollbackTargetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "rollbackTargetDigest" <> "bundleDigest"
    AND "signerIdentity" ~ '^(spiffe|sast-signer)://[^[:space:]]+$'
    AND "killSwitchNamespace" ~ '^sast-kill-switch://[a-z0-9][a-z0-9._/-]{0,255}$'
    AND "signatureRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "provenanceRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "compatibilityRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "rolloutPolicyRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "killSwitchRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "goldenCorpusResultRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "regressionCorpusResultRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "maliciousCorpusResultRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "performanceCorpusResultRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND NOT (
      "signatureRef" ~ '^https?://'
      OR "provenanceRef" ~ '^https?://'
      OR "compatibilityRef" ~ '^https?://'
      OR "rolloutPolicyRef" ~ '^https?://'
      OR "killSwitchRef" ~ '^https?://'
      OR "goldenCorpusResultRef" ~ '^https?://'
      OR "regressionCorpusResultRef" ~ '^https?://'
      OR "maliciousCorpusResultRef" ~ '^https?://'
      OR "performanceCorpusResultRef" ~ '^https?://'
    )
    AND "source" = 'PLATFORM_MANAGED'
    AND "immutable" IS TRUE
    AND "customerExecutableConfigAllowed" IS FALSE
    AND "executableRuleContentStored" IS FALSE
    AND "customerSourceStored" IS FALSE
    AND "secretValueStored" IS FALSE
  )
);

CREATE TABLE "SastRuleBundleManifestMember" (
  "manifestId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "memberId" TEXT NOT NULL,
  "digest" TEXT NOT NULL,

  CONSTRAINT "SastRuleBundleManifestMember_pkey" PRIMARY KEY ("manifestId", "position"),
  CONSTRAINT "SastRuleBundleManifestMember_contract_check" CHECK (
    "position" BETWEEN 0 AND 24999
    AND octet_length("memberId") BETWEEN 1 AND 512
    AND "memberId" ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$'
    AND "digest" ~ '^sha256:[a-f0-9]{64}$'
  )
);

CREATE TABLE "SastRuleBundleManifestRule" (
  "manifestId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "ruleId" TEXT NOT NULL,
  "ruleRevision" TEXT NOT NULL,
  "ruleSemanticId" TEXT NOT NULL,
  "metadataDigest" TEXT NOT NULL,

  CONSTRAINT "SastRuleBundleManifestRule_pkey" PRIMARY KEY ("manifestId", "position"),
  CONSTRAINT "SastRuleBundleManifestRule_contract_check" CHECK (
    "position" BETWEEN 0 AND 24999
    AND octet_length("ruleId") BETWEEN 1 AND 512
    AND octet_length("ruleRevision") BETWEEN 1 AND 512
    AND octet_length("ruleSemanticId") BETWEEN 1 AND 512
    AND "metadataDigest" ~ '^sha256:[a-f0-9]{64}$'
  )
);

CREATE TABLE "SastRuleBundleCompatibilityEntry" (
  "manifestId" TEXT NOT NULL,
  "kind" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "value" TEXT NOT NULL,

  CONSTRAINT "SastRuleBundleCompatibilityEntry_pkey" PRIMARY KEY ("manifestId", "kind", "position"),
  CONSTRAINT "SastRuleBundleCompatibilityEntry_contract_check" CHECK (
    "kind" IN ('SCANNER_VERSION', 'SCANNER_IMAGE_DIGEST', 'WRAPPER_DIGEST', 'SCHEMA_BUNDLE_DIGEST', 'NORMALIZER_BUNDLE_DIGEST', 'PROFILE_ID')
    AND "position" BETWEEN 0 AND 63
    AND octet_length("value") BETWEEN 1 AND 512
    AND (
      ("kind" = 'SCANNER_VERSION' AND "value" ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$')
      OR ("kind" IN ('SCANNER_IMAGE_DIGEST', 'WRAPPER_DIGEST', 'SCHEMA_BUNDLE_DIGEST', 'NORMALIZER_BUNDLE_DIGEST') AND "value" ~ '^sha256:[a-f0-9]{64}$')
      OR ("kind" = 'PROFILE_ID' AND "value" IN ('JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1'))
    )
  )
);

CREATE TABLE "SastRuleBundleSupplyChainAttestation" (
  "id" TEXT NOT NULL,
  "manifestId" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "memberSetDigest" TEXT NOT NULL,
  "signerIdentity" TEXT NOT NULL,
  "signatureRef" TEXT NOT NULL,
  "provenanceRef" TEXT NOT NULL,
  "signatureVerified" BOOLEAN NOT NULL DEFAULT true,
  "provenanceVerified" BOOLEAN NOT NULL DEFAULT true,
  "trustedSigner" BOOLEAN NOT NULL DEFAULT true,
  "subjectDigestsVerified" BOOLEAN NOT NULL DEFAULT true,
  "signatureBytesStored" BOOLEAN NOT NULL DEFAULT false,
  "provenancePayloadStored" BOOLEAN NOT NULL DEFAULT false,
  "executableRuleContentStored" BOOLEAN NOT NULL DEFAULT false,
  "verifiedAt" TIMESTAMP(3) NOT NULL,
  "attestationDigest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleBundleSupplyChainAttestation_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleSupplyChainAttestation_contract_check" CHECK (
    "id" ~ '^sast-rule-bundle-verification://[a-f0-9]{64}$'
    AND "manifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "id" = 'sast-rule-bundle-verification://' || substring("manifestDigest" FROM 8)
    AND "contractVersion" = 'sast-rule-bundle-supply-chain-attestation-v1'
    AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "memberSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "attestationDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "signerIdentity" ~ '^(spiffe|sast-signer)://[^[:space:]]+$'
    AND "signatureRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "provenanceRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "signatureRef" !~ '^https?://'
    AND "provenanceRef" !~ '^https?://'
    AND "signatureVerified" IS TRUE
    AND "provenanceVerified" IS TRUE
    AND "trustedSigner" IS TRUE
    AND "subjectDigestsVerified" IS TRUE
    AND "signatureBytesStored" IS FALSE
    AND "provenancePayloadStored" IS FALSE
    AND "executableRuleContentStored" IS FALSE
  )
);

CREATE TABLE "SastRuleBundleCompatibilityReceipt" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "manifestId" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "verificationId" TEXT NOT NULL,
  "verificationDigest" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "scannerSetDigest" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "scanner" TEXT NOT NULL,
  "scannerVersion" TEXT NOT NULL,
  "scannerImageDigest" TEXT NOT NULL,
  "wrapperDigest" TEXT NOT NULL,
  "schemaBundleDigest" TEXT NOT NULL,
  "normalizerBundleDigest" TEXT NOT NULL,
  "compatible" BOOLEAN NOT NULL DEFAULT true,
  "manifestProjectionMatched" BOOLEAN NOT NULL DEFAULT true,
  "signatureVerified" BOOLEAN NOT NULL DEFAULT true,
  "provenanceVerified" BOOLEAN NOT NULL DEFAULT true,
  "trustedSigner" BOOLEAN NOT NULL DEFAULT true,
  "customerInputAccepted" BOOLEAN NOT NULL DEFAULT false,
  "executableRuleContentStored" BOOLEAN NOT NULL DEFAULT false,
  "evaluatedAt" TIMESTAMP(3) NOT NULL,
  "receiptDigest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleBundleCompatibilityReceipt_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleBundleCompatibilityReceipt_contract_check" CHECK (
    "id" ~ '^sast-rule-bundle-compatibility://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-bundle-compatibility-receipt-v1'
    AND "manifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "verificationId" ~ '^sast-rule-bundle-verification://[a-f0-9]{64}$'
    AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "verificationDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "scannerSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "scannerImageDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "wrapperDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "schemaBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "normalizerBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "receiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "profileId" IN ('JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1')
    AND "scanner" IN ('OPENGREP', 'TRIVY')
    AND octet_length("scannerVersion") BETWEEN 1 AND 512
    AND "compatible" IS TRUE
    AND "manifestProjectionMatched" IS TRUE
    AND "signatureVerified" IS TRUE
    AND "provenanceVerified" IS TRUE
    AND "trustedSigner" IS TRUE
    AND "customerInputAccepted" IS FALSE
    AND "executableRuleContentStored" IS FALSE
  )
);

CREATE UNIQUE INDEX "SastRuleBundleManifest_manifestDigest_key" ON "SastRuleBundleManifest"("manifestDigest");
CREATE INDEX "SastRuleBundleManifest_bundleId_bundleVersion_idx" ON "SastRuleBundleManifest"("bundleId", "bundleVersion");
CREATE INDEX "SastRuleBundleManifest_scanner_lifecycleState_idx" ON "SastRuleBundleManifest"("scanner", "lifecycleState");
CREATE INDEX "SastRuleBundleManifest_bundleDigest_idx" ON "SastRuleBundleManifest"("bundleDigest");
CREATE UNIQUE INDEX "SastRuleBundleManifestMember_manifestId_memberId_key" ON "SastRuleBundleManifestMember"("manifestId", "memberId");
CREATE UNIQUE INDEX "SastRuleBundleManifestRule_manifestId_ruleId_key" ON "SastRuleBundleManifestRule"("manifestId", "ruleId");
CREATE UNIQUE INDEX "SastRuleBundleCompatibilityEntry_manifestId_kind_value_key" ON "SastRuleBundleCompatibilityEntry"("manifestId", "kind", "value");
CREATE UNIQUE INDEX "SastRuleBundleSupplyChainAttestation_manifestId_key" ON "SastRuleBundleSupplyChainAttestation"("manifestId");
CREATE UNIQUE INDEX "SastRuleBundleSupplyChainAttestation_attestationDigest_key" ON "SastRuleBundleSupplyChainAttestation"("attestationDigest");
CREATE UNIQUE INDEX "SastRuleBundleCompatibilityReceipt_receiptDigest_key" ON "SastRuleBundleCompatibilityReceipt"("receiptDigest");
CREATE UNIQUE INDEX "SastRuleBundleCompatibilityReceipt_manifest_context_key" ON "SastRuleBundleCompatibilityReceipt"("manifestId", "scannerSetDigest", "profileDigest");
CREATE INDEX "SastRuleBundleCompatibilityReceipt_scannerSet_profile_idx" ON "SastRuleBundleCompatibilityReceipt"("scannerSetDigest", "profileId");

ALTER TABLE "SastRuleBundleManifestMember" ADD CONSTRAINT "SastRuleBundleManifestMember_manifestId_fkey" FOREIGN KEY ("manifestId") REFERENCES "SastRuleBundleManifest"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleManifestRule" ADD CONSTRAINT "SastRuleBundleManifestRule_manifestId_fkey" FOREIGN KEY ("manifestId") REFERENCES "SastRuleBundleManifest"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCompatibilityEntry" ADD CONSTRAINT "SastRuleBundleCompatibilityEntry_manifestId_fkey" FOREIGN KEY ("manifestId") REFERENCES "SastRuleBundleManifest"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleSupplyChainAttestation" ADD CONSTRAINT "SastRuleBundleSupplyChainAttestation_manifestId_fkey" FOREIGN KEY ("manifestId") REFERENCES "SastRuleBundleManifest"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCompatibilityReceipt" ADD CONSTRAINT "SastRuleBundleCompatibilityReceipt_manifestId_fkey" FOREIGN KEY ("manifestId") REFERENCES "SastRuleBundleManifest"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleBundleCompatibilityReceipt" ADD CONSTRAINT "SastRuleBundleCompatibilityReceipt_verificationId_fkey" FOREIGN KEY ("verificationId") REFERENCES "SastRuleBundleSupplyChainAttestation"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

CREATE FUNCTION "reject_sast_rule_bundle_ledger_mutation"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'SAST rule-bundle supply-chain ledgers are immutable';
END;
$$;

CREATE TRIGGER "SastRuleBundleManifest_immutable_update" BEFORE UPDATE ON "SastRuleBundleManifest" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleManifest_immutable_delete" BEFORE DELETE ON "SastRuleBundleManifest" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleManifestMember_immutable_update" BEFORE UPDATE ON "SastRuleBundleManifestMember" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleManifestMember_immutable_delete" BEFORE DELETE ON "SastRuleBundleManifestMember" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleManifestRule_immutable_update" BEFORE UPDATE ON "SastRuleBundleManifestRule" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleManifestRule_immutable_delete" BEFORE DELETE ON "SastRuleBundleManifestRule" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleCompatibilityEntry_immutable_update" BEFORE UPDATE ON "SastRuleBundleCompatibilityEntry" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleCompatibilityEntry_immutable_delete" BEFORE DELETE ON "SastRuleBundleCompatibilityEntry" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleSupplyChainAttestation_immutable_update" BEFORE UPDATE ON "SastRuleBundleSupplyChainAttestation" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleSupplyChainAttestation_immutable_delete" BEFORE DELETE ON "SastRuleBundleSupplyChainAttestation" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleCompatibilityReceipt_immutable_update" BEFORE UPDATE ON "SastRuleBundleCompatibilityReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();
CREATE TRIGGER "SastRuleBundleCompatibilityReceipt_immutable_delete" BEFORE DELETE ON "SastRuleBundleCompatibilityReceipt" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_bundle_ledger_mutation"();

COMMENT ON TABLE "SastRuleBundleManifest" IS 'Immutable T045 platform metadata; executable rule content, customer source, credentials, and secrets are prohibited.';
COMMENT ON TABLE "SastRuleBundleSupplyChainAttestation" IS 'Trusted signature and provenance verification facts only; raw signature and provenance payloads are prohibited.';
COMMENT ON TABLE "SastRuleBundleCompatibilityReceipt" IS 'Exact compatible scanner-set/profile binding created before queue reservation; denial attempts create no receipt.';
