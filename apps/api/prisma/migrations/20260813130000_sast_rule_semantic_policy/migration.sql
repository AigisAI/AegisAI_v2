-- T046 stores immutable platform rule semantics and tenant-scoped,
-- non-executable policy metadata. Rule bodies, repository/source/evidence,
-- arbitrary configuration, credentials, and secret values are absent.

-- The v2 planning key adds the verified tenant-policy receipt. Existing v1
-- planning identities cannot be rewritten safely, so deployment must first
-- drain or explicitly cancel every non-terminal v1 plan/reservation. Terminal
-- rows remain immutable audit history.
DO $t046_canonical_key_cutover$
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
      'T046 canonical scan-key v2 cutover requires all existing v1 SAST plans and reservations to be completed, failed, or canceled';
  END IF;
END;
$t046_canonical_key_cutover$;

CREATE UNIQUE INDEX "SastRuleBundleManifest_id_digest_key"
  ON "SastRuleBundleManifest"("id", "manifestDigest");
CREATE UNIQUE INDEX "SastRuleBundleManifest_metadata_binding_key"
  ON "SastRuleBundleManifest"("id", "manifestDigest", "bundleId", "bundleDigest", "scanner");
CREATE UNIQUE INDEX "SastRuleBundleManifestRule_metadata_binding_key"
  ON "SastRuleBundleManifestRule"("manifestId", "ruleId", "ruleRevision", "ruleSemanticId", "metadataDigest");
CREATE UNIQUE INDEX "Waiver_id_tenantId_key" ON "Waiver"("id", "tenantId");
CREATE UNIQUE INDEX "Suppression_id_tenantId_key" ON "Suppression"("id", "tenantId");

CREATE TABLE "SastRuleSemanticIdentity" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "semanticRuleId" TEXT NOT NULL,
  "semanticIdentityDigest" TEXT NOT NULL,
  "capability" TEXT NOT NULL,
  "category" TEXT NOT NULL,
  "languageCount" INTEGER NOT NULL,
  "formatCount" INTEGER NOT NULL,
  "vulnerabilityPredicateRef" TEXT NOT NULL,
  "sourceKindCount" INTEGER NOT NULL,
  "sinkKindCount" INTEGER NOT NULL,
  "defaultSeverity" "Severity" NOT NULL,
  "defaultConfidence" TEXT NOT NULL,
  "findingIdentityRef" TEXT NOT NULL,
  "tenantControl" TEXT NOT NULL,
  "source" TEXT NOT NULL DEFAULT 'PLATFORM_MANAGED',
  "immutable" BOOLEAN NOT NULL DEFAULT true,
  "executableRuleContentStored" BOOLEAN NOT NULL DEFAULT false,
  "customerSourceStored" BOOLEAN NOT NULL DEFAULT false,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleSemanticIdentity_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleSemanticIdentity_contract_check" CHECK (
    "id" ~ '^sast-rule-semantic-identity://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-semantic-identity-v1'
    AND "semanticRuleId" ~ '^[a-z0-9][a-z0-9._:-]{0,255}$'
    AND "semanticIdentityDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-semantic-identity://' || substring("semanticIdentityDigest" FROM 8)
    AND "capability" IN ('SAST', 'SECRET_DETECTION', 'IAC_MISCONFIGURATION')
    AND "category" ~ '^[A-Z][A-Z0-9_]{0,127}$'
    AND "languageCount" BETWEEN 0 AND 32
    AND "formatCount" BETWEEN 0 AND 32
    AND "languageCount" + "formatCount" > 0
    AND "sourceKindCount" BETWEEN 0 AND 64
    AND "sinkKindCount" BETWEEN 0 AND 64
    AND "defaultConfidence" IN ('HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
    AND "tenantControl" IN ('MANDATORY', 'OPTIONAL')
    AND "vulnerabilityPredicateRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "findingIdentityRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "vulnerabilityPredicateRef" !~ '^https?://'
    AND "findingIdentityRef" !~ '^https?://'
    AND "source" = 'PLATFORM_MANAGED'
    AND "immutable" IS TRUE
    AND "executableRuleContentStored" IS FALSE
    AND "customerSourceStored" IS FALSE
    AND "secretValueStored" IS FALSE
  )
);

CREATE TABLE "SastRuleSemanticIdentityValue" (
  "semanticIdentityId" TEXT NOT NULL,
  "kind" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "value" TEXT NOT NULL,

  CONSTRAINT "SastRuleSemanticIdentityValue_pkey" PRIMARY KEY ("semanticIdentityId", "kind", "position"),
  CONSTRAINT "SastRuleSemanticIdentityValue_contract_check" CHECK (
    "kind" IN ('LANGUAGE', 'FORMAT', 'SOURCE_KIND', 'SINK_KIND')
    AND "position" BETWEEN 0 AND 63
    AND octet_length("value") BETWEEN 1 AND 256
    AND (
      ("kind" IN ('LANGUAGE', 'FORMAT') AND "value" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$')
      OR ("kind" IN ('SOURCE_KIND', 'SINK_KIND') AND "value" ~ '^[A-Z][A-Z0-9_.:-]{0,127}$')
    )
  )
);

CREATE TABLE "SastRuleDefinitionMetadata" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "metadataDigest" TEXT NOT NULL,
  "scanner" TEXT NOT NULL,
  "ruleId" TEXT NOT NULL,
  "ruleRevision" TEXT NOT NULL,
  "semanticRuleId" TEXT NOT NULL,
  "semanticIdentityId" TEXT NOT NULL,
  "semanticIdentityDigest" TEXT NOT NULL,
  "ownerRef" TEXT NOT NULL,
  "cweCount" INTEGER NOT NULL,
  "owaspMappingCount" INTEGER NOT NULL,
  "documentationRef" TEXT NOT NULL,
  "fixtureRefCount" INTEGER NOT NULL,
  "introducedInBundleVersion" TEXT NOT NULL,
  "firstSupportedScannerVersion" TEXT NOT NULL,
  "lastSupportedScannerVersion" TEXT,
  "deprecationState" TEXT NOT NULL,
  "replacementSemanticRuleId" TEXT,
  "source" TEXT NOT NULL DEFAULT 'PLATFORM_MANAGED',
  "immutable" BOOLEAN NOT NULL DEFAULT true,
  "executableRuleContentStored" BOOLEAN NOT NULL DEFAULT false,
  "customerExecutableConfigAllowed" BOOLEAN NOT NULL DEFAULT false,
  "customerSourceStored" BOOLEAN NOT NULL DEFAULT false,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleDefinitionMetadata_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleDefinitionMetadata_contract_check" CHECK (
    "id" ~ '^sast-rule-definition-metadata://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-definition-metadata-v1'
    AND "metadataDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-definition-metadata://' || substring("metadataDigest" FROM 8)
    AND "scanner" IN ('OPENGREP', 'TRIVY')
    AND octet_length("ruleId") BETWEEN 1 AND 256
    AND octet_length("ruleRevision") BETWEEN 1 AND 256
    AND "semanticRuleId" ~ '^[a-z0-9][a-z0-9._:-]{0,255}$'
    AND "semanticIdentityId" ~ '^sast-rule-semantic-identity://[a-f0-9]{64}$'
    AND "semanticIdentityDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "ownerRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "ownerRef" !~ '^https?://'
    AND "cweCount" BETWEEN 0 AND 64
    AND "owaspMappingCount" BETWEEN 0 AND 64
    AND "fixtureRefCount" BETWEEN 1 AND 64
    AND "documentationRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "documentationRef" !~ '^https?://'
    AND "introducedInBundleVersion" ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$'
    AND "firstSupportedScannerVersion" ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$'
    AND ("lastSupportedScannerVersion" IS NULL OR "lastSupportedScannerVersion" ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$')
    AND octet_length("introducedInBundleVersion") BETWEEN 1 AND 256
    AND octet_length("firstSupportedScannerVersion") BETWEEN 1 AND 256
    AND ("lastSupportedScannerVersion" IS NULL OR octet_length("lastSupportedScannerVersion") BETWEEN 1 AND 256)
    AND "deprecationState" IN ('ACTIVE', 'DEPRECATED', 'RETIRED')
    AND (
      ("deprecationState" = 'ACTIVE' AND "replacementSemanticRuleId" IS NULL)
      OR ("deprecationState" = 'DEPRECATED' AND ("replacementSemanticRuleId" IS NULL OR ("replacementSemanticRuleId" ~ '^[a-z0-9][a-z0-9._:-]{0,255}$' AND "replacementSemanticRuleId" <> "semanticRuleId")))
      OR ("deprecationState" = 'RETIRED' AND "replacementSemanticRuleId" ~ '^[a-z0-9][a-z0-9._:-]{0,255}$' AND "replacementSemanticRuleId" <> "semanticRuleId")
    )
    AND "source" = 'PLATFORM_MANAGED'
    AND "immutable" IS TRUE
    AND "executableRuleContentStored" IS FALSE
    AND "customerExecutableConfigAllowed" IS FALSE
    AND "customerSourceStored" IS FALSE
    AND "secretValueStored" IS FALSE
  )
);

CREATE TABLE "SastRuleDefinitionMetadataValue" (
  "metadataId" TEXT NOT NULL,
  "kind" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "value" TEXT NOT NULL,

  CONSTRAINT "SastRuleDefinitionMetadataValue_pkey" PRIMARY KEY ("metadataId", "kind", "position"),
  CONSTRAINT "SastRuleDefinitionMetadataValue_contract_check" CHECK (
    "kind" IN ('CWE', 'OWASP', 'FIXTURE')
    AND "position" BETWEEN 0 AND 63
    AND octet_length("value") BETWEEN 1 AND 2048
    AND (
      ("kind" = 'CWE' AND "value" ~ '^CWE-[1-9][0-9]{0,8}$')
      OR ("kind" = 'OWASP' AND "value" ~ '^OWASP-[A-Z0-9][A-Z0-9._:-]{0,127}$')
      OR ("kind" = 'FIXTURE' AND "value" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$' AND "value" !~ '^https?://')
    )
  )
);

CREATE TABLE "SastRuleDefinitionMetadataBinding" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "bindingDigest" TEXT NOT NULL,
  "manifestId" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "bundleId" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "scanner" TEXT NOT NULL,
  "ruleId" TEXT NOT NULL,
  "ruleRevision" TEXT NOT NULL,
  "semanticRuleId" TEXT NOT NULL,
  "metadataId" TEXT NOT NULL,
  "metadataDigest" TEXT NOT NULL,
  "semanticIdentityDigest" TEXT NOT NULL,
  "source" TEXT NOT NULL DEFAULT 'PLATFORM_MANAGED',
  "immutable" BOOLEAN NOT NULL DEFAULT true,
  "executableRuleContentStored" BOOLEAN NOT NULL DEFAULT false,
  "customerExecutableConfigAllowed" BOOLEAN NOT NULL DEFAULT false,
  "customerSourceStored" BOOLEAN NOT NULL DEFAULT false,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastRuleDefinitionMetadataBinding_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastRuleDefinitionMetadataBinding_contract_check" CHECK (
    "id" ~ '^sast-rule-definition-metadata-binding://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-rule-definition-metadata-binding-v1'
    AND "bindingDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-rule-definition-metadata-binding://' || substring("bindingDigest" FROM 8)
    AND "manifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "bundleId" ~ '^sast-rule-bundle://(opengrep|trivy)/[a-z0-9][a-z0-9._-]{0,127}$'
    AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "scanner" IN ('OPENGREP', 'TRIVY')
    AND octet_length("ruleId") BETWEEN 1 AND 256
    AND octet_length("ruleRevision") BETWEEN 1 AND 256
    AND "semanticRuleId" ~ '^[a-z0-9][a-z0-9._:-]{0,255}$'
    AND "metadataId" ~ '^sast-rule-definition-metadata://[a-f0-9]{64}$'
    AND "metadataDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "semanticIdentityDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "source" = 'PLATFORM_MANAGED'
    AND "immutable" IS TRUE
    AND "executableRuleContentStored" IS FALSE
    AND "customerExecutableConfigAllowed" IS FALSE
    AND "customerSourceStored" IS FALSE
    AND "secretValueStored" IS FALSE
  )
);

CREATE TABLE "SastTenantRulePolicy" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "policyVersion" TEXT NOT NULL,
  "policyDigest" TEXT NOT NULL,
  "effectiveAt" TIMESTAMP(3) NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "categoryDecisionCount" INTEGER NOT NULL,
  "categoryDecisionDigest" TEXT NOT NULL,
  "ruleDecisionCount" INTEGER NOT NULL,
  "ruleDecisionDigest" TEXT NOT NULL,
  "pathExclusionCount" INTEGER NOT NULL,
  "pathExclusionDigest" TEXT NOT NULL,
  "dashboardSeverityFloor" "Severity" NOT NULL,
  "publicationSeverityFloor" "Severity" NOT NULL,
  "repositoryOverrideCount" INTEGER NOT NULL,
  "repositoryOverrideDigest" TEXT NOT NULL,
  "approvedWaiverRefCount" INTEGER NOT NULL,
  "approvedSuppressionRefCount" INTEGER NOT NULL,
  "approvedReferenceDigest" TEXT NOT NULL,
  "actorRef" TEXT NOT NULL,
  "auditRef" TEXT NOT NULL,
  "source" TEXT NOT NULL DEFAULT 'TENANT_ADMIN_METADATA',
  "immutable" BOOLEAN NOT NULL DEFAULT true,
  "executableRulesAccepted" BOOLEAN NOT NULL DEFAULT false,
  "cliFlagsAccepted" BOOLEAN NOT NULL DEFAULT false,
  "pluginsAccepted" BOOLEAN NOT NULL DEFAULT false,
  "arbitraryConfigurationAccepted" BOOLEAN NOT NULL DEFAULT false,
  "customerSourceStored" BOOLEAN NOT NULL DEFAULT false,
  "secretValueStored" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastTenantRulePolicy_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastTenantRulePolicy_contract_check" CHECK (
    "id" ~ '^sast-tenant-rule-policy://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-tenant-rule-policy-v1'
    AND "policyDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-tenant-rule-policy://' || substring("policyDigest" FROM 8)
    AND octet_length("tenantId") BETWEEN 1 AND 256
    AND "tenantId" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
    AND "policyVersion" ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    AND "expiresAt" > "effectiveAt"
    AND "expiresAt" <= "effectiveAt" + INTERVAL '366 days'
    AND "categoryDecisionCount" BETWEEN 0 AND 256
    AND "ruleDecisionCount" BETWEEN 0 AND 25000
    AND "pathExclusionCount" BETWEEN 0 AND 256
    AND "repositoryOverrideCount" BETWEEN 0 AND 256
    AND "approvedWaiverRefCount" BETWEEN 0 AND 1024
    AND "approvedSuppressionRefCount" BETWEEN 0 AND 1024
    AND "categoryDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "ruleDecisionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "pathExclusionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "repositoryOverrideDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "approvedReferenceDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "publicationSeverityFloor" <= "dashboardSeverityFloor"
    AND "publicationSeverityFloor" <= 'MEDIUM'::"Severity"
    AND octet_length("actorRef") BETWEEN 1 AND 2048
    AND "actorRef" ~ '^(user|service|tenant-admin)://[^[:space:]]+$'
    AND "auditRef" ~ '^[a-z][a-z0-9+.-]*://[^[:space:]]+/sha256:[a-f0-9]{64}$'
    AND "auditRef" !~ '^https?://'
    AND "source" = 'TENANT_ADMIN_METADATA'
    AND "immutable" IS TRUE
    AND "executableRulesAccepted" IS FALSE
    AND "cliFlagsAccepted" IS FALSE
    AND "pluginsAccepted" IS FALSE
    AND "arbitraryConfigurationAccepted" IS FALSE
    AND "customerSourceStored" IS FALSE
    AND "secretValueStored" IS FALSE
  )
);

CREATE TABLE "SastTenantRulePolicyDecision" (
  "policyId" TEXT NOT NULL,
  "kind" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "target" TEXT NOT NULL,
  "state" TEXT NOT NULL,

  CONSTRAINT "SastTenantRulePolicyDecision_pkey" PRIMARY KEY ("policyId", "kind", "position"),
  CONSTRAINT "SastTenantRulePolicyDecision_contract_check" CHECK (
    "kind" IN ('CATEGORY', 'RULE')
    AND "state" IN ('ENABLED', 'DISABLED')
    AND "position" BETWEEN 0 AND 24999
    AND (
      ("kind" = 'CATEGORY' AND "target" ~ '^[A-Z][A-Z0-9_]{0,127}$')
      OR ("kind" = 'RULE' AND "target" ~ '^[a-z0-9][a-z0-9._:-]{0,255}$')
    )
  )
);

CREATE TABLE "SastTenantRulePolicyPathExclusion" (
  "policyId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "pathPrefix" TEXT NOT NULL,

  CONSTRAINT "SastTenantRulePolicyPathExclusion_pkey" PRIMARY KEY ("policyId", "position"),
  CONSTRAINT "SastTenantRulePolicyPathExclusion_contract_check" CHECK (
    "position" BETWEEN 0 AND 255
    AND octet_length("pathPrefix") BETWEEN 1 AND 1024
    AND "pathPrefix" !~ '^/'
    AND "pathPrefix" !~ '/$'
    AND "pathPrefix" !~ '(^|/)\.\.?(/|$)'
    AND "pathPrefix" !~ '[\\*?\[\]{}()|]'
  )
);

CREATE TABLE "SastTenantRulePolicyRepositoryOverride" (
  "policyId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "categoryDecisionCount" INTEGER NOT NULL,
  "ruleDecisionCount" INTEGER NOT NULL,
  "pathExclusionCount" INTEGER NOT NULL,
  "dashboardSeverityFloor" "Severity" NOT NULL,
  "publicationSeverityFloor" "Severity" NOT NULL,

  CONSTRAINT "SastTenantRulePolicyRepositoryOverride_pkey" PRIMARY KEY ("policyId", "repositoryBindingId"),
  CONSTRAINT "SastTenantRulePolicyRepositoryOverride_contract_check" CHECK (
    "position" BETWEEN 0 AND 255
    AND "categoryDecisionCount" BETWEEN 0 AND 256
    AND "ruleDecisionCount" BETWEEN 0 AND 25000
    AND "pathExclusionCount" BETWEEN 0 AND 256
    AND "publicationSeverityFloor" <= "dashboardSeverityFloor"
    AND "publicationSeverityFloor" <= 'MEDIUM'::"Severity"
  )
);

CREATE TABLE "SastTenantRulePolicyRepositoryDecision" (
  "policyId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "kind" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "target" TEXT NOT NULL,
  "state" TEXT NOT NULL,

  CONSTRAINT "SastTenantRulePolicyRepositoryDecision_pkey" PRIMARY KEY ("policyId", "repositoryBindingId", "kind", "position"),
  CONSTRAINT "SastTenantRulePolicyRepositoryDecision_contract_check" CHECK (
    "kind" IN ('CATEGORY', 'RULE')
    AND "state" IN ('ENABLED', 'DISABLED')
    AND "position" BETWEEN 0 AND 24999
    AND (
      ("kind" = 'CATEGORY' AND "target" ~ '^[A-Z][A-Z0-9_]{0,127}$')
      OR ("kind" = 'RULE' AND "target" ~ '^[a-z0-9][a-z0-9._:-]{0,255}$')
    )
  )
);

CREATE TABLE "SastTenantRulePolicyRepositoryPathExclusion" (
  "policyId" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "pathPrefix" TEXT NOT NULL,

  CONSTRAINT "SastTenantRulePolicyRepositoryPathExclusion_pkey" PRIMARY KEY ("policyId", "repositoryBindingId", "position"),
  CONSTRAINT "SastTenantRulePolicyRepositoryPath_contract_check" CHECK (
    "position" BETWEEN 0 AND 255
    AND octet_length("pathPrefix") BETWEEN 1 AND 1024
    AND "pathPrefix" !~ '^/'
    AND "pathPrefix" !~ '/$'
    AND "pathPrefix" !~ '(^|/)\.\.?(/|$)'
    AND "pathPrefix" !~ '[\\*?\[\]{}()|]'
  )
);

CREATE TABLE "SastTenantRulePolicyWaiverReference" (
  "policyId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "reference" TEXT NOT NULL,
  "waiverId" TEXT NOT NULL,

  CONSTRAINT "SastTenantRulePolicyWaiverReference_pkey" PRIMARY KEY ("policyId", "position"),
  CONSTRAINT "SastTenantRulePolicyWaiverReference_contract_check" CHECK (
    "position" BETWEEN 0 AND 1023
    AND "reference" ~ '^waiver://[A-Za-z0-9._-]{1,256}$'
    AND "reference" = 'waiver://' || "waiverId"
  )
);

CREATE TABLE "SastTenantRulePolicySuppressionReference" (
  "policyId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "reference" TEXT NOT NULL,
  "suppressionId" TEXT NOT NULL,

  CONSTRAINT "SastTenantRulePolicySuppressionReference_pkey" PRIMARY KEY ("policyId", "position"),
  CONSTRAINT "SastTenantRulePolicySuppressionReference_contract_check" CHECK (
    "position" BETWEEN 0 AND 1023
    AND "reference" ~ '^suppression://[A-Za-z0-9._-]{1,256}$'
    AND "reference" = 'suppression://' || "suppressionId"
  )
);

CREATE TABLE "SastTenantRulePolicyResolution" (
  "id" TEXT NOT NULL,
  "contractVersion" TEXT NOT NULL,
  "receiptIdentityDigest" TEXT NOT NULL,
  "receiptDigest" TEXT NOT NULL,
  "policyId" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "policyVersion" TEXT NOT NULL,
  "policyDigest" TEXT NOT NULL,
  "repositoryBindingId" TEXT NOT NULL,
  "scannerSetDigest" TEXT NOT NULL,
  "profileId" TEXT NOT NULL,
  "profileDigest" TEXT NOT NULL,
  "manifestCount" INTEGER NOT NULL,
  "manifestSetDigest" TEXT NOT NULL,
  "semanticMetadataSetDigest" TEXT NOT NULL,
  "ruleCount" INTEGER NOT NULL,
  "ruleResolutionDigest" TEXT NOT NULL,
  "enabledRuleSetDigest" TEXT NOT NULL,
  "disabledRuleSetDigest" TEXT NOT NULL,
  "pathExclusionCount" INTEGER NOT NULL,
  "pathExclusionDigest" TEXT NOT NULL,
  "dashboardSeverityFloor" "Severity" NOT NULL,
  "publicationSeverityFloor" "Severity" NOT NULL,
  "policyMatched" BOOLEAN NOT NULL DEFAULT true,
  "manifestMetadataMatched" BOOLEAN NOT NULL DEFAULT true,
  "semanticIdentityVerified" BOOLEAN NOT NULL DEFAULT true,
  "mandatoryRulesPreserved" BOOLEAN NOT NULL DEFAULT true,
  "executableConfigurationAccepted" BOOLEAN NOT NULL DEFAULT false,
  "customerInputStored" BOOLEAN NOT NULL DEFAULT false,
  "evaluatedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SastTenantRulePolicyResolution_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "SastTenantRulePolicyResolution_contract_check" CHECK (
    "id" ~ '^sast-tenant-rule-policy-resolution://[a-f0-9]{64}$'
    AND "contractVersion" = 'sast-tenant-rule-policy-resolution-v1'
    AND "receiptIdentityDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "id" = 'sast-tenant-rule-policy-resolution://' || substring("receiptIdentityDigest" FROM 8)
    AND "receiptDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "policyId" ~ '^sast-tenant-rule-policy://[a-f0-9]{64}$'
    AND "policyDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "scannerSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "profileId" IN ('JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1')
    AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "manifestCount" BETWEEN 1 AND 256
    AND "manifestSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "semanticMetadataSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "ruleCount" BETWEEN 1 AND 50000
    AND "ruleResolutionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "enabledRuleSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "disabledRuleSetDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "pathExclusionCount" BETWEEN 0 AND 512
    AND "pathExclusionDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "publicationSeverityFloor" <= "dashboardSeverityFloor"
    AND "publicationSeverityFloor" <= 'MEDIUM'::"Severity"
    AND "policyMatched" IS TRUE
    AND "manifestMetadataMatched" IS TRUE
    AND "semanticIdentityVerified" IS TRUE
    AND "mandatoryRulesPreserved" IS TRUE
    AND "executableConfigurationAccepted" IS FALSE
    AND "customerInputStored" IS FALSE
  )
);

CREATE TABLE "SastTenantRulePolicyResolutionRule" (
  "resolutionId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "bindingId" TEXT NOT NULL,
  "bindingDigest" TEXT NOT NULL,
  "manifestId" TEXT NOT NULL,
  "manifestDigest" TEXT NOT NULL,
  "bundleDigest" TEXT NOT NULL,
  "ruleId" TEXT NOT NULL,
  "ruleRevision" TEXT NOT NULL,
  "semanticRuleId" TEXT NOT NULL,
  "metadataId" TEXT NOT NULL,
  "metadataDigest" TEXT NOT NULL,
  "semanticIdentityDigest" TEXT NOT NULL,
  "category" TEXT NOT NULL,
  "tenantControl" TEXT NOT NULL,
  "state" TEXT NOT NULL,

  CONSTRAINT "SastTenantRulePolicyResolutionRule_pkey" PRIMARY KEY ("resolutionId", "position"),
  CONSTRAINT "SastTenantRulePolicyResolutionRule_contract_check" CHECK (
    "position" BETWEEN 0 AND 49999
    AND "bindingId" ~ '^sast-rule-definition-metadata-binding://[a-f0-9]{64}$'
    AND "bindingDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "manifestId" ~ '^sast-rule-bundle-manifest://[a-f0-9]{64}$'
    AND "manifestDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "bundleDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND octet_length("ruleId") BETWEEN 1 AND 256
    AND octet_length("ruleRevision") BETWEEN 1 AND 256
    AND "semanticRuleId" ~ '^[a-z0-9][a-z0-9._:-]{0,255}$'
    AND "metadataId" ~ '^sast-rule-definition-metadata://[a-f0-9]{64}$'
    AND "metadataDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "semanticIdentityDigest" ~ '^sha256:[a-f0-9]{64}$'
    AND "category" ~ '^[A-Z][A-Z0-9_]{0,127}$'
    AND "tenantControl" IN ('MANDATORY', 'OPTIONAL')
    AND "state" IN ('ENABLED', 'DISABLED')
    AND NOT ("tenantControl" = 'MANDATORY' AND "state" = 'DISABLED')
  )
);

CREATE TABLE "SastTenantRulePolicyResolutionPathExclusion" (
  "resolutionId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "pathPrefix" TEXT NOT NULL,

  CONSTRAINT "SastTenantRulePolicyResolutionPathExclusion_pkey" PRIMARY KEY ("resolutionId", "position"),
  CONSTRAINT "SastTenantRulePolicyResolutionPath_contract_check" CHECK (
    "position" BETWEEN 0 AND 511
    AND octet_length("pathPrefix") BETWEEN 1 AND 1024
    AND "pathPrefix" !~ '^/'
    AND "pathPrefix" !~ '/$'
    AND "pathPrefix" !~ '(^|/)\.\.?(/|$)'
    AND "pathPrefix" !~ '[\\*?\[\]{}()|]'
  )
);

CREATE UNIQUE INDEX "SastRuleSemanticIdentity_semanticRuleId_key" ON "SastRuleSemanticIdentity"("semanticRuleId");
CREATE UNIQUE INDEX "SastRuleSemanticIdentity_semanticIdentityDigest_key" ON "SastRuleSemanticIdentity"("semanticIdentityDigest");
CREATE UNIQUE INDEX "SastRuleSemanticIdentity_binding_key" ON "SastRuleSemanticIdentity"("id", "semanticRuleId", "semanticIdentityDigest");
CREATE UNIQUE INDEX "SastRuleSemanticIdentity_resolution_key" ON "SastRuleSemanticIdentity"("semanticRuleId", "semanticIdentityDigest", "category", "tenantControl");
CREATE INDEX "SastRuleSemanticIdentity_capability_category_idx" ON "SastRuleSemanticIdentity"("capability", "category");
CREATE UNIQUE INDEX "SastRuleSemanticIdentityValue_kind_value_key" ON "SastRuleSemanticIdentityValue"("semanticIdentityId", "kind", "value");
CREATE UNIQUE INDEX "SastRuleDefinitionMetadata_metadataDigest_key" ON "SastRuleDefinitionMetadata"("metadataDigest");
CREATE UNIQUE INDEX "SastRuleDefinitionMetadata_content_binding_key" ON "SastRuleDefinitionMetadata"("id", "metadataDigest", "semanticRuleId", "semanticIdentityDigest");
CREATE INDEX "SastRuleDefinitionMetadata_semanticRuleId_idx" ON "SastRuleDefinitionMetadata"("semanticRuleId");
CREATE UNIQUE INDEX "SastRuleDefinitionMetadataValue_kind_value_key" ON "SastRuleDefinitionMetadataValue"("metadataId", "kind", "value");
CREATE UNIQUE INDEX "SastRuleDefinitionMetadataBinding_bindingDigest_key" ON "SastRuleDefinitionMetadataBinding"("bindingDigest");
CREATE UNIQUE INDEX "SastRuleDefinitionMetadataBinding_manifest_rule_key" ON "SastRuleDefinitionMetadataBinding"("manifestId", "ruleId");
CREATE UNIQUE INDEX "SastRuleDefinitionMetadataBinding_manifest_projection_key" ON "SastRuleDefinitionMetadataBinding"("manifestId", "ruleId", "ruleRevision", "semanticRuleId", "metadataDigest");
CREATE UNIQUE INDEX "SastRuleDefinitionMetadataBinding_resolution_key" ON "SastRuleDefinitionMetadataBinding"("id", "bindingDigest", "manifestId", "manifestDigest", "bundleDigest", "ruleId", "ruleRevision", "metadataId", "metadataDigest", "semanticRuleId", "semanticIdentityDigest");
CREATE INDEX "SastRuleDefinitionMetadataBinding_metadataId_idx" ON "SastRuleDefinitionMetadataBinding"("metadataId");
CREATE INDEX "SastRuleDefinitionMetadataBinding_bundleDigest_idx" ON "SastRuleDefinitionMetadataBinding"("bundleDigest");
CREATE UNIQUE INDEX "SastTenantRulePolicy_policyDigest_key" ON "SastTenantRulePolicy"("policyDigest");
CREATE UNIQUE INDEX "SastTenantRulePolicy_tenant_version_key" ON "SastTenantRulePolicy"("tenantId", "policyVersion");
CREATE UNIQUE INDEX "SastTenantRulePolicy_id_tenant_key" ON "SastTenantRulePolicy"("id", "tenantId");
CREATE UNIQUE INDEX "SastTenantRulePolicy_resolution_binding_key" ON "SastTenantRulePolicy"("id", "tenantId", "policyVersion", "policyDigest");
CREATE INDEX "SastTenantRulePolicy_effective_window_idx" ON "SastTenantRulePolicy"("tenantId", "effectiveAt", "expiresAt");
CREATE UNIQUE INDEX "SastTenantRulePolicyDecision_kind_target_key" ON "SastTenantRulePolicyDecision"("policyId", "kind", "target");
CREATE UNIQUE INDEX "SastTenantRulePolicyPathExclusion_path_key" ON "SastTenantRulePolicyPathExclusion"("policyId", "pathPrefix");
CREATE UNIQUE INDEX "SastTenantRulePolicyRepositoryOverride_position_key" ON "SastTenantRulePolicyRepositoryOverride"("policyId", "position");
CREATE INDEX "SastTenantRulePolicyRepositoryOverride_tenant_repo_idx" ON "SastTenantRulePolicyRepositoryOverride"("tenantId", "repositoryBindingId");
CREATE UNIQUE INDEX "SastTenantRulePolicyRepositoryDecision_target_key" ON "SastTenantRulePolicyRepositoryDecision"("policyId", "repositoryBindingId", "kind", "target");
CREATE UNIQUE INDEX "SastTenantRulePolicyRepositoryPath_path_key" ON "SastTenantRulePolicyRepositoryPathExclusion"("policyId", "repositoryBindingId", "pathPrefix");
CREATE UNIQUE INDEX "SastTenantRulePolicyWaiverReference_reference_key" ON "SastTenantRulePolicyWaiverReference"("policyId", "reference");
CREATE UNIQUE INDEX "SastTenantRulePolicySuppressionReference_reference_key" ON "SastTenantRulePolicySuppressionReference"("policyId", "reference");
CREATE UNIQUE INDEX "SastTenantRulePolicyResolution_receiptDigest_key" ON "SastTenantRulePolicyResolution"("receiptDigest");
CREATE UNIQUE INDEX "SastTenantRulePolicyResolution_receiptIdentityDigest_key" ON "SastTenantRulePolicyResolution"("receiptIdentityDigest");
CREATE UNIQUE INDEX "SastTenantRulePolicyResolution_context_key" ON "SastTenantRulePolicyResolution"("policyId", "repositoryBindingId", "scannerSetDigest", "profileDigest");
CREATE INDEX "SastTenantRulePolicyResolution_tenant_repo_idx" ON "SastTenantRulePolicyResolution"("tenantId", "repositoryBindingId", "evaluatedAt");
CREATE UNIQUE INDEX "SastTenantRulePolicyResolutionRule_manifest_rule_key" ON "SastTenantRulePolicyResolutionRule"("resolutionId", "manifestId", "ruleId");
CREATE INDEX "SastTenantRulePolicyResolutionRule_semantic_state_idx" ON "SastTenantRulePolicyResolutionRule"("semanticRuleId", "state");
CREATE UNIQUE INDEX "SastTenantRulePolicyResolutionPath_path_key" ON "SastTenantRulePolicyResolutionPathExclusion"("resolutionId", "pathPrefix");

ALTER TABLE "SastRuleSemanticIdentityValue" ADD CONSTRAINT "SastRuleSemanticIdentityValue_semanticIdentityId_fkey" FOREIGN KEY ("semanticIdentityId") REFERENCES "SastRuleSemanticIdentity"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleDefinitionMetadata" ADD CONSTRAINT "SastRuleDefinitionMetadata_semantic_identity_fkey" FOREIGN KEY ("semanticIdentityId", "semanticRuleId", "semanticIdentityDigest") REFERENCES "SastRuleSemanticIdentity"("id", "semanticRuleId", "semanticIdentityDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleDefinitionMetadataValue" ADD CONSTRAINT "SastRuleDefinitionMetadataValue_metadataId_fkey" FOREIGN KEY ("metadataId") REFERENCES "SastRuleDefinitionMetadata"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleDefinitionMetadataBinding" ADD CONSTRAINT "SastRuleDefinitionMetadataBinding_manifest_fkey" FOREIGN KEY ("manifestId", "manifestDigest", "bundleId", "bundleDigest", "scanner") REFERENCES "SastRuleBundleManifest"("id", "manifestDigest", "bundleId", "bundleDigest", "scanner") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleDefinitionMetadataBinding" ADD CONSTRAINT "SastRuleDefinitionMetadataBinding_manifest_rule_fkey" FOREIGN KEY ("manifestId", "ruleId", "ruleRevision", "semanticRuleId", "metadataDigest") REFERENCES "SastRuleBundleManifestRule"("manifestId", "ruleId", "ruleRevision", "ruleSemanticId", "metadataDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastRuleDefinitionMetadataBinding" ADD CONSTRAINT "SastRuleDefinitionMetadataBinding_metadata_fkey" FOREIGN KEY ("metadataId", "metadataDigest", "semanticRuleId", "semanticIdentityDigest") REFERENCES "SastRuleDefinitionMetadata"("id", "metadataDigest", "semanticRuleId", "semanticIdentityDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicy" ADD CONSTRAINT "SastTenantRulePolicy_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyDecision" ADD CONSTRAINT "SastTenantRulePolicyDecision_policyId_fkey" FOREIGN KEY ("policyId") REFERENCES "SastTenantRulePolicy"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyPathExclusion" ADD CONSTRAINT "SastTenantRulePolicyPathExclusion_policyId_fkey" FOREIGN KEY ("policyId") REFERENCES "SastTenantRulePolicy"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyRepositoryOverride" ADD CONSTRAINT "SastTenantRulePolicyRepositoryOverride_policy_fkey" FOREIGN KEY ("policyId", "tenantId") REFERENCES "SastTenantRulePolicy"("id", "tenantId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyRepositoryOverride" ADD CONSTRAINT "SastTenantRulePolicyRepositoryOverride_repository_fkey" FOREIGN KEY ("repositoryBindingId", "tenantId") REFERENCES "RepositoryBinding"("id", "tenantId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyRepositoryDecision" ADD CONSTRAINT "SastTenantRulePolicyRepositoryDecision_override_fkey" FOREIGN KEY ("policyId", "repositoryBindingId") REFERENCES "SastTenantRulePolicyRepositoryOverride"("policyId", "repositoryBindingId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyRepositoryPathExclusion" ADD CONSTRAINT "SastTenantRulePolicyRepositoryPath_override_fkey" FOREIGN KEY ("policyId", "repositoryBindingId") REFERENCES "SastTenantRulePolicyRepositoryOverride"("policyId", "repositoryBindingId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyWaiverReference" ADD CONSTRAINT "SastTenantRulePolicyWaiverReference_policy_fkey" FOREIGN KEY ("policyId", "tenantId") REFERENCES "SastTenantRulePolicy"("id", "tenantId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyWaiverReference" ADD CONSTRAINT "SastTenantRulePolicyWaiverReference_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyWaiverReference" ADD CONSTRAINT "SastTenantRulePolicyWaiverReference_waiver_fkey" FOREIGN KEY ("waiverId", "tenantId") REFERENCES "Waiver"("id", "tenantId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicySuppressionReference" ADD CONSTRAINT "SastTenantRulePolicySuppressionReference_policy_fkey" FOREIGN KEY ("policyId", "tenantId") REFERENCES "SastTenantRulePolicy"("id", "tenantId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicySuppressionReference" ADD CONSTRAINT "SastTenantRulePolicySuppressionReference_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicySuppressionReference" ADD CONSTRAINT "SastTenantRulePolicySuppressionReference_suppression_fkey" FOREIGN KEY ("suppressionId", "tenantId") REFERENCES "Suppression"("id", "tenantId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyResolution" ADD CONSTRAINT "SastTenantRulePolicyResolution_policy_fkey" FOREIGN KEY ("policyId", "tenantId", "policyVersion", "policyDigest") REFERENCES "SastTenantRulePolicy"("id", "tenantId", "policyVersion", "policyDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyResolution" ADD CONSTRAINT "SastTenantRulePolicyResolution_repository_fkey" FOREIGN KEY ("repositoryBindingId", "tenantId") REFERENCES "RepositoryBinding"("id", "tenantId") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyResolutionRule" ADD CONSTRAINT "SastTenantRulePolicyResolutionRule_resolutionId_fkey" FOREIGN KEY ("resolutionId") REFERENCES "SastTenantRulePolicyResolution"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyResolutionRule" ADD CONSTRAINT "SastTenantRulePolicyResolutionRule_metadata_binding_fkey" FOREIGN KEY ("bindingId", "bindingDigest", "manifestId", "manifestDigest", "bundleDigest", "ruleId", "ruleRevision", "metadataId", "metadataDigest", "semanticRuleId", "semanticIdentityDigest") REFERENCES "SastRuleDefinitionMetadataBinding"("id", "bindingDigest", "manifestId", "manifestDigest", "bundleDigest", "ruleId", "ruleRevision", "metadataId", "metadataDigest", "semanticRuleId", "semanticIdentityDigest") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyResolutionRule" ADD CONSTRAINT "SastTenantRulePolicyResolutionRule_semantic_identity_fkey" FOREIGN KEY ("semanticRuleId", "semanticIdentityDigest", "category", "tenantControl") REFERENCES "SastRuleSemanticIdentity"("semanticRuleId", "semanticIdentityDigest", "category", "tenantControl") ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE "SastTenantRulePolicyResolutionPathExclusion" ADD CONSTRAINT "SastTenantRulePolicyResolutionPathExclusion_resolutionId_fkey" FOREIGN KEY ("resolutionId") REFERENCES "SastTenantRulePolicyResolution"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

CREATE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'SAST semantic identity and tenant rule-policy ledgers are immutable';
END;
$$;

CREATE TRIGGER "SastRuleSemanticIdentity_immutable_update" BEFORE UPDATE ON "SastRuleSemanticIdentity" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastRuleSemanticIdentity_immutable_delete" BEFORE DELETE ON "SastRuleSemanticIdentity" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastRuleSemanticIdentityValue_immutable_update" BEFORE UPDATE ON "SastRuleSemanticIdentityValue" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastRuleSemanticIdentityValue_immutable_delete" BEFORE DELETE ON "SastRuleSemanticIdentityValue" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastRuleDefinitionMetadata_immutable_update" BEFORE UPDATE ON "SastRuleDefinitionMetadata" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastRuleDefinitionMetadata_immutable_delete" BEFORE DELETE ON "SastRuleDefinitionMetadata" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastRuleDefinitionMetadataValue_immutable_update" BEFORE UPDATE ON "SastRuleDefinitionMetadataValue" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastRuleDefinitionMetadataValue_immutable_delete" BEFORE DELETE ON "SastRuleDefinitionMetadataValue" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastRuleDefinitionMetadataBinding_immutable_update" BEFORE UPDATE ON "SastRuleDefinitionMetadataBinding" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastRuleDefinitionMetadataBinding_immutable_delete" BEFORE DELETE ON "SastRuleDefinitionMetadataBinding" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicy_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicy" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicy_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicy" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyDecision_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicyDecision" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyDecision_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicyDecision" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyPathExclusion_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicyPathExclusion" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyPathExclusion_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicyPathExclusion" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyRepositoryOverride_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicyRepositoryOverride" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyRepositoryOverride_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicyRepositoryOverride" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyRepositoryDecision_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicyRepositoryDecision" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyRepositoryDecision_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicyRepositoryDecision" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyRepositoryPathExclusion_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicyRepositoryPathExclusion" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyRepositoryPathExclusion_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicyRepositoryPathExclusion" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyWaiverReference_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicyWaiverReference" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyWaiverReference_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicyWaiverReference" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicySuppressionReference_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicySuppressionReference" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicySuppressionReference_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicySuppressionReference" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyResolution_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicyResolution" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyResolution_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicyResolution" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyResolutionRule_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicyResolutionRule" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyResolutionRule_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicyResolutionRule" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyResolutionPathExclusion_immutable_update" BEFORE UPDATE ON "SastTenantRulePolicyResolutionPathExclusion" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();
CREATE TRIGGER "SastTenantRulePolicyResolutionPathExclusion_immutable_delete" BEFORE DELETE ON "SastTenantRulePolicyResolutionPathExclusion" FOR EACH ROW EXECUTE FUNCTION "reject_sast_rule_semantic_policy_ledger_mutation"();

COMMENT ON TABLE "SastRuleSemanticIdentity" IS 'Immutable platform semantic core; unrelated behavior cannot reuse a semantic rule ID.';
COMMENT ON TABLE "SastRuleDefinitionMetadata" IS 'Reusable content-free rule metadata whose digest is independent of any bundle manifest.';
COMMENT ON TABLE "SastRuleDefinitionMetadataBinding" IS 'Immutable byte-exact binding from reusable metadata to a T045 signed manifest rule projection.';
COMMENT ON TABLE "SastTenantRulePolicy" IS 'Tenant-scoped declarative narrowing metadata; executable rules, flags, plugins, arbitrary configuration, source, and secrets are prohibited.';
COMMENT ON TABLE "SastTenantRulePolicyResolution" IS 'Immutable pre-queue policy and semantic-metadata resolution; denied evaluations create no receipt.';
