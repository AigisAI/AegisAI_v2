-- Production architecture baseline. This migration intentionally precedes the
-- AI advisory metadata migration, whose foreign keys depend on Tenant and ScanRequest.
CREATE TYPE "ScmIntegrationType" AS ENUM ('GITHUB_APP', 'GITLAB_CLOUD_INTEGRATION');
CREATE TYPE "IntegrationStatus" AS ENUM ('ACTIVE', 'REVOKED', 'SUSPENDED');
CREATE TYPE "IntegrationPrincipal" AS ENUM ('REPO_READ', 'COMMENT_WRITE', 'INTEGRATION_ADMIN');
CREATE TYPE "ScanLane" AS ENUM ('FAST', 'DEEP');
CREATE TYPE "ArchitectureScanStatus" AS ENUM ('QUEUED', 'PLANNING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELED');
CREATE TYPE "IsolationClass" AS ENUM ('STANDARD', 'HARDENED', 'RESTRICTED');
CREATE TYPE "ScannerKind" AS ENUM ('OPENGREP', 'TRIVY', 'SYFT', 'MOCK');
CREATE TYPE "ScannerRunStatus" AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT', 'SKIPPED');
CREATE TYPE "NormalizedFindingStatus" AS ENUM ('OPEN', 'ACCEPTED', 'REJECTED', 'WAIVED', 'SUPPRESSED', 'FIXED');
CREATE TYPE "EvidenceClassification" AS ENUM ('SHORT_LIVED_EVIDENCE');
CREATE TYPE "PolicyAction" AS ENUM ('DASHBOARD_ONLY', 'COMMENT', 'WARN', 'TICKET', 'BLOCK');
CREATE TYPE "SuppressionReason" AS ENUM ('STALE_RESULT', 'DUPLICATE', 'POLICY');

CREATE TABLE "Tenant" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "Tenant_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "User" ADD COLUMN "tenantId" TEXT;
INSERT INTO "Tenant" ("id", "slug", "name", "updatedAt")
SELECT "id", 'personal-' || "id", "name" || '''s workspace', CURRENT_TIMESTAMP
FROM "User";
UPDATE "User" SET "tenantId" = "id" WHERE "tenantId" IS NULL;
ALTER TABLE "User" ALTER COLUMN "tenantId" SET NOT NULL;

CREATE TABLE "ScmIntegration" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "provider" "RepoProvider" NOT NULL,
    "integrationType" "ScmIntegrationType" NOT NULL,
    "externalInstallationId" TEXT NOT NULL,
    "repoReadPrincipalId" TEXT NOT NULL,
    "commentWritePrincipalId" TEXT,
    "integrationAdminPrincipalId" TEXT,
    "status" "IntegrationStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "ScmIntegration_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "RepositoryBinding" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "scmIntegrationId" TEXT NOT NULL,
    "providerRepoId" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "defaultBranch" TEXT NOT NULL,
    "isPrivate" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "RepositoryBinding_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ScanRequest" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "repositoryBindingId" TEXT NOT NULL,
    "lane" "ScanLane" NOT NULL,
    "targetRef" TEXT NOT NULL,
    "commitSha" TEXT NOT NULL,
    "policyVersion" TEXT NOT NULL,
    "scannerSetVersion" TEXT NOT NULL,
    "canonicalKey" TEXT NOT NULL,
    "status" "ArchitectureScanStatus" NOT NULL DEFAULT 'QUEUED',
    "isolationClass" "IsolationClass" NOT NULL DEFAULT 'STANDARD',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "ScanRequest_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ScannerRun" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "scanRequestId" TEXT NOT NULL,
    "scanner" "ScannerKind" NOT NULL,
    "scannerVersion" TEXT NOT NULL,
    "status" "ScannerRunStatus" NOT NULL DEFAULT 'QUEUED',
    "rawArtifactObjectKey" TEXT,
    "coverageState" JSONB,
    "errorMessage" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "ScannerRun_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "NormalizedFinding" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "scanRequestId" TEXT NOT NULL,
    "scannerRunId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "scannerProvenance" "ScannerKind" NOT NULL,
    "filePath" TEXT NOT NULL,
    "lineStart" INTEGER NOT NULL,
    "lineEnd" INTEGER,
    "status" "NormalizedFindingStatus" NOT NULL DEFAULT 'OPEN',
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "NormalizedFinding_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "NormalizedFinding_valid_line_range_check" CHECK ("lineStart" > 0 AND ("lineEnd" IS NULL OR "lineEnd" >= "lineStart"))
);

CREATE TABLE "EvidencePack" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "scanRequestId" TEXT NOT NULL,
    "classification" "EvidenceClassification" NOT NULL DEFAULT 'SHORT_LIVED_EVIDENCE',
    "objectKey" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "byteSize" INTEGER NOT NULL,
    "redacted" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "EvidencePack_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "EvidencePack_valid_retention_check" CHECK ("byteSize" >= 0 AND "expiresAt" > "createdAt")
);

CREATE TABLE "PolicyDecision" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "scanRequestId" TEXT NOT NULL,
    "findingId" TEXT,
    "enforcementAction" "PolicyAction" NOT NULL,
    "commentAllowed" BOOLEAN NOT NULL DEFAULT false,
    "dashboardVisible" BOOLEAN NOT NULL DEFAULT true,
    "ticketRequested" BOOLEAN NOT NULL DEFAULT false,
    "blockRequested" BOOLEAN NOT NULL DEFAULT false,
    "reasonCodes" JSONB NOT NULL,
    "requiredCoverage" JSONB NOT NULL,
    "waiverApplied" BOOLEAN NOT NULL DEFAULT false,
    "staleSuppressed" BOOLEAN NOT NULL DEFAULT false,
    "aiAdvisoryVisible" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "PolicyDecision_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Waiver" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "owner" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastReviewedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "Waiver_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Suppression" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "scanRequestId" TEXT NOT NULL,
    "findingId" TEXT,
    "reason" "SuppressionReason" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "Suppression_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "AuditEvent" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "scanRequestId" TEXT,
    "eventType" TEXT NOT NULL,
    "actor" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "metadata" JSONB,
    "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "Tenant_slug_key" ON "Tenant"("slug");
CREATE INDEX "User_tenantId_idx" ON "User"("tenantId");
CREATE INDEX "ScmIntegration_tenantId_idx" ON "ScmIntegration"("tenantId");
CREATE UNIQUE INDEX "ScmIntegration_tenantId_provider_externalInstallationId_key" ON "ScmIntegration"("tenantId", "provider", "externalInstallationId");
CREATE INDEX "RepositoryBinding_tenantId_idx" ON "RepositoryBinding"("tenantId");
CREATE INDEX "RepositoryBinding_scmIntegrationId_idx" ON "RepositoryBinding"("scmIntegrationId");
CREATE UNIQUE INDEX "RepositoryBinding_tenantId_scmIntegrationId_providerRepoId_key" ON "RepositoryBinding"("tenantId", "scmIntegrationId", "providerRepoId");
CREATE UNIQUE INDEX "ScanRequest_canonicalKey_key" ON "ScanRequest"("canonicalKey");
CREATE INDEX "ScanRequest_tenantId_idx" ON "ScanRequest"("tenantId");
CREATE INDEX "ScanRequest_repositoryBindingId_idx" ON "ScanRequest"("repositoryBindingId");
CREATE INDEX "ScanRequest_status_idx" ON "ScanRequest"("status");
CREATE INDEX "ScanRequest_createdAt_idx" ON "ScanRequest"("createdAt" DESC);
CREATE INDEX "ScannerRun_tenantId_idx" ON "ScannerRun"("tenantId");
CREATE INDEX "ScannerRun_scanRequestId_idx" ON "ScannerRun"("scanRequestId");
CREATE INDEX "ScannerRun_scanner_idx" ON "ScannerRun"("scanner");
CREATE INDEX "ScannerRun_status_idx" ON "ScannerRun"("status");
CREATE INDEX "NormalizedFinding_tenantId_idx" ON "NormalizedFinding"("tenantId");
CREATE INDEX "NormalizedFinding_scanRequestId_idx" ON "NormalizedFinding"("scanRequestId");
CREATE INDEX "NormalizedFinding_scannerRunId_idx" ON "NormalizedFinding"("scannerRunId");
CREATE INDEX "NormalizedFinding_severity_idx" ON "NormalizedFinding"("severity");
CREATE INDEX "NormalizedFinding_status_idx" ON "NormalizedFinding"("status");
CREATE INDEX "EvidencePack_tenantId_idx" ON "EvidencePack"("tenantId");
CREATE INDEX "EvidencePack_scanRequestId_idx" ON "EvidencePack"("scanRequestId");
CREATE INDEX "EvidencePack_expiresAt_idx" ON "EvidencePack"("expiresAt");
CREATE INDEX "PolicyDecision_tenantId_idx" ON "PolicyDecision"("tenantId");
CREATE INDEX "PolicyDecision_scanRequestId_idx" ON "PolicyDecision"("scanRequestId");
CREATE INDEX "PolicyDecision_findingId_idx" ON "PolicyDecision"("findingId");
CREATE INDEX "Waiver_tenantId_idx" ON "Waiver"("tenantId");
CREATE INDEX "Waiver_expiresAt_idx" ON "Waiver"("expiresAt");
CREATE INDEX "Suppression_tenantId_idx" ON "Suppression"("tenantId");
CREATE INDEX "Suppression_scanRequestId_idx" ON "Suppression"("scanRequestId");
CREATE INDEX "Suppression_findingId_idx" ON "Suppression"("findingId");
CREATE INDEX "AuditEvent_tenantId_idx" ON "AuditEvent"("tenantId");
CREATE INDEX "AuditEvent_scanRequestId_idx" ON "AuditEvent"("scanRequestId");
CREATE INDEX "AuditEvent_eventType_idx" ON "AuditEvent"("eventType");
CREATE INDEX "AuditEvent_occurredAt_idx" ON "AuditEvent"("occurredAt");

ALTER TABLE "User" ADD CONSTRAINT "User_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "ScmIntegration" ADD CONSTRAINT "ScmIntegration_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RepositoryBinding" ADD CONSTRAINT "RepositoryBinding_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RepositoryBinding" ADD CONSTRAINT "RepositoryBinding_scmIntegrationId_fkey" FOREIGN KEY ("scmIntegrationId") REFERENCES "ScmIntegration"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ScanRequest" ADD CONSTRAINT "ScanRequest_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ScanRequest" ADD CONSTRAINT "ScanRequest_repositoryBindingId_fkey" FOREIGN KEY ("repositoryBindingId") REFERENCES "RepositoryBinding"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ScannerRun" ADD CONSTRAINT "ScannerRun_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ScannerRun" ADD CONSTRAINT "ScannerRun_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "NormalizedFinding" ADD CONSTRAINT "NormalizedFinding_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "NormalizedFinding" ADD CONSTRAINT "NormalizedFinding_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "NormalizedFinding" ADD CONSTRAINT "NormalizedFinding_scannerRunId_fkey" FOREIGN KEY ("scannerRunId") REFERENCES "ScannerRun"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "EvidencePack" ADD CONSTRAINT "EvidencePack_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "EvidencePack" ADD CONSTRAINT "EvidencePack_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PolicyDecision" ADD CONSTRAINT "PolicyDecision_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PolicyDecision" ADD CONSTRAINT "PolicyDecision_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PolicyDecision" ADD CONSTRAINT "PolicyDecision_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "NormalizedFinding"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Waiver" ADD CONSTRAINT "Waiver_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Suppression" ADD CONSTRAINT "Suppression_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Suppression" ADD CONSTRAINT "Suppression_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Suppression" ADD CONSTRAINT "Suppression_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "NormalizedFinding"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE SET NULL ON UPDATE CASCADE;
