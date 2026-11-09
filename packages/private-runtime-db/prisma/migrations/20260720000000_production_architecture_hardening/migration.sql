-- CreateEnum
CREATE TYPE "ScmIntegrationType" AS ENUM ('GITHUB_APP', 'GITLAB_CLOUD_INTEGRATION');

-- CreateEnum
CREATE TYPE "IntegrationStatus" AS ENUM ('ACTIVE', 'REVOKED', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "IntegrationPrincipal" AS ENUM ('REPO_READ', 'COMMENT_WRITE', 'INTEGRATION_ADMIN');

-- CreateEnum
CREATE TYPE "ScanLane" AS ENUM ('FAST', 'DEEP');

-- CreateEnum
CREATE TYPE "ArchitectureScanStatus" AS ENUM ('QUEUED', 'PLANNING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELED');

-- CreateEnum
CREATE TYPE "IsolationClass" AS ENUM ('STANDARD', 'HARDENED', 'RESTRICTED');

-- CreateEnum
CREATE TYPE "ScannerKind" AS ENUM ('OPENGREP', 'TRIVY', 'SYFT', 'MOCK');

-- CreateEnum
CREATE TYPE "ScannerRunStatus" AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT', 'SKIPPED');

-- CreateEnum
CREATE TYPE "NormalizedFindingStatus" AS ENUM ('OPEN', 'ACCEPTED', 'REJECTED', 'WAIVED', 'SUPPRESSED', 'FIXED');

-- CreateEnum
CREATE TYPE "EvidenceClassification" AS ENUM ('SHORT_LIVED_EVIDENCE');

-- CreateEnum
CREATE TYPE "PolicyAction" AS ENUM ('DASHBOARD_ONLY', 'COMMENT', 'WARN', 'TICKET', 'BLOCK');

-- CreateEnum
CREATE TYPE "SuppressionReason" AS ENUM ('STALE_RESULT', 'DUPLICATE', 'POLICY');

-- CreateEnum
CREATE TYPE "TenantStatus" AS ENUM ('ACTIVE', 'SUSPENDED');

-- Preserve user identity metadata while eliminating long-lived OAuth credentials.
ALTER TABLE "OAuthToken" RENAME TO "UserOAuthIdentity";
ALTER TABLE "UserOAuthIdentity" RENAME CONSTRAINT "OAuthToken_pkey" TO "UserOAuthIdentity_pkey";
ALTER TABLE "UserOAuthIdentity" RENAME CONSTRAINT "OAuthToken_userId_fkey" TO "UserOAuthIdentity_userId_fkey";
ALTER INDEX "OAuthToken_userId_provider_key" RENAME TO "UserOAuthIdentity_userId_provider_key";
ALTER INDEX "OAuthToken_provider_providerUserId_key" RENAME TO "UserOAuthIdentity_provider_providerUserId_key";
ALTER TABLE "UserOAuthIdentity"
    DROP COLUMN "accessToken",
    DROP COLUMN "refreshToken",
    DROP COLUMN "expiresAt";

-- CreateTable
CREATE TABLE "Tenant" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "status" "TenantStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Tenant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
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

-- CreateTable
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

-- CreateTable
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

-- CreateTable
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

-- CreateTable
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

    CONSTRAINT "NormalizedFinding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
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

    CONSTRAINT "EvidencePack_pkey" PRIMARY KEY ("id")
);

-- CreateTable
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

-- CreateTable
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

-- CreateTable
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

-- CreateTable
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

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_slug_key" ON "Tenant"("slug");

-- CreateIndex
CREATE INDEX "ScmIntegration_tenantId_idx" ON "ScmIntegration"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "ScmIntegration_tenantId_provider_externalInstallationId_key" ON "ScmIntegration"("tenantId", "provider", "externalInstallationId");

-- CreateIndex
CREATE INDEX "RepositoryBinding_tenantId_idx" ON "RepositoryBinding"("tenantId");

-- CreateIndex
CREATE INDEX "RepositoryBinding_scmIntegrationId_idx" ON "RepositoryBinding"("scmIntegrationId");

-- CreateIndex
CREATE UNIQUE INDEX "RepositoryBinding_tenantId_scmIntegrationId_providerRepoId_key" ON "RepositoryBinding"("tenantId", "scmIntegrationId", "providerRepoId");

-- CreateIndex
CREATE UNIQUE INDEX "ScanRequest_canonicalKey_key" ON "ScanRequest"("canonicalKey");

-- CreateIndex
CREATE INDEX "ScanRequest_tenantId_idx" ON "ScanRequest"("tenantId");

-- CreateIndex
CREATE INDEX "ScanRequest_repositoryBindingId_idx" ON "ScanRequest"("repositoryBindingId");

-- CreateIndex
CREATE INDEX "ScanRequest_status_idx" ON "ScanRequest"("status");

-- CreateIndex
CREATE INDEX "ScanRequest_createdAt_idx" ON "ScanRequest"("createdAt" DESC);

-- CreateIndex
CREATE INDEX "ScannerRun_tenantId_idx" ON "ScannerRun"("tenantId");

-- CreateIndex
CREATE INDEX "ScannerRun_scanRequestId_idx" ON "ScannerRun"("scanRequestId");

-- CreateIndex
CREATE INDEX "ScannerRun_scanner_idx" ON "ScannerRun"("scanner");

-- CreateIndex
CREATE INDEX "ScannerRun_status_idx" ON "ScannerRun"("status");

-- CreateIndex
CREATE INDEX "NormalizedFinding_tenantId_idx" ON "NormalizedFinding"("tenantId");

-- CreateIndex
CREATE INDEX "NormalizedFinding_scanRequestId_idx" ON "NormalizedFinding"("scanRequestId");

-- CreateIndex
CREATE INDEX "NormalizedFinding_scannerRunId_idx" ON "NormalizedFinding"("scannerRunId");

-- CreateIndex
CREATE INDEX "NormalizedFinding_severity_idx" ON "NormalizedFinding"("severity");

-- CreateIndex
CREATE INDEX "NormalizedFinding_status_idx" ON "NormalizedFinding"("status");

-- CreateIndex
CREATE INDEX "EvidencePack_tenantId_idx" ON "EvidencePack"("tenantId");

-- CreateIndex
CREATE INDEX "EvidencePack_scanRequestId_idx" ON "EvidencePack"("scanRequestId");

-- CreateIndex
CREATE INDEX "EvidencePack_expiresAt_idx" ON "EvidencePack"("expiresAt");

-- CreateIndex
CREATE INDEX "PolicyDecision_tenantId_idx" ON "PolicyDecision"("tenantId");

-- CreateIndex
CREATE INDEX "PolicyDecision_scanRequestId_idx" ON "PolicyDecision"("scanRequestId");

-- CreateIndex
CREATE INDEX "PolicyDecision_findingId_idx" ON "PolicyDecision"("findingId");

-- CreateIndex
CREATE INDEX "Waiver_tenantId_idx" ON "Waiver"("tenantId");

-- CreateIndex
CREATE INDEX "Waiver_expiresAt_idx" ON "Waiver"("expiresAt");

-- CreateIndex
CREATE INDEX "Suppression_tenantId_idx" ON "Suppression"("tenantId");

-- CreateIndex
CREATE INDEX "Suppression_scanRequestId_idx" ON "Suppression"("scanRequestId");

-- CreateIndex
CREATE INDEX "Suppression_findingId_idx" ON "Suppression"("findingId");

-- CreateIndex
CREATE INDEX "AuditEvent_tenantId_idx" ON "AuditEvent"("tenantId");

-- CreateIndex
CREATE INDEX "AuditEvent_scanRequestId_idx" ON "AuditEvent"("scanRequestId");

-- CreateIndex
CREATE INDEX "AuditEvent_eventType_idx" ON "AuditEvent"("eventType");

-- CreateIndex
CREATE INDEX "AuditEvent_occurredAt_idx" ON "AuditEvent"("occurredAt");

-- AddForeignKey
ALTER TABLE "ScmIntegration" ADD CONSTRAINT "ScmIntegration_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RepositoryBinding" ADD CONSTRAINT "RepositoryBinding_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RepositoryBinding" ADD CONSTRAINT "RepositoryBinding_scmIntegrationId_fkey" FOREIGN KEY ("scmIntegrationId") REFERENCES "ScmIntegration"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanRequest" ADD CONSTRAINT "ScanRequest_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanRequest" ADD CONSTRAINT "ScanRequest_repositoryBindingId_fkey" FOREIGN KEY ("repositoryBindingId") REFERENCES "RepositoryBinding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScannerRun" ADD CONSTRAINT "ScannerRun_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScannerRun" ADD CONSTRAINT "ScannerRun_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NormalizedFinding" ADD CONSTRAINT "NormalizedFinding_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NormalizedFinding" ADD CONSTRAINT "NormalizedFinding_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NormalizedFinding" ADD CONSTRAINT "NormalizedFinding_scannerRunId_fkey" FOREIGN KEY ("scannerRunId") REFERENCES "ScannerRun"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EvidencePack" ADD CONSTRAINT "EvidencePack_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EvidencePack" ADD CONSTRAINT "EvidencePack_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PolicyDecision" ADD CONSTRAINT "PolicyDecision_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PolicyDecision" ADD CONSTRAINT "PolicyDecision_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PolicyDecision" ADD CONSTRAINT "PolicyDecision_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "NormalizedFinding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Waiver" ADD CONSTRAINT "Waiver_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Suppression" ADD CONSTRAINT "Suppression_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Suppression" ADD CONSTRAINT "Suppression_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Suppression" ADD CONSTRAINT "Suppression_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "NormalizedFinding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- Domain integrity checks not currently expressible in the Prisma schema DSL.
ALTER TABLE "NormalizedFinding" ADD CONSTRAINT "NormalizedFinding_valid_line_range_check"
  CHECK ("lineStart" > 0 AND ("lineEnd" IS NULL OR "lineEnd" >= "lineStart"));
ALTER TABLE "EvidencePack" ADD CONSTRAINT "EvidencePack_valid_retention_check"
  CHECK ("byteSize" >= 0 AND "expiresAt" > "createdAt");
