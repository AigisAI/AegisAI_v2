CREATE TYPE "SastCredentialLeaseStatus" AS ENUM ('RESERVED', 'ISSUED', 'WIPED', 'REVOKED');

CREATE TABLE "SastRepositoryCredentialLease" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "repositoryBindingId" TEXT NOT NULL,
    "scanRequestId" TEXT NOT NULL,
    "attemptId" TEXT NOT NULL,
    "workloadIdentityRef" TEXT NOT NULL,
    "commitSha" TEXT NOT NULL,
    "credentialFingerprint" TEXT,
    "status" "SastCredentialLeaseStatus" NOT NULL DEFAULT 'RESERVED',
    "issuedAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "wipedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SastRepositoryCredentialLease_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "SastRepositoryCredentialLease_expiry_check"
      CHECK ("expiresAt" > "issuedAt"),
    CONSTRAINT "SastRepositoryCredentialLease_commit_sha_check"
      CHECK ("commitSha" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    CONSTRAINT "SastRepositoryCredentialLease_fingerprint_check"
      CHECK (
        ("status" = 'RESERVED' AND "credentialFingerprint" IS NULL)
        OR
        ("status" IN ('ISSUED', 'WIPED') AND "credentialFingerprint" ~ '^sha256:[0-9a-f]{64}$')
        OR
        ("status" = 'REVOKED' AND (
          "credentialFingerprint" IS NULL
          OR "credentialFingerprint" ~ '^sha256:[0-9a-f]{64}$'
        ))
      ),
    CONSTRAINT "SastRepositoryCredentialLease_lifecycle_check"
      CHECK (
        ("status" IN ('RESERVED', 'ISSUED')
          AND "wipedAt" IS NULL
          AND "revokedAt" IS NULL)
        OR
        ("status" = 'WIPED'
          AND "wipedAt" IS NOT NULL
          AND "wipedAt" >= "issuedAt"
          AND "revokedAt" IS NULL)
        OR
        ("status" = 'REVOKED'
          AND "revokedAt" IS NOT NULL
          AND "revokedAt" >= "issuedAt"
          AND "wipedAt" IS NULL)
      )
);

CREATE UNIQUE INDEX "SastRepositoryCredentialLease_tenantId_attemptId_key"
ON "SastRepositoryCredentialLease"("tenantId", "attemptId");

CREATE INDEX "SastRepositoryCredentialLease_tenantId_scanRequestId_status_idx"
ON "SastRepositoryCredentialLease"("tenantId", "scanRequestId", "status");

CREATE INDEX "SastRepositoryCredentialLease_repositoryBindingId_status_idx"
ON "SastRepositoryCredentialLease"("repositoryBindingId", "status");

CREATE INDEX "SastRepositoryCredentialLease_expiresAt_status_idx"
ON "SastRepositoryCredentialLease"("expiresAt", "status");

ALTER TABLE "SastRepositoryCredentialLease"
ADD CONSTRAINT "SastRepositoryCredentialLease_tenantId_fkey"
FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastRepositoryCredentialLease"
ADD CONSTRAINT "SastCredentialLease_repository_scope_fkey"
FOREIGN KEY ("repositoryBindingId", "tenantId")
REFERENCES "RepositoryBinding"("id", "tenantId") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SastRepositoryCredentialLease"
ADD CONSTRAINT "SastCredentialLease_scan_scope_fkey"
FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")
REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")
ON DELETE CASCADE ON UPDATE CASCADE;
