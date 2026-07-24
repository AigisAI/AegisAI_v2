-- Repository removal must preserve immutable scan and queue history.
CREATE TYPE "RepositoryBindingStatus" AS ENUM ('ACTIVE', 'REVOKED');

ALTER TABLE "RepositoryBinding"
ADD COLUMN "status" "RepositoryBindingStatus" NOT NULL DEFAULT 'ACTIVE',
ADD COLUMN "revokedAt" TIMESTAMP(3);

CREATE INDEX "RepositoryBinding_tenantId_status_idx"
ON "RepositoryBinding"("tenantId", "status");
