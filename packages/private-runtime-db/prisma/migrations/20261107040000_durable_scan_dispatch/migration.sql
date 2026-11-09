-- CreateEnum
CREATE TYPE "DispatchJobStatus" AS ENUM ('PENDING', 'LEASED', 'SUCCEEDED', 'DEAD', 'CANCELED');

-- CreateEnum
CREATE TYPE "DispatchFailureCode" AS ENUM ('UPSTREAM_UNAVAILABLE', 'LEASE_EXPIRED', 'DISPATCH_REJECTED');

-- CreateTable
CREATE TABLE "ScanDispatchJob" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "scanRequestId" TEXT NOT NULL,
    "status" "DispatchJobStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "availableAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "leaseToken" TEXT,
    "leasedBy" TEXT,
    "leaseExpiresAt" TIMESTAMP(3),
    "lastErrorCode" "DispatchFailureCode",
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanDispatchJob_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ScanDispatchJob_scanRequestId_key" ON "ScanDispatchJob"("scanRequestId");

-- CreateIndex
CREATE UNIQUE INDEX "ScanDispatchJob_leaseToken_key" ON "ScanDispatchJob"("leaseToken");

-- CreateIndex
CREATE INDEX "ScanDispatchJob_status_availableAt_createdAt_idx" ON "ScanDispatchJob"("status", "availableAt", "createdAt");

-- CreateIndex
CREATE INDEX "ScanDispatchJob_tenantId_status_idx" ON "ScanDispatchJob"("tenantId", "status");

-- CreateIndex
CREATE INDEX "ScanDispatchJob_status_leaseExpiresAt_idx" ON "ScanDispatchJob"("status", "leaseExpiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "ScanDispatchJob_tenantId_scanRequestId_key" ON "ScanDispatchJob"("tenantId", "scanRequestId");

-- CreateIndex
CREATE UNIQUE INDEX "ScanRequest_tenantId_id_key" ON "ScanRequest"("tenantId", "id");

-- AddForeignKey
ALTER TABLE "ScanDispatchJob" ADD CONSTRAINT "ScanDispatchJob_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanDispatchJob" ADD CONSTRAINT "ScanDispatchJob_tenantId_scanRequestId_fkey" FOREIGN KEY ("tenantId", "scanRequestId") REFERENCES "ScanRequest"("tenantId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Database-level invariants also apply to administrative SQL and future workers.
ALTER TABLE "ScanDispatchJob" ADD CONSTRAINT "ScanDispatchJob_attempts_check"
CHECK ("attempts" >= 0 AND "attempts" <= 5);
ALTER TABLE "ScanDispatchJob" ADD CONSTRAINT "ScanDispatchJob_lease_check"
CHECK (
  ("status" = 'LEASED' AND "leaseToken" IS NOT NULL AND "leasedBy" IS NOT NULL AND "leaseExpiresAt" IS NOT NULL)
  OR
  ("status" <> 'LEASED' AND "leaseToken" IS NULL AND "leasedBy" IS NULL AND "leaseExpiresAt" IS NULL)
);

-- Old completed/failed/canceled requests must never be dispatched by this migration.
INSERT INTO "ScanDispatchJob" ("id", "tenantId", "scanRequestId", "updatedAt")
SELECT 'dispatch_job_' || md5("id"), "tenantId", "id", CURRENT_TIMESTAMP
FROM "ScanRequest" WHERE "status" IN ('QUEUED', 'PLANNING');

