-- CreateEnum
CREATE TYPE "FetchCapabilityStatus" AS ENUM ('ISSUED', 'CONSUMING', 'CONSUMED', 'REVOKED', 'EXPIRED');

-- Additive only: existing identities, integrations, scans and dispatch jobs remain.

-- CreateTable
CREATE TABLE "ScanBrokerRuntime" (
    "id" TEXT NOT NULL,
    "epoch" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanBrokerRuntime_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanFetchCapability" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "scanRequestId" TEXT NOT NULL,
    "dispatchJobId" TEXT NOT NULL,
    "issuerEpoch" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "leaseFingerprint" TEXT NOT NULL,
    "claimFingerprint" TEXT,
    "status" "FetchCapabilityStatus" NOT NULL DEFAULT 'ISSUED',
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "finishedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanFetchCapability_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ScanFetchCapability_fingerprint_key" ON "ScanFetchCapability"("fingerprint");

-- CreateIndex
CREATE INDEX "ScanFetchCapability_issuerEpoch_status_idx" ON "ScanFetchCapability"("issuerEpoch", "status");

-- CreateIndex
CREATE INDEX "ScanFetchCapability_dispatchJobId_status_idx" ON "ScanFetchCapability"("dispatchJobId", "status");

-- CreateIndex
CREATE INDEX "ScanFetchCapability_status_expiresAt_idx" ON "ScanFetchCapability"("status", "expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "ScanFetchCapability_tenantId_id_key" ON "ScanFetchCapability"("tenantId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "ScanDispatchJob_tenantId_id_scanRequestId_key" ON "ScanDispatchJob"("tenantId", "id", "scanRequestId");

-- AddForeignKey
ALTER TABLE "ScanFetchCapability" ADD CONSTRAINT "ScanFetchCapability_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanFetchCapability" ADD CONSTRAINT "ScanFetchCapability_tenantId_scanRequestId_fkey" FOREIGN KEY ("tenantId", "scanRequestId") REFERENCES "ScanRequest"("tenantId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanFetchCapability" ADD CONSTRAINT "ScanFetchCapability_tenantId_dispatchJobId_scanRequestId_fkey" FOREIGN KEY ("tenantId", "dispatchJobId", "scanRequestId") REFERENCES "ScanDispatchJob"("tenantId", "id", "scanRequestId") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ScanBrokerRuntime" ADD CONSTRAINT "ScanBrokerRuntime_singleton_check"
CHECK ("id" = 'private-single-host');
ALTER TABLE "ScanFetchCapability" ADD CONSTRAINT "ScanFetchCapability_ttl_check"
CHECK ("expiresAt" > "issuedAt" AND "expiresAt" <= "issuedAt" + INTERVAL '600 seconds');
ALTER TABLE "ScanFetchCapability" ADD CONSTRAINT "ScanFetchCapability_fingerprint_check"
CHECK ("fingerprint" ~ '^[0-9a-f]{64}$' AND "leaseFingerprint" ~ '^[0-9a-f]{64}$'
 AND ("claimFingerprint" IS NULL OR "claimFingerprint" ~ '^[0-9a-f]{64}$'));
ALTER TABLE "ScanFetchCapability" ADD CONSTRAINT "ScanFetchCapability_state_check"
CHECK (
 ("status" = 'ISSUED' AND "claimFingerprint" IS NULL AND "finishedAt" IS NULL) OR
 ("status" = 'CONSUMING' AND "claimFingerprint" IS NOT NULL AND "finishedAt" IS NULL) OR
 ("status" = 'CONSUMED' AND "claimFingerprint" IS NOT NULL AND "finishedAt" IS NOT NULL) OR
 ("status" IN ('REVOKED', 'EXPIRED') AND "finishedAt" IS NOT NULL)
);
CREATE UNIQUE INDEX "ScanFetchCapability_one_open_job_key"
ON "ScanFetchCapability"("dispatchJobId") WHERE "status" IN ('ISSUED','CONSUMING');

