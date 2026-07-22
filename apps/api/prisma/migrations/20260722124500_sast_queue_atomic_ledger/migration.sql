-- Shared SAST queue admission ledger. All replicas use these rows through
-- SERIALIZABLE transactions; process-local counters are never authoritative.
CREATE TABLE "SastQueueLedger" (
    "id" TEXT NOT NULL,
    "lane" "ScanLane" NOT NULL,
    "dailyWindowStartedAt" TIMESTAMP(3) NOT NULL,
    "snapshotVersion" BIGINT NOT NULL,
    "queuedInLane" INTEGER NOT NULL,
    "lastServedTenantId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "SastQueueLedger_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "SastQueueLedger_snapshotVersion_check"
      CHECK ("snapshotVersion" >= 0 AND "snapshotVersion" <= 9007199254740991),
    CONSTRAINT "SastQueueLedger_queuedInLane_check" CHECK ("queuedInLane" >= 0)
);

CREATE TABLE "SastQueueTenantUsage" (
    "ledgerId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "activeForTenant" INTEGER NOT NULL,
    "queuedForTenant" INTEGER NOT NULL,
    "admittedTodayForTenant" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "SastQueueTenantUsage_pkey" PRIMARY KEY ("ledgerId", "tenantId"),
    CONSTRAINT "SastQueueTenantUsage_counters_check"
      CHECK (
        "activeForTenant" >= 0 AND
        "queuedForTenant" >= 0 AND
        "admittedTodayForTenant" >= 0
      )
);

CREATE TABLE "SastQueueRepositoryUsage" (
    "ledgerId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "repositoryBindingId" TEXT NOT NULL,
    "activeForRepository" INTEGER NOT NULL,
    "lastRepositoryAdmissionAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "SastQueueRepositoryUsage_pkey"
      PRIMARY KEY ("ledgerId", "tenantId", "repositoryBindingId"),
    CONSTRAINT "SastQueueRepositoryUsage_active_check" CHECK ("activeForRepository" >= 0)
);

CREATE TABLE "SastQueueReservation" (
    "scanRequestId" TEXT NOT NULL,
    "ledgerId" TEXT NOT NULL,
    "canonicalScanKey" TEXT NOT NULL,
    "lane" "ScanLane" NOT NULL,
    "tenantId" TEXT NOT NULL,
    "repositoryBindingId" TEXT NOT NULL,
    "queuePolicyVersion" TEXT NOT NULL,
    "queuePolicyDigest" TEXT NOT NULL,
    "decision" JSONB NOT NULL,
    "enqueuedAt" TIMESTAMP(3) NOT NULL,
    "dispatchLeaseOwner" TEXT,
    "dispatchLeaseExpiresAt" TIMESTAMP(3),
    "dispatchAttempt" INTEGER NOT NULL DEFAULT 0,
    "publishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "SastQueueReservation_pkey" PRIMARY KEY ("scanRequestId"),
    CONSTRAINT "SastQueueReservation_canonicalScanKey_check"
      CHECK ("canonicalScanKey" ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT "SastQueueReservation_queuePolicyDigest_check"
      CHECK ("queuePolicyDigest" ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT "SastQueueReservation_dispatchAttempt_check" CHECK ("dispatchAttempt" >= 0),
    CONSTRAINT "SastQueueReservation_dispatchLease_check"
      CHECK (("dispatchLeaseOwner" IS NULL) = ("dispatchLeaseExpiresAt" IS NULL)),
    CONSTRAINT "SastQueueReservation_publishedLease_check"
      CHECK (
        "publishedAt" IS NULL OR
        ("dispatchLeaseOwner" IS NOT NULL AND "dispatchLeaseExpiresAt" IS NOT NULL)
      )
);

CREATE UNIQUE INDEX "SastQueueLedger_lane_dailyWindowStartedAt_key"
  ON "SastQueueLedger"("lane", "dailyWindowStartedAt");
CREATE INDEX "SastQueueLedger_dailyWindowStartedAt_idx"
  ON "SastQueueLedger"("dailyWindowStartedAt");
CREATE INDEX "SastQueueTenantUsage_tenantId_idx"
  ON "SastQueueTenantUsage"("tenantId");
CREATE INDEX "SastQueueRepositoryUsage_tenantId_repositoryBindingId_idx"
  ON "SastQueueRepositoryUsage"("tenantId", "repositoryBindingId");
CREATE INDEX "SastQueueReservation_ledgerId_publishedAt_enqueuedAt_idx"
  ON "SastQueueReservation"("ledgerId", "publishedAt", "enqueuedAt");
CREATE INDEX "SastQueueReservation_tenantId_lane_enqueuedAt_idx"
  ON "SastQueueReservation"("tenantId", "lane", "enqueuedAt");
CREATE INDEX "SastQueueReservation_dispatchLeaseExpiresAt_idx"
  ON "SastQueueReservation"("dispatchLeaseExpiresAt");

ALTER TABLE "SastQueueTenantUsage"
  ADD CONSTRAINT "SastQueueTenantUsage_ledgerId_fkey"
  FOREIGN KEY ("ledgerId") REFERENCES "SastQueueLedger"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastQueueRepositoryUsage"
  ADD CONSTRAINT "SastQueueRepositoryUsage_ledgerId_fkey"
  FOREIGN KEY ("ledgerId") REFERENCES "SastQueueLedger"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SastQueueReservation"
  ADD CONSTRAINT "SastQueueReservation_ledgerId_fkey"
  FOREIGN KEY ("ledgerId") REFERENCES "SastQueueLedger"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
