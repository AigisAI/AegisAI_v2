-- CreateTable
CREATE TABLE "AiAdvisoryMetadata" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "scanRequestId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "modelVersion" TEXT NOT NULL,
    "advisoryOnly" BOOLEAN NOT NULL DEFAULT true,
    "redactedEvidenceOnly" BOOLEAN NOT NULL DEFAULT true,
    "detectorSignals" JSONB NOT NULL,
    "plannerSteps" JSONB NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "detectorAdvisories" JSONB,
    "plannerAdvisories" JSONB,
    "modelMetadata" JSONB,
    "fallback" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiAdvisoryMetadata_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AiAdvisoryMetadata_tenantId_idx" ON "AiAdvisoryMetadata"("tenantId");

-- CreateIndex
CREATE INDEX "AiAdvisoryMetadata_scanRequestId_idx" ON "AiAdvisoryMetadata"("scanRequestId");

-- CreateIndex
CREATE INDEX "AiAdvisoryMetadata_findingId_idx" ON "AiAdvisoryMetadata"("findingId");

-- CreateIndex
CREATE INDEX "AiAdvisoryMetadata_createdAt_idx" ON "AiAdvisoryMetadata"("createdAt" DESC);

-- AddForeignKey
ALTER TABLE "AiAdvisoryMetadata" ADD CONSTRAINT "AiAdvisoryMetadata_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AiAdvisoryMetadata" ADD CONSTRAINT "AiAdvisoryMetadata_scanRequestId_fkey" FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;
