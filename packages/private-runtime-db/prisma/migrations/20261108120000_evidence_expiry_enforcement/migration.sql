ALTER TABLE "EvidencePack" ADD COLUMN "deletedAt" TIMESTAMP(3);
CREATE INDEX "EvidencePack_pending_expiry_idx" ON "EvidencePack"("expiresAt") WHERE "deletedAt" IS NULL;
