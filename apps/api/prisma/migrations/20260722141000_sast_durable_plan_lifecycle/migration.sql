-- A queue reservation may only exist for a durable scan request and must carry
-- the exact admitted planning state and immutable execution plan.
ALTER TABLE "ScanRequest"
ADD COLUMN "sastPlanning" JSONB;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM "SastQueueReservation" LIMIT 1) THEN
    RAISE EXCEPTION
      'SastQueueReservation must be empty before adding immutable plan persistence';
  END IF;
END
$$;

ALTER TABLE "SastQueueReservation"
ADD COLUMN "planning" JSONB NOT NULL,
ADD COLUMN "immutablePlan" JSONB NOT NULL,
ADD COLUMN "startedAt" TIMESTAMP(3),
ADD COLUMN "completedAt" TIMESTAMP(3),
ADD COLUMN "terminalStatus" "ArchitectureScanStatus";

ALTER TABLE "SastQueueReservation"
ADD CONSTRAINT "SastQueueReservation_scanRequestId_fkey"
FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id")
ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE INDEX "SastQueueReservation_completedAt_idx"
ON "SastQueueReservation"("completedAt");
