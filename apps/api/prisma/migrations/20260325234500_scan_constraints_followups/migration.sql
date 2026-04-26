ALTER TABLE "Vulnerability"
ADD CONSTRAINT "Vulnerability_consensus_score_range_check" CHECK (
  "consensusScore" IS NULL OR ("consensusScore" >= 0 AND "consensusScore" <= 1)
);

CREATE UNIQUE INDEX "Scan_active_branch_unique_idx"
ON "Scan"("connectedRepoId", "branch")
WHERE "status" IN ('PENDING', 'RUNNING');
