WITH ranked_active_reports AS (
  SELECT
    "id",
    "status",
    ROW_NUMBER() OVER (
      PARTITION BY "scanId", "userId"
      ORDER BY
        CASE WHEN "status" = 'READY' THEN 0 ELSE 1 END,
        "createdAt" DESC,
        "id" DESC
    ) AS "rank"
  FROM "Report"
  WHERE "status" IN ('GENERATING', 'READY')
),
duplicate_active_reports AS (
  SELECT "id", "status"
  FROM ranked_active_reports
  WHERE "rank" > 1
)
UPDATE "Report"
SET
  "status" = CASE
    WHEN duplicate_active_reports."status" = 'READY' THEN 'EXPIRED'::"ReportStatus"
    ELSE 'FAILED'::"ReportStatus"
  END,
  "downloadUrl" = NULL,
  "errorMessage" = CASE
    WHEN duplicate_active_reports."status" = 'READY'
      THEN 'Report expired during active report deduplication.'
    ELSE 'Duplicate active report failed during active report deduplication.'
  END
FROM duplicate_active_reports
WHERE "Report"."id" = duplicate_active_reports."id";

CREATE UNIQUE INDEX "Report_active_scan_user_unique_idx"
ON "Report"("scanId", "userId")
WHERE "status" IN ('GENERATING', 'READY');
