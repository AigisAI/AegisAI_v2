CREATE UNIQUE INDEX "Report_active_scan_user_unique_idx"
ON "Report"("scanId", "userId")
WHERE "status" IN ('GENERATING', 'READY');
