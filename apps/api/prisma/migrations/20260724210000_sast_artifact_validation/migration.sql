-- Nullable columns preserve rolling-deployment compatibility. The application writes
-- all three fields for every new runtime record. The mandatory online schema step
-- validates ScannerRun_runtime_metadata_v3_check before removing v1/v2 constraints.
ALTER TABLE "ScannerRun"
  ADD COLUMN "schemaBundleDigest" TEXT,
  ADD COLUMN "normalizerBundleDigest" TEXT;

ALTER TABLE "SastArtifactIngestion"
  ADD COLUMN "envelope" JSONB;
