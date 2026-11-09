-- Dependency advisories may identify a manifest without a source line.
ALTER TABLE "NormalizedFinding" ALTER COLUMN "lineStart" DROP NOT NULL;
ALTER TABLE "NormalizedFinding" ADD CONSTRAINT "NormalizedFinding_location_check"
CHECK (("lineStart" IS NULL OR "lineStart" > 0)
 AND ("lineEnd" IS NULL OR ("lineStart" IS NOT NULL AND "lineEnd" >= "lineStart")));
