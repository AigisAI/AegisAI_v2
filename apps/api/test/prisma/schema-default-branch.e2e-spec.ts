import { readFileSync } from 'node:fs';
import { join } from 'node:path';

describe('ConnectedRepo Prisma schema', () => {
  const schema = readFileSync(join(__dirname, '../../prisma/schema.prisma'), 'utf8');
  const initialMigration = readFileSync(
    join(__dirname, '../../prisma/migrations/20260315215651_init/migration.sql'),
    'utf8'
  );

  it('requires defaultBranch to be set explicitly instead of relying on a Prisma default', () => {
    const defaultBranchLine = schema
      .split(/\r?\n/)
      .find((line) => line.includes('defaultBranch'));

    expect(defaultBranchLine).toContain('defaultBranch');
    expect(defaultBranchLine).not.toContain('@default');
  });

  it('does not bake a database-level fallback into the initial migration', () => {
    expect(initialMigration).not.toContain('"defaultBranch" TEXT NOT NULL DEFAULT');
  });

  it('guards scan metrics against impossible negative values', () => {
    expect(initialMigration).toContain('CONSTRAINT "Scan_non_negative_metrics_check" CHECK');
    expect(initialMigration).toContain('"totalFiles" IS NULL OR "totalFiles" >= 0');
    expect(initialMigration).toContain('"totalLines" IS NULL OR "totalLines" >= 0');
    expect(initialMigration).toContain('"vulnCritical" >= 0');
    expect(initialMigration).toContain('"vulnHigh" >= 0');
    expect(initialMigration).toContain('"vulnMedium" >= 0');
    expect(initialMigration).toContain('"vulnLow" >= 0');
    expect(initialMigration).toContain('"vulnInfo" >= 0');
  });

  it('guards vulnerability line ranges against impossible values', () => {
    expect(initialMigration).toContain('CONSTRAINT "Vulnerability_valid_line_range_check" CHECK');
    expect(initialMigration).toContain('"lineStart" > 0');
    expect(initialMigration).toContain('"lineEnd" IS NULL OR "lineEnd" >= "lineStart"');
  });
});
