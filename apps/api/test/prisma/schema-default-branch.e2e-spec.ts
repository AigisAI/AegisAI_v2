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
});
