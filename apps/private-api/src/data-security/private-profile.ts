import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { PrismaClient } from "@aegisai/private-runtime-db";

export interface PrivateMigration {
  name: string;
  sqlSha256: string;
  acceptedAppliedChecksums: string[];
}
export interface PrivateProfile {
  profile: string;
  generalQualification: string;
  migrations: PrivateMigration[];
}
export interface MigrationRow {
  migration_name: string;
  checksum: string;
  finished_at: Date | null;
  rolled_back_at: Date | null;
}

export function validatePrivateHistory(profile: PrivateProfile, rows: MigrationRow[]): void {
  if (profile.profile !== "private-single-host-v1" || profile.generalQualification !== "NOT_QUALIFIED" ||
      profile.migrations.length !== 6 || rows.length !== 6) throw new Error("PRIVATE_DATABASE_HISTORY_MISMATCH");
  const expected = new Map(profile.migrations.map(migration => [migration.name, migration]));
  if (expected.size !== 6 || new Set(rows.map(row => row.migration_name)).size !== 6) throw new Error("PRIVATE_DATABASE_HISTORY_MISMATCH");
  for (const row of rows) {
    const migration = expected.get(row.migration_name);
    if (!migration || !row.finished_at || row.rolled_back_at ||
        !migration.acceptedAppliedChecksums.includes(row.checksum)) throw new Error("PRIVATE_DATABASE_HISTORY_MISMATCH");
  }
}

/** Existing deployment only: fail before serving/migrating a different schema family. */
export async function assertPrivateDatabase(): Promise<void> {
  if (process.env.NODE_ENV !== "production") return;
  const profile = JSON.parse(await readFile("/app/private-runtime-profile.json", "utf8")) as PrivateProfile;
  for (const migration of profile.migrations) {
    if (!/^\d{14}_[a-z0-9_]+$/.test(migration.name)) throw new Error("PRIVATE_PROFILE_INVALID");
    const bytes = await readFile(`/app/packages/private-runtime-db/prisma/migrations/${migration.name}/migration.sql`);
    if (createHash("sha256").update(bytes).digest("hex") !== migration.sqlSha256) throw new Error("PRIVATE_PROFILE_SQL_DRIFT");
  }
  const client = new PrismaClient();
  try {
    const rows = await client.$queryRawUnsafe<MigrationRow[]>(
      'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations"'
    );
    validatePrivateHistory(profile, rows);
  } finally {
    await client.$disconnect();
  }
}
