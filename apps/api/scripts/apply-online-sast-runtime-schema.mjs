import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const indexes = [
  {
    name: 'ScannerRun_attemptId_scanner_key',
    unique: true,
    create:
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "ScannerRun_attemptId_scanner_key" ON "ScannerRun"("attemptId", "scanner")'
  },
  {
    name: 'ScannerRun_attemptId_idx',
    unique: false,
    create:
      'CREATE INDEX CONCURRENTLY IF NOT EXISTS "ScannerRun_attemptId_idx" ON "ScannerRun"("attemptId")'
  },
  {
    name: 'AuditEvent_attemptId_idx',
    unique: false,
    create:
      'CREATE INDEX CONCURRENTLY IF NOT EXISTS "AuditEvent_attemptId_idx" ON "AuditEvent"("attemptId")'
  },
  {
    name: 'AuditEvent_final_attempt_scope_key',
    unique: true,
    create:
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "AuditEvent_final_attempt_scope_key" ON "AuditEvent"("id", "attemptId", "tenantId")'
  },
  {
    name: 'ScannerRun_ingress_scope_key',
    unique: true,
    create:
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "ScannerRun_ingress_scope_key" ON "ScannerRun"("id", "attemptId", "tenantId", "repositoryBindingId", "scanRequestId")'
  }
];

const constraints = [
  {
    table: 'ScannerRun',
    name: 'ScannerRun_attempt_scope_fkey',
    type: 'f',
    definition:
      'FOREIGN KEY ("attemptId", "tenantId", "repositoryBindingId", "scanRequestId") REFERENCES "SastScanAttempt"("id", "tenantId", "repositoryBindingId", "scanRequestId") ON DELETE CASCADE ON UPDATE CASCADE'
  },
  {
    table: 'ScannerRun',
    name: 'ScannerRun_exit_code_check',
    type: 'c',
    definition:
      'CHECK ("exitCode" IS NULL OR "exitCode" BETWEEN -1 AND 255)'
  },
  {
    table: 'ScannerRun',
    name: 'ScannerRun_duration_check',
    type: 'c',
    definition:
      'CHECK ("durationMilliseconds" IS NULL OR "durationMilliseconds" >= 0)'
  },
  {
    table: 'ScannerRun',
    name: 'ScannerRun_runtime_metadata_v3_check',
    type: 'c',
    definition: `CHECK (
      "attemptId" IS NULL
      OR COALESCE(
        (
          "repositoryBindingId" IS NOT NULL
          AND "required" = true
          AND "scanner" IN ('OPENGREP', 'TRIVY', 'SYFT')
          AND "status"::text IN ('RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT', 'QUARANTINED', 'KILLED')
          AND "wrapperDigest" ~ '^sha256:[a-f0-9]{64}$'
          AND "scannerImageDigest" ~ '^sha256:[a-f0-9]{64}$'
          AND "scannerSetDigest" ~ '^sha256:[a-f0-9]{64}$'
          AND char_length("profileId") BETWEEN 1 AND 255
          AND "profileDigest" ~ '^sha256:[a-f0-9]{64}$'
          AND char_length("preflightAttestationRef") BETWEEN 1 AND 8192
          AND "preflightInventoryDigest" ~ '^sha256:[a-f0-9]{64}$'
          AND (
            "scannerWorkspaceInventoryDigest" IS NULL
            OR "scannerWorkspaceInventoryDigest" ~ '^sha256:[a-f0-9]{64}$'
          )
          AND (
            (
              "scanner" = 'OPENGREP'
              AND "ruleBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
              AND "databaseDigest" IS NULL
              AND "artifactSchema" = 'OPENGREP_SARIF'
            )
            OR (
              "scanner" = 'TRIVY'
              AND "ruleBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
              AND "databaseDigest" ~ '^sha256:[a-f0-9]{64}$'
              AND "artifactSchema" = 'TRIVY_JSON'
            )
            OR (
              "scanner" = 'SYFT'
              AND "ruleBundleDigest" IS NULL
              AND "databaseDigest" IS NULL
              AND "artifactSchema" = 'CYCLONEDX_JSON'
            )
          )
          AND (
            (
              "schemaBundleDigest" IS NULL
              AND "normalizerBundleDigest" IS NULL
              AND "artifactSchemaVersion" ~ '^sha256:[a-f0-9]{64}$'
            )
            OR (
              "schemaBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
              AND "normalizerBundleDigest" ~ '^sha256:[a-f0-9]{64}$'
              AND (
                ("scanner" = 'OPENGREP' AND "artifactSchemaVersion" = '2.1.0')
                OR ("scanner" = 'TRIVY' AND "artifactSchemaVersion" = '2')
                OR ("scanner" = 'SYFT' AND "artifactSchemaVersion" = '1.6')
              )
            )
          )
          AND "startedAt" IS NOT NULL
          AND (
            (
              "status" = 'RUNNING'
              AND "completedAt" IS NULL
              AND "exitCode" IS NULL
              AND "timedOut" IS NULL
              AND "outputLimitExceeded" IS NULL
              AND "durationMilliseconds" IS NULL
              AND jsonb_typeof("artifactMetadata") = 'object'
              AND char_length("artifactMetadata" ->> 'artifactRef') BETWEEN 1 AND 2048
              AND (
                "rawArtifactObjectKey" IS NULL
                OR char_length("rawArtifactObjectKey") BETWEEN 1 AND 2048
              )
            )
            OR (
              "status" IN ('COMPLETED', 'FAILED', 'TIMED_OUT', 'QUARANTINED', 'KILLED')
              AND "completedAt" IS NOT NULL
              AND "completedAt" >= "startedAt"
              AND "exitCode" IS NOT NULL
              AND "timedOut" IS NOT NULL
              AND "outputLimitExceeded" IS NOT NULL
              AND "durationMilliseconds" IS NOT NULL
              AND jsonb_typeof("stdoutMetadata") = 'object'
              AND jsonb_typeof("stderrMetadata") = 'object'
              AND jsonb_typeof("resourceMetadata") = 'object'
              AND (
                "status" <> 'COMPLETED'
                OR (
                  jsonb_typeof("artifactMetadata") = 'object'
                  AND jsonb_typeof("artifactMetadata" -> 'byteSize') = 'number'
                  AND ("artifactMetadata" ->> 'byteSize')::numeric > 0
                  AND char_length("rawArtifactObjectKey") BETWEEN 1 AND 2048
                )
              )
            )
          )
        ),
        false
      )
    )`
  },
  {
    table: 'AuditEvent',
    name: 'AuditEvent_attempt_scope_fkey',
    type: 'f',
    definition:
      'FOREIGN KEY ("attemptId", "tenantId") REFERENCES "SastScanAttempt"("id", "tenantId") ON DELETE CASCADE ON UPDATE CASCADE'
  },
  {
    table: 'SastScanAttempt',
    name: 'SastScanAttempt_finalAuditEventId_fkey',
    type: 'f',
    definition:
      'FOREIGN KEY ("finalAuditEventId", "id", "tenantId") REFERENCES "AuditEvent"("id", "attemptId", "tenantId") ON DELETE NO ACTION ON UPDATE NO ACTION'
  },
  {
    table: 'SastArtifactIngestion',
    name: 'SastArtifactIngestion_scanner_run_scope_fkey',
    type: 'f',
    definition:
      'FOREIGN KEY ("scannerRunId", "attemptId", "tenantId", "repositoryBindingId", "scanRequestId") REFERENCES "ScannerRun"("id", "attemptId", "tenantId", "repositoryBindingId", "scanRequestId") ON DELETE CASCADE ON UPDATE CASCADE'
  }
];

const supersededConstraints = [
  {
    table: 'ScannerRun',
    name: 'ScannerRun_runtime_metadata_check',
    replacement: 'ScannerRun_runtime_metadata_v3_check'
  },
  {
    table: 'ScannerRun',
    name: 'ScannerRun_runtime_metadata_v2_check',
    replacement: 'ScannerRun_runtime_metadata_v3_check'
  }
];

async function applyIndex(index) {
  assertIdentifier(index.name);
  const existing = await readIndex(index.name);
  if (existing && (!existing.valid || !existing.ready)) {
    await prisma.$executeRawUnsafe(
      `DROP INDEX CONCURRENTLY IF EXISTS "${index.name}"`
    );
  } else if (existing && existing.unique !== index.unique) {
    throw new Error(`Online index ${index.name} has an unexpected definition.`);
  }

  await prisma.$executeRawUnsafe(index.create);
  const applied = await readIndex(index.name);
  if (
    !applied ||
    !applied.valid ||
    !applied.ready ||
    applied.unique !== index.unique
  ) {
    throw new Error(`Online index ${index.name} is not valid after creation.`);
  }
  process.stdout.write(`online index ready: ${index.name}\n`);
}

async function applyConstraint(constraint) {
  assertIdentifier(constraint.table);
  assertIdentifier(constraint.name);
  const existing = await readConstraint(constraint.table, constraint.name);
  if (existing && existing.type !== constraint.type) {
    throw new Error(
      `Online constraint ${constraint.name} has an unexpected type.`
    );
  }
  if (!existing) {
    await prisma.$executeRawUnsafe(
      `ALTER TABLE "${constraint.table}" ADD CONSTRAINT "${constraint.name}" ${constraint.definition} NOT VALID`
    );
  }

  await prisma.$executeRawUnsafe(
    `ALTER TABLE "${constraint.table}" VALIDATE CONSTRAINT "${constraint.name}"`
  );
  const applied = await readConstraint(constraint.table, constraint.name);
  if (!applied?.validated || applied.type !== constraint.type) {
    throw new Error(
      `Online constraint ${constraint.name} is not valid after validation.`
    );
  }
  process.stdout.write(`online constraint ready: ${constraint.name}\n`);
}

async function readIndex(name) {
  const rows = await prisma.$queryRawUnsafe(
    `SELECT
       index_state.indisvalid AS "valid",
       index_state.indisready AS "ready",
       index_state.indisunique AS "unique"
     FROM pg_catalog.pg_class AS index_class
     JOIN pg_catalog.pg_namespace AS namespace
       ON namespace.oid = index_class.relnamespace
     JOIN pg_catalog.pg_index AS index_state
       ON index_state.indexrelid = index_class.oid
     WHERE namespace.nspname = current_schema()
       AND index_class.relname = $1`,
    name
  );
  return rows[0];
}

async function readConstraint(table, name) {
  const rows = await prisma.$queryRawUnsafe(
    `SELECT
       constraint_state.convalidated AS "validated",
       constraint_state.contype::text AS "type"
     FROM pg_catalog.pg_constraint AS constraint_state
     JOIN pg_catalog.pg_class AS table_class
       ON table_class.oid = constraint_state.conrelid
     JOIN pg_catalog.pg_namespace AS namespace
       ON namespace.oid = table_class.relnamespace
     WHERE namespace.nspname = current_schema()
       AND table_class.relname = $1
       AND constraint_state.conname = $2`,
    table,
    name
  );
  return rows[0];
}

async function dropSupersededConstraint(constraint) {
  assertIdentifier(constraint.table);
  assertIdentifier(constraint.name);
  assertIdentifier(constraint.replacement);
  const replacement = await readConstraint(
    constraint.table,
    constraint.replacement
  );
  if (!replacement?.validated) {
    throw new Error(
      `Replacement constraint ${constraint.replacement} is not validated.`
    );
  }

  const existing = await readConstraint(constraint.table, constraint.name);
  if (existing) {
    await prisma.$executeRawUnsafe(
      `ALTER TABLE "${constraint.table}" DROP CONSTRAINT "${constraint.name}"`
    );
  }
  if (await readConstraint(constraint.table, constraint.name)) {
    throw new Error(
      `Superseded constraint ${constraint.name} was not removed.`
    );
  }
  process.stdout.write(
    `superseded constraint removed: ${constraint.name}\n`
  );
}

function assertIdentifier(value) {
  if (!/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(value)) {
    throw new Error('Online schema identifier is invalid.');
  }
}

async function main() {
  for (const index of indexes) {
    await applyIndex(index);
  }
  for (const constraint of constraints) {
    await applyConstraint(constraint);
  }
  for (const constraint of supersededConstraints) {
    await dropSupersededConstraint(constraint);
  }
}

try {
  await main();
} finally {
  await prisma.$disconnect();
}
