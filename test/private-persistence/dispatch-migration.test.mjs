import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const databaseUrl = process.env.PERSISTENCE_TEST_DATABASE_URL;
assert.ok(databaseUrl, 'Dedicated verification database required');
assert.match(new URL(databaseUrl).pathname, /^\/aegisai_(verify|ci|test)$/);
const require = createRequire(new URL('../../apps/private-api/package.json', import.meta.url));
const { PrismaClient } = require('@aegisai/private-runtime-db');
const prismaDirectory = fileURLToPath(new URL('../../packages/private-runtime-db/prisma/', import.meta.url));
const migrationName = '20261107040000_durable_scan_dispatch';

test('upgrades existing scans without redispatching terminal history', async () => {
  const schema = 'verify_dispatch_' + randomUUID().replaceAll('-', '');
  assert.match(schema, /^verify_dispatch_[a-f0-9]{32}$/);
  const target = new URL(databaseUrl);
  target.searchParams.set('schema', schema);
  const directory = mkdtempSync(join(tmpdir(), 'aegisai-dispatch-migrate-'));
  const env = { ...process.env, DATABASE_URL: target.href, CHECKPOINT_DISABLE: '1' };
  const prisma = new PrismaClient({ datasources: { db: { url: target.href } } });
  const cli = require.resolve('prisma/build/index.js');

  function migrate(path) {
    execFileSync(process.execPath, [cli, 'migrate', 'deploy', '--schema', path],
      { env, encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] });
  }

  try {
    cpSync(join(prismaDirectory, 'schema.prisma'), join(directory, 'schema.prisma'));
    const names = readdirSync(join(prismaDirectory, 'migrations')).filter((name) => /^\d{14}_/.test(name));
    for (const name of names.filter((name) => name < migrationName)) {
      cpSync(join(prismaDirectory, 'migrations', name), join(directory, 'migrations', name), { recursive: true });
    }
    cpSync(join(prismaDirectory, 'migrations', 'migration_lock.toml'), join(directory, 'migrations', 'migration_lock.toml'));
    migrate(join(directory, 'schema.prisma'));
    const tenantId = `migration_${randomUUID()}`;
    await prisma.tenant.create({ data: { id: tenantId, slug: tenantId, name: 'Migration verification' } });
    const integration = await prisma.scmIntegration.create({ data: {
      tenantId, provider: 'GITHUB', integrationType: 'GITHUB_APP',
      externalInstallationId: 'verification', repoReadPrincipalId: 'verification'
    } });
    const binding = await prisma.repositoryBinding.create({ data: {
      tenantId, scmIntegrationId: integration.id, providerRepoId: '1', fullName: 'verify/repo', defaultBranch: 'main'
    } });
    for (const status of ['QUEUED', 'PLANNING', 'COMPLETED', 'FAILED', 'CANCELED']) {
      await prisma.scanRequest.create({ data: {
        id: `migration_scan_${status}`, tenantId, repositoryBindingId: binding.id,
        lane: 'FAST', targetRef: 'main', commitSha: 'a'.repeat(40), policyVersion: 'v1',
        scannerSetVersion: 'v1', canonicalKey: `verify:${status}`, status
      } });
    }
    migrate(join(prismaDirectory, 'schema.prisma'));
    const jobs = await prisma.scanDispatchJob.findMany({ orderBy: { scanRequestId: 'asc' } });
    assert.deepEqual(jobs.map((job) => job.scanRequestId), ['migration_scan_PLANNING', 'migration_scan_QUEUED']);
    assert.ok(jobs.every((job) => job.tenantId === tenantId && job.status === 'PENDING' && job.attempts === 0));
    assert.equal(await prisma.scanRequest.count(), 5);
    migrate(join(prismaDirectory, 'schema.prisma'));
    assert.equal(await prisma.scanDispatchJob.count(), 2);
  } finally {
    try { await prisma.$executeRawUnsafe(`DROP SCHEMA "${schema}" CASCADE`); }
    finally {
      await prisma.$disconnect();
      assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
      assert.ok(basename(directory).startsWith('aegisai-dispatch-migrate-'));
      rmSync(directory, { recursive: true, force: true });
    }
  }
});
