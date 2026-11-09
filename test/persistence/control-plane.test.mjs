import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import test from 'node:test';

const databaseUrl = process.env.PERSISTENCE_TEST_DATABASE_URL;
assert.ok(databaseUrl, 'PERSISTENCE_TEST_DATABASE_URL is required; never default to production');
const parsed = new URL(databaseUrl);
assert.match(parsed.pathname, /^\/aegisai_(verify|ci|test)$/, 'Dedicated verification database required');
process.env.DATABASE_URL = databaseUrl;

const require = createRequire(new URL('../../apps/api/package.json', import.meta.url));
const { PrismaClient } = require('@prisma/client');
const controlModule = new URL('../../apps/api/dist/control-plane/control-plane.service.js', import.meta.url);
const { ControlPlaneService } = await import(controlModule.href);
const { IdentityStoreService } = await import('../../apps/api/dist/auth/identity-store.service.js');
const options = { provider: 'GITHUB', integrationType: 'GITHUB_APP' };

test('PostgreSQL production persistence boundaries', async (t) => {
  const suffix = randomUUID();
  const principal = {
    userId: `user_verify_${suffix}`, tenantId: `tenant_verify_${suffix}`,
    provider: 'GITHUB', providerUserId: `verify_${suffix}`,
    email: `verify_${suffix}@example.test`, name: 'Verification User'
  };
  const strangerId = `tenant_other_${suffix}`;
  const prisma = new PrismaClient();
  const service = new ControlPlaneService(prisma);
  const identity = new IdentityStoreService(prisma);
  let integration;
  let binding;
  let scan;
  let input;
  try {
    await t.test('persists identity without credentials and deduplicates concurrent installs', async () => {
      await Promise.all(Array.from({ length: 4 }, () => identity.persist(principal)));
      assert.equal(await prisma.userOAuthIdentity.count({ where: { userId: principal.userId } }), 1);
      await prisma.tenant.create({ data: { id: strangerId, slug: strangerId, name: 'Other tenant' } });
      const installs = await Promise.all(Array.from({ length: 4 }, () => service.installIntegration({
        tenantId: principal.tenantId, externalInstallationId: `installation_${suffix}`,
        repoReadPrincipalId: 'verified-read-principal',
        repositories: [{ providerRepoId: '101', fullName: 'verify/repo', defaultBranch: 'main', isPrivate: true }]
      }, options)));
      assert.equal(new Set(installs.map((row) => row.id)).size, 1);
      integration = installs[0];
      const bindings = await service.listRepositoryBindings(principal.tenantId);
      assert.equal(bindings.length, 1);
      binding = bindings[0];
    });

    await t.test('deduplicates concurrent scans and normalizes commit case', async () => {
      input = {
        tenantId: principal.tenantId, repositoryBindingId: binding.id,
        lane: 'FAST', targetRef: 'refs/heads/main', commitSha: 'abcdef123',
        policyVersion: 'v1', scannerSetVersion: 'v1'
      };
      const requests = await Promise.all(Array.from({ length: 6 }, (_, index) => service.createScanRequest({
        ...input, commitSha: index % 2 ? input.commitSha.toUpperCase() : input.commitSha
      })));
      assert.equal(new Set(requests.map((row) => row.id)).size, 1);
      scan = requests[0];
      assert.equal(await prisma.scanRequest.count({ where: { tenantId: principal.tenantId } }), 1);
    });

    await t.test('a separate process reads the same rows and duplicate identity', async () => {
      const program = `
        import { createRequire } from 'node:module';
        const require = createRequire(${JSON.stringify(new URL('../../apps/api/package.json', import.meta.url).href)});
        const { PrismaClient } = require('@prisma/client');
        const { ControlPlaneService } = await import(${JSON.stringify(controlModule.href)});
        const prisma = new PrismaClient();
        try {
          const service = new ControlPlaneService(prisma);
          const input = JSON.parse(process.argv[1]);
          const found = await service.getScanRequest(input.tenantId, process.argv[2]);
          const duplicate = await service.createScanRequest(input);
          console.log(JSON.stringify({found, duplicateId: duplicate.id}));
        } finally { await prisma.$disconnect(); }
      `;
      const result = JSON.parse(execFileSync(process.execPath,
        ['--input-type=module', '-e', program, JSON.stringify(input), scan.id],
        { encoding: 'utf8', timeout: 30000, env: { ...process.env, DATABASE_URL: databaseUrl } }));
      assert.deepEqual(result.found, scan);
      assert.equal(result.duplicateId, scan.id);
    });

    await t.test('rejects cross-tenant reads, creates and revocations', async () => {
      assert.deepEqual(await service.listIntegrations(strangerId), []);
      assert.deepEqual(await service.listRepositoryBindings(strangerId), []);
      await assert.rejects(service.getScanRequest(strangerId, scan.id), { status: 404 });
      await assert.rejects(service.createScanRequest({ ...input, tenantId: strangerId }), { status: 404 });
      await assert.rejects(service.removeIntegration(strangerId, integration.id), { status: 404 });
      assert.equal((await service.getScanRequest(principal.tenantId, scan.id)).status, 'QUEUED');
    });

    await t.test('revokes access atomically and preserves scan and audit history', async () => {
      await Promise.all(Array.from({ length: 3 }, () => service.removeIntegration(principal.tenantId, integration.id)));
      assert.deepEqual(await service.listRepositoryBindings(principal.tenantId), []);
      assert.equal((await service.getScanRequest(principal.tenantId, scan.id)).status, 'CANCELED');
      assert.equal(await prisma.auditEvent.count({ where: {
        tenantId: principal.tenantId, eventType: 'integration.revoked'
      } }), 1);
      await assert.rejects(service.createScanRequest(input), { status: 404 });
      await assert.rejects(service.installIntegration({
        tenantId: principal.tenantId, externalInstallationId: `installation_${suffix}`,
        repoReadPrincipalId: 'verified-read-principal'
      }, options), { status: 403 });
    });

    await t.test('suspended tenants cannot log in, query or mutate', async () => {
      await prisma.tenant.update({ where: { id: principal.tenantId }, data: { status: 'SUSPENDED' } });
      await assert.rejects(identity.persist(principal), { status: 403 });
      assert.deepEqual(await service.listIntegrations(principal.tenantId), []);
      await assert.rejects(service.getScanRequest(principal.tenantId, scan.id), { status: 404 });
      await assert.rejects(service.installIntegration({
        tenantId: principal.tenantId, externalInstallationId: 'another', repoReadPrincipalId: 'read'
      }, options), { status: 403 });
    });

    await t.test('database unavailability never returns an in-memory success', async () => {
      const unavailable = new PrismaClient({ datasources: {
        db: { url: 'postgresql://verify:unused@127.0.0.1:1/aegisai_verify?connect_timeout=1' }
      } });
      try {
        const offline = new ControlPlaneService(unavailable);
        await assert.rejects(offline.listIntegrations(principal.tenantId));
        await assert.rejects(offline.createScanRequest(input));
      } finally { await unavailable.$disconnect(); }
    });
  } finally {
    // Only UUID-scoped fixtures in the explicitly allowlisted test database.
    await prisma.tenant.deleteMany({ where: { id: { in: [principal.tenantId, strangerId] } } });
    await prisma.user.deleteMany({ where: { id: principal.userId } });
    await prisma.$disconnect();
  }
});
