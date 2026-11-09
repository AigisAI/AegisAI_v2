import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import test from 'node:test';

const databaseUrl = process.env.PERSISTENCE_TEST_DATABASE_URL;
assert.ok(databaseUrl, 'Dedicated verification database required');
assert.match(new URL(databaseUrl).pathname, /^\/aegisai_(verify|ci|test)$/);
process.env.DATABASE_URL = databaseUrl;
const require = createRequire(new URL('../../apps/api/package.json', import.meta.url));
const { PrismaClient } = require('@prisma/client');
const { ControlPlaneService } = await import('../../apps/api/dist/control-plane/control-plane.service.js');
const queueModule = new URL('../../apps/api/dist/dispatch/scan-dispatch.service.js', import.meta.url);
const { ScanDispatchService } = await import(queueModule.href);

test('Durable dispatch queue against PostgreSQL', async (t) => {
  const prisma = new PrismaClient();
  const service = new ControlPlaneService(prisma);
  const queue = new ScanDispatchService(prisma);

  async function fixture(tenantCount, run) {
    const tenants = Array.from({ length: tenantCount }, () => `queue_test_${randomUUID()}`);
    try {
      // Global-capacity tests require an isolated verification DB, never delete unrelated rows.
      assert.equal(await prisma.scanDispatchJob.count({ where: { status: { in: ['PENDING', 'LEASED'] } } }), 0,
        'Verification DB has unrelated jobs; run suites serially');
      const inputs = [];
      const integrations = [];
      for (const tenantId of tenants) {
        await prisma.tenant.create({ data: { id: tenantId, slug: tenantId, name: 'Queue verification' } });
        integrations.push(await service.installIntegration({
          tenantId, externalInstallationId: randomUUID(), repoReadPrincipalId: 'verified-test-read',
          repositories: [{ providerRepoId: '100', fullName: 'verify/queue', defaultBranch: 'main', isPrivate: true }]
        }, { provider: 'GITHUB', integrationType: 'GITHUB_APP' }));
        const [binding] = await service.listRepositoryBindings(tenantId);
        inputs.push({ tenantId, repositoryBindingId: binding.id, lane: 'FAST', targetRef: 'main',
          commitSha: 'a'.repeat(40), policyVersion: 'v1', scannerSetVersion: 'v1' });
      }
      await run({ tenants, inputs, integrations });
    } finally {
      await prisma.tenant.deleteMany({ where: { id: { in: tenants } } });
    }
  }

  async function ready(jobId) {
    await prisma.scanDispatchJob.update({ where: { id: jobId }, data: { availableAt: new Date(0) } });
  }

  try {
    await t.test('creates one atomic outbox job under concurrent duplicate requests', () => fixture(1, async ({ inputs }) => {
      const scans = await Promise.all(Array.from({ length: 6 }, () => service.createScanRequest(inputs[0])));
      assert.equal(new Set(scans.map((scan) => scan.id)).size, 1);
      const jobs = await prisma.scanDispatchJob.findMany({ where: { tenantId: inputs[0].tenantId } });
      assert.equal(jobs.length, 1);
      assert.equal(jobs[0].scanRequestId, scans[0].id);
      assert.equal(jobs[0].status, 'PENDING');
    }));

    await t.test('rolls back the scan when dispatch insertion fails', () => fixture(1, async ({ inputs }) => {
      const failing = new Proxy(prisma, { get(target, key) {
        if (key !== '$transaction') return Reflect.get(target, key);
        return (operation, options) => prisma.$transaction((tx) => operation(new Proxy(tx, { get(transaction, field) {
          if (field === 'scanDispatchJob') return { upsert: async () => { throw new Error('injected dispatch failure'); } };
          return Reflect.get(transaction, field);
        } })), options);
      } });
      await assert.rejects(new ControlPlaneService(failing).createScanRequest(inputs[0]), /injected dispatch failure/);
      assert.equal(await prisma.scanRequest.count({ where: { tenantId: inputs[0].tenantId } }), 0);
      assert.equal(await prisma.scanDispatchJob.count({ where: { tenantId: inputs[0].tenantId } }), 0);
    }));

    await t.test('enforces global and tenant capacity under concurrent claims', () => fixture(3, async ({ inputs }) => {
      for (const input of inputs) {
        await service.createScanRequest(input);
        await service.createScanRequest({ ...input, targetRef: 'other' });
      }
      const leases = (await Promise.all(Array.from({ length: 6 }, (_, i) => queue.claim(`worker_${i}`)))).filter(Boolean);
      assert.equal(leases.length, 2);
      assert.equal(new Set(leases.map((lease) => lease.jobId)).size, 2);
      assert.equal(new Set(leases.map((lease) => lease.tenantId)).size, 2);
      assert.equal(await queue.claim('capacity_full'), null);
      await queue.acknowledge(leases[0].tenantId, leases[0].jobId, leases[0].leaseToken);
      assert.ok(await queue.claim('capacity_released'));
    }));

    await t.test('rejects cross-tenant and forged lease operations', () => fixture(2, async ({ inputs, tenants }) => {
      await service.createScanRequest(inputs[0]);
      const lease = await queue.claim('worker_owned');
      assert.ok(lease);
      for (const method of ['acknowledge', 'heartbeat']) {
        await assert.rejects(queue[method](tenants[1], lease.jobId, lease.leaseToken), { status: 409 });
        await assert.rejects(queue[method](tenants[0], lease.jobId, randomUUID()), { status: 409 });
      }
      await assert.rejects(queue.fail(tenants[1], lease.jobId, lease.leaseToken, 'UPSTREAM_UNAVAILABLE'), { status: 409 });
      await assert.rejects(queue.fail(tenants[0], lease.jobId, lease.leaseToken, 'raw-secret'), { status: 400 });
      assert.equal((await prisma.scanDispatchJob.findUnique({ where: { id: lease.jobId } })).status, 'LEASED');
    }));

    await t.test('expires old ownership, backs off and fences the previous attempt', () => fixture(1, async ({ inputs }) => {
      await service.createScanRequest(inputs[0]);
      const first = await queue.claim('worker_crashed');
      const heartbeat = await queue.heartbeat(first.tenantId, first.jobId, first.leaseToken);
      assert.equal(heartbeat.leaseToken, first.leaseToken);
      await prisma.scanDispatchJob.update({ where: { id: first.jobId }, data: { leaseExpiresAt: new Date(0) } });
      await assert.rejects(queue.acknowledge(first.tenantId, first.jobId, first.leaseToken), { status: 409 });
      assert.equal(await queue.claim('recover_expiry'), null); // Backoff starts from DB time.
      const waiting = await prisma.scanDispatchJob.findUnique({ where: { id: first.jobId } });
      assert.equal(waiting.status, 'PENDING');
      assert.equal(waiting.lastErrorCode, 'LEASE_EXPIRED');
      assert.equal(waiting.leaseToken, null);
      await ready(first.jobId);
      const second = await queue.claim('worker_replacement');
      assert.equal(second.attempt, 2);
      assert.notEqual(second.leaseToken, first.leaseToken);
      await assert.rejects(queue.heartbeat(first.tenantId, first.jobId, first.leaseToken), { status: 409 });
      await queue.acknowledge(second.tenantId, second.jobId, second.leaseToken);
      assert.equal((await service.getScanRequest(inputs[0].tenantId, second.scanRequestId)).status, 'PLANNING');
      await service.createScanRequest(inputs[0]);
      assert.equal(await queue.claim('duplicate_request'), null); // Acknowledged jobs are never recreated.
    }));

    await t.test('dead-letters after five failed attempts with bounded error metadata', () => fixture(1, async ({ inputs }) => {
      const scan = await service.createScanRequest(inputs[0]);
      let jobId;
      for (let attempt = 1; attempt <= 5; attempt += 1) {
        if (jobId) await ready(jobId);
        const lease = await queue.claim('worker_retry');
        assert.ok(lease);
        assert.equal(lease.attempt, attempt);
        jobId = lease.jobId;
        await queue.fail(lease.tenantId, jobId, lease.leaseToken, 'UPSTREAM_UNAVAILABLE');
      }
      const dead = await prisma.scanDispatchJob.findUnique({ where: { id: jobId } });
      assert.equal(dead.status, 'DEAD');
      assert.equal(dead.attempts, 5);
      assert.equal(dead.leaseToken, null);
      assert.equal((await service.getScanRequest(inputs[0].tenantId, scan.id)).status, 'FAILED');
      assert.equal(await queue.claim('no_sixth_attempt'), null);
      const events = await prisma.auditEvent.findMany({ where: { tenantId: inputs[0].tenantId } });
      assert.equal(events.filter((event) => event.eventType === 'scan.dispatch.dead').length, 1);
      assert.ok(events.every((event) => !JSON.stringify(event.metadata).includes('leaseToken')));
      assert.equal(events.length, 5);
    }));

    await t.test('revocation cancels queued and leased jobs, preserving history', () => fixture(1, async ({ inputs, integrations }) => {
      await service.createScanRequest(inputs[0]);
      await service.createScanRequest({ ...inputs[0], targetRef: 'other' });
      const lease = await queue.claim('worker_revoked');
      await service.removeIntegration(inputs[0].tenantId, integrations[0].id);
      await assert.rejects(queue.acknowledge(lease.tenantId, lease.jobId, lease.leaseToken), { status: 409 });
      assert.equal(await queue.claim('cannot_claim_revoked'), null);
      const jobs = await prisma.scanDispatchJob.findMany({ where: { tenantId: inputs[0].tenantId } });
      assert.equal(jobs.length, 2);
      assert.ok(jobs.every((job) => job.status === 'CANCELED' && job.leaseToken === null));
      assert.equal(await prisma.scanRequest.count({ where: { tenantId: inputs[0].tenantId } }), 2);
    }));

    await t.test('suspended tenants cannot claim or retain leases', () => fixture(1, async ({ inputs }) => {
      await service.createScanRequest(inputs[0]);
      const lease = await queue.claim('worker_suspended');
      await prisma.tenant.update({ where: { id: inputs[0].tenantId }, data: { status: 'SUSPENDED' } });
      await assert.rejects(queue.heartbeat(lease.tenantId, lease.jobId, lease.leaseToken), { status: 409 });
      assert.equal(await queue.claim('suspended_cleanup'), null);
      assert.equal((await prisma.scanDispatchJob.findUnique({ where: { id: lease.jobId } })).status, 'CANCELED');
    }));

    await t.test('separate process recovers durable pending jobs', () => fixture(1, async ({ inputs }) => {
      const scan = await service.createScanRequest(inputs[0]);
      const program = `
        import { createRequire } from 'node:module';
        const require = createRequire(${JSON.stringify(new URL('../../apps/api/package.json', import.meta.url).href)});
        const { PrismaClient } = require('@prisma/client');
        const { ScanDispatchService } = await import(${JSON.stringify(queueModule.href)});
        const prisma = new PrismaClient();
        try {
          const lease = await new ScanDispatchService(prisma).claim('restarted_process');
          console.log(JSON.stringify({ scanRequestId: lease?.scanRequestId, attempt: lease?.attempt }));
        } finally { await prisma.$disconnect(); }
      `;
      const found = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', program],
        { encoding: 'utf8', timeout: 30000, env: { ...process.env, DATABASE_URL: databaseUrl } }));
      assert.deepEqual(found, { scanRequestId: scan.id, attempt: 1 });
    }));

    await t.test('database constraints reject tenant mismatch and malformed leases', () => fixture(2, async ({ inputs, tenants }) => {
      const scan = await service.createScanRequest(inputs[0]);
      const job = await prisma.scanDispatchJob.findUnique({ where: { scanRequestId: scan.id } });
      await assert.rejects(prisma.scanDispatchJob.update({ where: { id: job.id }, data: { tenantId: tenants[1] } }));
      await assert.rejects(prisma.scanDispatchJob.update({ where: { id: job.id }, data: { status: 'LEASED' } }));
      await assert.rejects(prisma.scanDispatchJob.update({ where: { id: job.id }, data: { attempts: 6 } }));
      assert.equal((await prisma.scanDispatchJob.findUnique({ where: { id: job.id } })).status, 'PENDING');
    }));
  } finally {
    await prisma.$disconnect();
  }
});
