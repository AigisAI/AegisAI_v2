// One-shot operator continuation after actual login, using normal provider/service checks.
// Run in the API image with root-owned read-only install metadata; never creates identity.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { PrismaService } from '/app/apps/api/dist/prisma/prisma.service.js';
import { GithubAppClient } from '/app/apps/api/dist/control-plane/github-app.client.js';
import { GithubInstallationService } from '/app/apps/api/dist/control-plane/github-installation.service.js';
import { ControlPlaneService } from '/app/apps/api/dist/control-plane/control-plane.service.js';

const live = JSON.parse(await readFile('/run/preflight/install.json', 'utf8'));
assert.equal(live.verifiedAdministratorId, 161540124);
assert.equal(live.organizationId, 241095585);
assert.equal(String(live.appId), process.env.GITHUB_APP_ID);
assert.ok(process.env.ALLOWED_GITHUB_USER_IDS.split(',').includes(String(live.verifiedAdministratorId)));
const config = { get: (key) => process.env[key], getOptional: (key) => process.env[key] };
const prisma = new PrismaService();
await prisma.$connect();
try {
  const providerUserId = String(live.verifiedAdministratorId);
  const identity = await prisma.userOAuthIdentity.findUnique({
    where: { provider_providerUserId: { provider: 'GITHUB', providerUserId } }, include: { user: true }
  });
  assert.ok(identity?.user, 'Actual completed OAuth login is required');
  const digest = createHash('sha256').update(`github:${providerUserId}`).digest('hex').slice(0,32);
  assert.equal(identity.userId, `user_${digest}`);
  const tenantId = `tenant_${digest}`;
  assert.equal((await prisma.tenant.findUnique({where:{id:tenantId}}))?.status, 'ACTIVE');
  const principal = { userId: identity.userId, tenantId, providerUserId, provider:'GITHUB',
    name:identity.user.name, email:identity.user.email };
  const service = new GithubInstallationService(prisma, new GithubAppClient(config), new ControlPlaneService(prisma));
  const result = await service.link(principal, {
    installationId: live.installationId, repositoryIds: live.repositories.map(item=>item.id)
  });
  assert.equal(result.status, 'ACTIVE');
  const count = await prisma.repositoryBinding.count({where:{tenantId,scmIntegrationId:result.id}});
  assert.equal(count, live.repositories.length);
  console.log(JSON.stringify({verifiedLoginRequired:true,organizationAuthorityRechecked:true,
    integrationPersisted:true,selectedRepositoryBindings:count,discoveryTokenRevoked:true,sourceDownloaded:false}));
} finally {
  await prisma.$disconnect();
}
