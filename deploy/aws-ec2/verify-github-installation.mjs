// Run only in the target API image with root-owned read-only preflight mounts.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { GithubAppClient } from '/app/apps/api/dist/control-plane/github-app.client.js';
import { loadRuntimeSecrets } from '/app/apps/api/dist/data-security/runtime-secrets.js';

await loadRuntimeSecrets('broker');

const live = JSON.parse(await readFile('/run/preflight/install.json', 'utf8'));
assert.equal(live.verifiedAdministratorId, 161540124);
assert.equal(live.organizationId, 241095585);
const config = {
  get: (key) => process.env[key],
  getOptional: (key) => process.env[key]
};
assert.equal(String(live.appId), config.get('GITHUB_APP_ID'));
const result = await new GithubAppClient(config).discoverInstallation(
  live.installationId, live.repositories.map((repository) => repository.id),
  String(live.verifiedAdministratorId)
);
assert.deepEqual(result.map((repository) => Number(repository.providerRepoId)).sort((a, b) => a - b),
  live.repositories.map((repository) => repository.id).sort((a, b) => a - b));
const repository = result.find((item) => item.providerRepoId === '1175038477');
assert.ok(repository);
const commit = await new GithubAppClient(config).resolveBranchCommit(
  live.installationId, Number(repository.providerRepoId), String(live.verifiedAdministratorId), repository.defaultBranch
);
assert.match(commit.commitSha, /^[a-f0-9]{40}$/);
assert.equal(commit.targetRef, repository.defaultBranch);
const resource = await new GithubAppClient(config).openReadSession(
  live.installationId, Number(repository.providerRepoId), String(live.verifiedAdministratorId),
  Date.now()+60_000, async()=>{throw new Error('Upstream revocation unconfirmed');}
);
// No transfer or source request: validate actual upstream resource creation/revocation only.
await resource.revoke();
console.log(JSON.stringify({ githubOrganizationInstallation: 'verified',
  selectedRepositoryCount: result.length, discoveryTokenRevoked: true,
  immutableCommitResolved: true, resolutionTokenRevoked: true,
  upstreamReadResourceRevoked: true, sourceDownloaded: false }));
