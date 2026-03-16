import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const files = {
  workflow: new URL('../../.github/workflows/cd.yml', import.meta.url),
  dockerIgnore: new URL('../../.dockerignore', import.meta.url),
  apiDockerfile: new URL('../../apps/api/Dockerfile', import.meta.url),
  webDockerfile: new URL('../../apps/web/Dockerfile', import.meta.url),
  webNginx: new URL('../../apps/web/nginx.conf', import.meta.url),
  infraCompose: new URL('../../deploy/oracle/docker-compose.infra.yml', import.meta.url),
  appCompose: new URL('../../deploy/oracle/docker-compose.app.yml', import.meta.url),
  deployScript: new URL('../../deploy/oracle/deploy.sh', import.meta.url),
  envExample: new URL('../../deploy/oracle/.env.example', import.meta.url)
};

test('cd workflow and oracle deployment files enforce the split infra/app deploy path', () => {
  for (const [name, fileUrl] of Object.entries(files)) {
    assert.equal(existsSync(fileUrl), true, `Expected ${name} file to exist at ${fileUrl.pathname}`);
  }

  const workflow = readFileSync(files.workflow, 'utf8');
  const apiDockerfile = readFileSync(files.apiDockerfile, 'utf8');
  const webDockerfile = readFileSync(files.webDockerfile, 'utf8');
  const infraCompose = readFileSync(files.infraCompose, 'utf8');
  const appCompose = readFileSync(files.appCompose, 'utf8');
  const deployScript = readFileSync(files.deployScript, 'utf8');
  const envExample = readFileSync(files.envExample, 'utf8');

  assert.match(workflow, /^name:\s*CD/m);
  assert.match(workflow, /push:\s*[\s\S]*branches:\s*[\s\S]*- main/m);
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /docker\/login-action@v3/);
  assert.match(workflow, /docker\/build-push-action@v6/);
  assert.match(workflow, /ghcr\.io/);
  assert.match(workflow, /ssh-keyscan/);
  assert.match(workflow, /scp /);
  assert.match(workflow, /ssh /);
  assert.match(workflow, /docker-compose\.infra\.yml/);
  assert.match(workflow, /docker-compose\.app\.yml/);

  assert.match(apiDockerfile, /FROM node:20-alpine/);
  assert.match(apiDockerfile, /corepack pnpm --filter @aegisai\/api build/);
  assert.match(apiDockerfile, /CMD \["node", "apps\/api\/dist\/main\.js"\]/);

  assert.match(webDockerfile, /FROM nginx:1\.27-alpine/);
  assert.match(webDockerfile, /COPY --from=builder \/app\/apps\/web\/dist/);

  assert.match(infraCompose, /postgres:16-alpine/);
  assert.match(infraCompose, /redis:7-alpine/);
  assert.match(infraCompose, /postgres-data:/);
  assert.match(infraCompose, /redis-data:/);
  assert.match(infraCompose, /name:\s*aegisai-platform/m);

  assert.match(appCompose, /ghcr\.io\/\$\{GHCR_OWNER\}\/aegisai-api:\$\{IMAGE_TAG\}/);
  assert.match(appCompose, /ghcr\.io\/\$\{GHCR_OWNER\}\/aegisai-web:\$\{IMAGE_TAG\}/);
  assert.match(appCompose, /external:\s*true/);
  assert.match(appCompose, /api:\n[\s\S]*env_file:/m);
  assert.match(appCompose, /web:\n[\s\S]*ports:\n[\s\S]*- "80:80"/m);

  assert.match(deployScript, /docker login ghcr\.io/);
  assert.match(deployScript, /docker compose -f docker-compose\.app\.yml pull/);
  assert.match(deployScript, /docker compose -f docker-compose\.app\.yml up -d --remove-orphans/);
  assert.doesNotMatch(deployScript, /docker-compose\.prod\.yml/);

  assert.match(envExample, /DATABASE_URL=postgresql:\/\/postgres:/);
  assert.match(envExample, /REDIS_URL=redis:\/\/redis:6379/);
  assert.match(envExample, /SESSION_SECRET=/);
  assert.match(envExample, /TOKEN_ENCRYPTION_KEY=/);
});
