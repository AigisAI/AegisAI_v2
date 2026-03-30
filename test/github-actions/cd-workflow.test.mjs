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
  envExample: new URL('../../deploy/oracle/.env.example', import.meta.url),
  bootstrapDoc: new URL('../../deploy/oracle/BOOTSTRAP.md', import.meta.url),
  bootstrapScript: new URL('../../deploy/oracle/bootstrap-infra.sh', import.meta.url),
  alloyConfig: new URL('../../deploy/oracle/alloy/config.alloy', import.meta.url),
  installAlloy: new URL('../../deploy/oracle/install-alloy.sh', import.meta.url)
};

const readNormalizedText = (fileUrl) => readFileSync(fileUrl, 'utf8').replace(/\r\n/g, '\n');

test('cd workflow and oracle deployment files describe the grafana cloud plus alloy deploy path', () => {
  for (const [name, fileUrl] of Object.entries(files)) {
    assert.equal(existsSync(fileUrl), true, `Expected ${name} file to exist at ${fileUrl.pathname}`);
  }

  const workflow = readNormalizedText(files.workflow);
  const apiDockerfile = readNormalizedText(files.apiDockerfile);
  const webDockerfile = readNormalizedText(files.webDockerfile);
  const webNginx = readNormalizedText(files.webNginx);
  const infraCompose = readNormalizedText(files.infraCompose);
  const appCompose = readNormalizedText(files.appCompose);
  const deployScript = readNormalizedText(files.deployScript);
  const envExample = readNormalizedText(files.envExample);
  const bootstrapDoc = readNormalizedText(files.bootstrapDoc);
  const bootstrapScript = readNormalizedText(files.bootstrapScript);
  const alloyConfig = readNormalizedText(files.alloyConfig);
  const installAlloy = readNormalizedText(files.installAlloy);
  const deployJobEnvBlock = workflow.match(/deploy:\n[\s\S]*?environment:\s*production\n\s*env:\n([\s\S]*?)\n\s*steps:/)?.[1] ?? '';

  assert.match(workflow, /^name:\s*CD/m);
  assert.match(workflow, /push:\s*[\s\S]*branches:\s*[\s\S]*- main/m);
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /docker\/login-action@v3/);
  assert.match(workflow, /docker\/setup-qemu-action@v3/);
  assert.match(workflow, /docker\/build-push-action@v6/);
  assert.match(workflow, /ghcr\.io/);
  assert.match(workflow, /platforms:\s*linux\/amd64,linux\/arm64/m);
  assert.match(workflow, /Verify multi-arch image manifests/);
  assert.match(workflow, /Validate deployment secrets/);
  assert.match(workflow, /Missing required GitHub Actions secrets for production deploy/);
  assert.match(workflow, /ORACLE_VPS_KNOWN_HOSTS/);
  assert.match(workflow, /TEAMS_WEBHOOK_URL/);
  assert.doesNotMatch(workflow, /ssh-keyscan/);
  assert.match(workflow, /scp /);
  assert.match(workflow, /ssh /);
  assert.match(workflow, /if:\s*always\(\)/);
  assert.match(workflow, /Notify Teams/);
  assert.match(workflow, /continue-on-error:\s*true/);
  assert.match(workflow, /curl -sSf/);
  assert.doesNotMatch(deployJobEnvBlock, /ORACLE_VPS_SSH_PRIVATE_KEY/);
  assert.match(workflow, /Configure SSH access[\s\S]*env:\s*[\s\S]*ORACLE_VPS_SSH_PRIVATE_KEY/);
  assert.match(workflow, /docker-compose\.infra\.yml/);
  assert.match(workflow, /docker-compose\.app\.yml/);
  assert.match(workflow, /deploy\/oracle\/alloy\/config\.alloy/);
  assert.match(workflow, /deploy\/oracle\/install-alloy\.sh/);
  assert.doesNotMatch(workflow, /docker-compose\.observability\.yml/);
  assert.doesNotMatch(workflow, /bootstrap-observability\.sh/);
  assert.doesNotMatch(workflow, /loki-config\.yml/);
  assert.doesNotMatch(workflow, /promtail-config\.yml/);
  assert.doesNotMatch(workflow, /grafana\/provisioning/);

  assert.match(apiDockerfile, /FROM node:20-bookworm-slim AS builder/);
  assert.match(apiDockerfile, /FROM node:20-bookworm-slim AS runner/);
  assert.match(apiDockerfile, /apt-get install -y --no-install-recommends openssl ca-certificates/);
  assert.match(apiDockerfile, /corepack pnpm --filter @aegisai\/api build/);
  assert.match(apiDockerfile, /CMD \["node", "apps\/api\/dist\/apps\/api\/src\/main\.js"\]/);

  assert.match(webDockerfile, /FROM nginx:1\.27-alpine/);
  assert.match(webDockerfile, /COPY --from=builder \/app\/apps\/web\/dist/);
  assert.match(webNginx, /resolver 127\.0\.0\.11 ipv6=off valid=10s;/);
  assert.match(webNginx, /set \$api_upstream api:3000;/);
  assert.match(webNginx, /proxy_pass http:\/\/\$api_upstream;/);

  assert.match(infraCompose, /postgres:16-alpine/);
  assert.match(infraCompose, /redis:7-alpine/);
  assert.match(infraCompose, /postgres-data:/);
  assert.match(infraCompose, /redis-data:/);
  assert.match(infraCompose, /^name:\s*aegisai-infra/m);
  assert.match(infraCompose, /name:\s*aegisai-platform/m);

  assert.match(appCompose, /ghcr\.io\/\$\{GHCR_OWNER\}\/aegisai-api:\$\{IMAGE_TAG\}/);
  assert.match(appCompose, /ghcr\.io\/\$\{GHCR_OWNER\}\/aegisai-web:\$\{IMAGE_TAG\}/);
  assert.match(appCompose, /^name:\s*aegisai-app/m);
  assert.match(appCompose, /external:\s*true/);
  assert.match(appCompose, /api:\n[\s\S]*env_file:/m);
  assert.match(appCompose, /api:\n[\s\S]*dns_opt:\n[\s\S]*- ndots:0/m);
  assert.match(appCompose, /api:\n[\s\S]*healthcheck:\n[\s\S]*127\.0\.0\.1:3000\/api\/health/m);
  assert.match(appCompose, /web:\n[\s\S]*ports:\n[\s\S]*- "80:80"/m);
  assert.match(appCompose, /web:\n[\s\S]*dns_opt:\n[\s\S]*- ndots:0/m);
  assert.match(appCompose, /web:\n[\s\S]*depends_on:\n[\s\S]*api:\n[\s\S]*condition:\s*service_healthy/m);
  assert.match(appCompose, /web:\n[\s\S]*healthcheck:\n[\s\S]*127\.0\.0\.1\/api\/health/m);

  assert.match(deployScript, /docker login ghcr\.io/);
  assert.match(deployScript, /docker compose -f docker-compose\.app\.yml pull/);
  assert.match(deployScript, /docker compose -f docker-compose\.app\.yml up -d/);
  assert.doesNotMatch(deployScript, /--remove-orphans/);

  assert.match(envExample, /DATABASE_URL=postgresql:\/\/postgres:/);
  assert.match(envExample, /REDIS_URL=redis:\/\/redis:6379/);
  assert.match(envExample, /SESSION_SECRET=/);
  assert.match(envExample, /TOKEN_ENCRYPTION_KEY=/);
  assert.match(envExample, /GRAFANA_CLOUD_LOGS_URL=/);
  assert.match(envExample, /GRAFANA_CLOUD_LOGS_USERNAME=/);
  assert.match(envExample, /GRAFANA_CLOUD_LOGS_PASSWORD=/);
  assert.match(envExample, /GRAFANA_CLOUD_METRICS_URL=/);
  assert.match(envExample, /GRAFANA_CLOUD_METRICS_USERNAME=/);
  assert.match(envExample, /GRAFANA_CLOUD_METRICS_PASSWORD=/);
  assert.match(envExample, /GRAFANA_CLOUD_INSTANCE_NAME=/);
  assert.doesNotMatch(envExample, /GRAFANA_ADMIN_USER=/);
  assert.doesNotMatch(envExample, /GRAFANA_ADMIN_PASSWORD=/);

  assert.match(bootstrapDoc, /Grafana Cloud/i);
  assert.match(bootstrapDoc, /Grafana Alloy/i);
  assert.match(bootstrapDoc, /Docker integration/i);
  assert.match(bootstrapDoc, /Explore/i);
  assert.match(bootstrapDoc, /TEAMS_WEBHOOK_URL/);
  assert.match(bootstrapDoc, /aegisai-app/i);
  assert.match(bootstrapDoc, /aegisai-infra/i);
  assert.doesNotMatch(bootstrapDoc, /Grafana is reachable on `http:\/\/<server-ip>:3001`/i);
  assert.doesNotMatch(bootstrapDoc, /docker-compose\.observability\.yml/);
  assert.doesNotMatch(bootstrapDoc, /bootstrap-observability\.sh/);

  assert.match(bootstrapScript, /^#!\/bin\/sh/m);
  assert.match(bootstrapScript, /docker compose -f docker-compose\.infra\.yml up -d/);
  assert.match(bootstrapScript, /docker-compose\.infra\.yml/);

  assert.match(alloyConfig, /discovery\.docker/);
  assert.match(alloyConfig, /loki\.source\.docker/);
  assert.match(alloyConfig, /prometheus\.exporter\.cadvisor/);
  assert.match(alloyConfig, /prometheus\.remote_write/);
  assert.match(alloyConfig, /GRAFANA_CLOUD_LOGS_/);
  assert.match(alloyConfig, /GRAFANA_CLOUD_METRICS_/);

  assert.match(installAlloy, /^#!\/bin\/sh/m);
  assert.match(installAlloy, /apt-get install -y alloy/);
  assert.match(installAlloy, /systemctl enable alloy/);
  assert.match(installAlloy, /systemctl restart alloy/);
});
