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
  observabilityCompose: new URL('../../deploy/oracle/docker-compose.observability.yml', import.meta.url),
  deployScript: new URL('../../deploy/oracle/deploy.sh', import.meta.url),
  envExample: new URL('../../deploy/oracle/.env.example', import.meta.url),
  bootstrapDoc: new URL('../../deploy/oracle/BOOTSTRAP.md', import.meta.url),
  bootstrapScript: new URL('../../deploy/oracle/bootstrap-infra.sh', import.meta.url),
  bootstrapObservabilityScript: new URL('../../deploy/oracle/bootstrap-observability.sh', import.meta.url),
  lokiConfig: new URL('../../deploy/oracle/loki-config.yml', import.meta.url),
  promtailConfig: new URL('../../deploy/oracle/promtail-config.yml', import.meta.url),
  grafanaDatasource: new URL('../../deploy/oracle/grafana/provisioning/datasources/loki.yml', import.meta.url)
};

const readNormalizedText = (fileUrl) => readFileSync(fileUrl, 'utf8').replace(/\r\n/g, '\n');

test('cd workflow and oracle deployment files enforce the split infra/app deploy path', () => {
  for (const [name, fileUrl] of Object.entries(files)) {
    assert.equal(existsSync(fileUrl), true, `Expected ${name} file to exist at ${fileUrl.pathname}`);
  }

  const workflow = readNormalizedText(files.workflow);
  const apiDockerfile = readNormalizedText(files.apiDockerfile);
  const webDockerfile = readNormalizedText(files.webDockerfile);
  const infraCompose = readNormalizedText(files.infraCompose);
  const appCompose = readNormalizedText(files.appCompose);
  const observabilityCompose = readNormalizedText(files.observabilityCompose);
  const deployScript = readNormalizedText(files.deployScript);
  const envExample = readNormalizedText(files.envExample);
  const bootstrapDoc = readNormalizedText(files.bootstrapDoc);
  const bootstrapScript = readNormalizedText(files.bootstrapScript);
  const bootstrapObservabilityScript = readNormalizedText(files.bootstrapObservabilityScript);
  const lokiConfig = readNormalizedText(files.lokiConfig);
  const promtailConfig = readNormalizedText(files.promtailConfig);
  const grafanaDatasource = readNormalizedText(files.grafanaDatasource);
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
  assert.match(workflow, /docker buildx imagetools inspect/);
  assert.match(workflow, /grep -q 'linux\/amd64'/);
  assert.match(workflow, /grep -q 'linux\/arm64'/);
  assert.match(workflow, /Validate deployment secrets/);
  assert.match(workflow, /Missing required GitHub Actions secrets for production deploy/);
  assert.match(workflow, /ORACLE_VPS_KNOWN_HOSTS/);
  assert.match(workflow, /TEAMS_WEBHOOK_URL/);
  assert.doesNotMatch(workflow, /ssh-keyscan/);
  assert.match(workflow, /scp /);
  assert.match(workflow, /ssh /);
  assert.match(workflow, /if:\s*always\(\)/);
  assert.match(workflow, /rm -f \.\/\.oracle-deploy\.env/);
  assert.match(workflow, /docker-compose\.observability\.yml/);
  assert.match(workflow, /bootstrap-observability\.sh/);
  assert.match(workflow, /loki-config\.yml/);
  assert.match(workflow, /promtail-config\.yml/);
  assert.match(workflow, /grafana\/provisioning\/datasources\/loki\.yml/);
  assert.match(workflow, /Notify Teams/);
  assert.match(workflow, /continue-on-error:\s*true/);
  assert.match(workflow, /curl -sSf/);
  assert.doesNotMatch(deployJobEnvBlock, /ORACLE_VPS_SSH_PRIVATE_KEY/);
  assert.match(workflow, /Configure SSH access[\s\S]*env:\s*[\s\S]*ORACLE_VPS_SSH_PRIVATE_KEY/);
  assert.match(workflow, /docker-compose\.infra\.yml/);
  assert.match(workflow, /docker-compose\.app\.yml/);

  assert.match(apiDockerfile, /FROM node:20-alpine/);
  assert.match(apiDockerfile, /corepack pnpm --filter @aegisai\/api build/);
  assert.match(apiDockerfile, /CMD \["node", "apps\/api\/dist\/apps\/api\/src\/main\.js"\]/);

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

  assert.match(observabilityCompose, /grafana\/grafana/);
  assert.match(observabilityCompose, /grafana:\n[\s\S]*- "3001:3000"/m);
  assert.match(observabilityCompose, /grafana-data:/);
  assert.match(observabilityCompose, /grafana\/provisioning/);
  assert.match(observabilityCompose, /grafana_admin_user/i);
  assert.match(observabilityCompose, /grafana_admin_password/i);
  assert.match(observabilityCompose, /grafana\/loki-docker-driver|grafana\/loki|loki:3/i);
  assert.match(observabilityCompose, /promtail/i);
  assert.match(observabilityCompose, /\/var\/lib\/docker\/containers/);
  assert.match(observabilityCompose, /\/var\/run\/docker\.sock/);

  assert.match(deployScript, /docker login ghcr\.io/);
  assert.match(deployScript, /docker compose -f docker-compose\.app\.yml pull/);
  assert.match(deployScript, /docker compose -f docker-compose\.app\.yml up -d --remove-orphans/);
  assert.doesNotMatch(deployScript, /docker-compose\.prod\.yml/);

  assert.match(envExample, /DATABASE_URL=postgresql:\/\/postgres:/);
  assert.match(envExample, /REDIS_URL=redis:\/\/redis:6379/);
  assert.match(envExample, /SESSION_SECRET=/);
  assert.match(envExample, /TOKEN_ENCRYPTION_KEY=/);
  assert.match(envExample, /TEAMS_WEBHOOK_URL=/);
  assert.match(envExample, /GRAFANA_ADMIN_USER=/);
  assert.match(envExample, /GRAFANA_ADMIN_PASSWORD=/);

  assert.match(bootstrapDoc, /Oracle Cloud/i);
  assert.match(bootstrapDoc, /ORACLE_VPS_HOST/);
  assert.match(bootstrapDoc, /ORACLE_VPS_KNOWN_HOSTS/);
  assert.match(bootstrapDoc, /GHCR_READ_TOKEN/);
  assert.match(bootstrapDoc, /TEAMS_WEBHOOK_URL/);
  assert.match(bootstrapDoc, /Grafana/i);
  assert.match(bootstrapDoc, /Loki/i);
  assert.match(bootstrapDoc, /docker-compose\.infra\.yml/);
  assert.match(bootstrapDoc, /docker-compose\.observability\.yml/);
  assert.match(bootstrapDoc, /bootstrap-infra\.sh/);
  assert.match(bootstrapDoc, /bootstrap-observability\.sh/);
  assert.match(bootstrapDoc, /docker compose -f docker-compose\.infra\.yml up -d/);
  assert.match(bootstrapDoc, /docker compose -f docker-compose\.observability\.yml up -d/);
  assert.match(bootstrapDoc, /\.env/);

  assert.match(bootstrapScript, /^#!\/bin\/sh/m);
  assert.match(bootstrapScript, /docker compose -f docker-compose\.infra\.yml up -d/);
  assert.match(bootstrapScript, /docker-compose\.infra\.yml/);

  assert.match(bootstrapObservabilityScript, /^#!\/bin\/sh/m);
  assert.match(bootstrapObservabilityScript, /docker compose -f docker-compose\.observability\.yml up -d/);
  assert.match(bootstrapObservabilityScript, /docker-compose\.observability\.yml/);

  assert.match(lokiConfig, /auth_enabled:\s*false/);
  assert.match(lokiConfig, /http_listen_port:\s*3100/);

  assert.match(promtailConfig, /docker_sd_configs:/);
  assert.match(promtailConfig, /unix:\/\/\/var\/run\/docker\.sock/);
  assert.match(promtailConfig, /__meta_docker_container_name/);
  assert.match(promtailConfig, /loki\/api\/v1\/push/);

  assert.match(grafanaDatasource, /type:\s*loki/);
  assert.match(grafanaDatasource, /url:\s*http:\/\/loki:3100/);
});
