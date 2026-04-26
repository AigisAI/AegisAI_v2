import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const dockerfile = readFileSync(new URL('../../apps/api/Dockerfile', import.meta.url), 'utf8');

test('api docker runtime entrypoint matches the built Nest output path', () => {
  assert.match(dockerfile, /CMD \["node", "apps\/api\/dist\/apps\/api\/src\/main\.js"\]/);
  assert.doesNotMatch(dockerfile, /CMD \["node", "apps\/api\/dist\/main\.js"\]/);
  assert.match(dockerfile, /FROM node:20-bookworm-slim AS builder/);
  assert.match(dockerfile, /FROM node:20-bookworm-slim AS runner/);
  assert.match(dockerfile, /apt-get install -y --no-install-recommends openssl ca-certificates/);
  assert.doesNotMatch(dockerfile, /FROM node:20-alpine AS builder/);
  assert.doesNotMatch(dockerfile, /FROM node:20-alpine AS runner/);
});
