import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const apiMain = new URL("../../apps/private-api/dist/main.js", import.meta.url);
const apiController = new URL("../../apps/private-api/dist/app.controller.js", import.meta.url);
const apiService = new URL("../../apps/private-api/dist/app.service.js", import.meta.url);
const staleNestedMain = new URL("../../apps/private-api/dist/src/main.js", import.meta.url);
const apiDockerfile = new URL("../../apps/private-api/Dockerfile", import.meta.url);

test("the clean API build matches the container runtime entry point", () => {
  assert.equal(existsSync(apiMain), true, "Expected apps/api/dist/main.js after build");
  assert.equal(existsSync(apiController), true, "Expected the root API controller in dist");
  assert.equal(existsSync(apiService), true, "Expected the root API service in dist");
  assert.equal(
    existsSync(staleNestedMain),
    false,
    "The API build must not depend on stale dist/src output"
  );

  const dockerfile = readFileSync(apiDockerfile, "utf8");
  assert.match(dockerfile, /CMD \["node", "apps\/api\/dist\/main\.js"\]/);
});
