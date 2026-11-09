import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import test from "node:test";
import { fileURLToPath } from "node:url";

const apiMain = fileURLToPath(new URL("../../apps/private-api/dist/main.js", import.meta.url));
const workspaceRoot = fileURLToPath(new URL("../../", import.meta.url));

function reservePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const isRunning = (child) => child.exitCode === null && child.signalCode === null;

async function waitForExit(child, timeoutMilliseconds) {
  if (!isRunning(child)) {
    return;
  }

  await Promise.race([once(child, "exit"), delay(timeoutMilliseconds)]);
}

test("the compiled API starts and serves its health endpoint", { timeout: 20_000 }, async () => {
  const port = await reservePort();
  const child = spawn(process.execPath, [apiMain], {
    cwd: workspaceRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PORT: String(port),
      DATABASE_URL: "postgresql://postgres:postgres@localhost:5432/aegisai_runtime_test",
      REDIS_URL: "redis://localhost:6379/15",
      SESSION_SECRET: "runtime-session-secret-at-least-32-characters",
      CSRF_SECRET: "runtime-csrf-secret-at-least-32-characters-long",
      GITHUB_CLIENT_ID: "runtime-github-client-id",
      GITHUB_CLIENT_SECRET: "runtime-github-client-secret",
      GITLAB_CLIENT_ID: "runtime-gitlab-client-id",
      GITLAB_CLIENT_SECRET: "runtime-gitlab-client-secret",
      APP_URL: `http://localhost:${port}`,
      FRONTEND_URL: "http://localhost:5173",
      SESSION_COOKIE_NAME: "aegisai_runtime_session",
      COOKIE_DOMAIN: "",
      COOKIE_SECURE: "false",
      SESSION_TTL_SECONDS: "3600",
      THROTTLE_TTL_MS: "60000",
      THROTTLE_LIMIT: "1000",
      TOKEN_ENCRYPTION_KEY: "a".repeat(64),
      ANALYSIS_CLIENT_MODE: "mock",
      AI_SERVER_URL: "http://localhost:8000",
      USE_INTERNAL_AI: "false",
      INTERNAL_API_SECRET: "runtime-internal-secret-at-least-32-characters",
      GITHUB_APP_WEBHOOK_SECRET: "",
      GITLAB_WEBHOOK_SECRET: "",
      REPORT_STORAGE_PATH: "./tmp/runtime-reports",
      REPORT_EXPIRY_HOURS: "24"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  try {
    const deadline = Date.now() + 10_000;
    let response;
    while (Date.now() < deadline) {
      if (!isRunning(child)) {
        assert.fail(
          `Compiled API exited with code ${child.exitCode ?? child.signalCode}: ${stderr}`
        );
      }

      try {
        response = await fetch(`http://127.0.0.1:${port}/api/health`);
        if (response.ok) {
          break;
        }
      } catch {
        // The listener may not be ready yet.
      }
      await delay(100);
    }

    assert.ok(response?.ok, `Compiled API did not become healthy: ${stderr}`);
    assert.deepEqual(await response.json(), {
      service: "api",
      status: "ok",
      dependencies: {
        database: "skipped",
        sessionStore: "memory"
      }
    });
  } finally {
    if (isRunning(child)) {
      child.kill();
      await waitForExit(child, 2_000);
    }
    if (isRunning(child)) {
      child.kill("SIGKILL");
      await waitForExit(child, 2_000);
    }
  }
});
