import { describe, expect, it } from "vitest";

import config from "./vite.config";

describe("vite config", () => {
  it("proxies same-origin /api requests to the local Nest backend during development", () => {
    expect(config.server?.proxy?.["/api"]).toMatchObject({
      target: "http://localhost:3000",
      changeOrigin: true,
    });
  });
});
