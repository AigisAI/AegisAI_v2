import { describe, expect, it } from "vitest";

import {
  buildDemoProviderCompletionPath,
  isDemoAuthenticated,
  isDemoMode,
} from "./demoMode";

describe("demo mode", () => {
  it("persists demo mode and authentication only after provider continuation", () => {
    expect(isDemoMode("?demo=1")).toBe(true);
    expect(isDemoAuthenticated("")).toBe(false);
    expect(isDemoAuthenticated("?demoAuth=1")).toBe(true);
    expect(isDemoAuthenticated("")).toBe(true);
  });

  it("builds a provider continuation into the real dashboard route", () => {
    expect(buildDemoProviderCompletionPath("github")).toBe(
      "/dashboard?demo=1&demoAuth=1&provider=github"
    );
  });
});
