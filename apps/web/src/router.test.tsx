import { describe, expect, it } from "vitest";

import { routes } from "./router";

describe("router", () => {
  it("exposes the public landing page at the root path", () => {
    expect(routes[0]?.path).toBe("/");
  });

  it("keeps the public routes separate from the protected workspace routes", () => {
    expect(routes[1]?.path).toBe("/login");
    expect(routes[2]?.path).toBe("/pricing");
    expect(routes[3]?.path).toBeUndefined();
  });

  it("exposes the vulnerability review workspace inside the protected scan routes", () => {
    const protectedChildren = routes[3]?.children ?? [];
    expect(protectedChildren.some((route) => route.path === "/scan/:scanId/review")).toBe(true);
  });
});
