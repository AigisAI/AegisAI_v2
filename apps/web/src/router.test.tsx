import { describe, expect, it } from "vitest";

import { routes } from "./router";

describe("router", () => {
  it("exposes the public landing page at the root path", () => {
    expect(routes[0]?.path).toBe("/");
  });

  it("keeps the public routes separate from the protected workspace routes", () => {
    expect(routes[1]?.path).toBe("/login");
    expect(routes[2]?.path).toBe("/pricing");
    expect(routes.some((route) => route.path === "/demo")).toBe(true);
    expect(routes.some((route) => route.path === "/api/auth/github")).toBe(true);
    expect(routes.some((route) => route.path === "/api/auth/gitlab")).toBe(true);
    expect(routes.some((route) => !route.path && route.children)).toBe(true);
  });

  it("exposes vulnerability review and report pages inside the protected routes", () => {
    const protectedChildren = routes.find((route) => !route.path && route.children)?.children ?? [];
    expect(protectedChildren.some((route) => route.path === "/scan/:scanId/review")).toBe(true);
    expect(protectedChildren.some((route) => route.path === "/reports/:reportId")).toBe(true);
  });
});
