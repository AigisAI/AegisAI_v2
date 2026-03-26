import { describe, expect, it } from "vitest";

import { routes } from "./router";

describe("router", () => {
  it("exposes the public landing page at the root path", () => {
    expect(routes[0]?.path).toBe("/");
  });

  it("keeps /login separate from the protected workspace routes", () => {
    expect(routes[1]?.path).toBe("/login");
    expect(routes[2]?.path).toBeUndefined();
  });
});
