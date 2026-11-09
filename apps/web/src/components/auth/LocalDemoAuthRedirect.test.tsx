import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";

import {
  isLocalDemoAuthAvailable,
  LocalDemoAuthRedirect,
} from "./LocalDemoAuthRedirect";

function LocationProbe() {
  const location = useLocation();
  return <span>{`${location.pathname}${location.search}`}</span>;
}

describe("LocalDemoAuthRedirect", () => {
  it("limits the automatic demo bridge to local development hosts", () => {
    expect(isLocalDemoAuthAvailable("localhost")).toBe(true);
    expect(isLocalDemoAuthAvailable("127.0.0.1")).toBe(true);
    expect(isLocalDemoAuthAvailable("aegis.example.com")).toBe(false);
  });

  it("continues a local GitHub login request into the authenticated demo dashboard", async () => {
    render(
      <MemoryRouter initialEntries={["/api/auth/github"]}>
        <Routes>
          <Route
            element={<LocalDemoAuthRedirect provider="github" />}
            path="/api/auth/github"
          />
          <Route element={<LocationProbe />} path="*" />
        </Routes>
      </MemoryRouter>
    );

    expect(
      await screen.findByText("/dashboard?demo=1&demoAuth=1&provider=github")
    ).toBeInTheDocument();
  });
});
