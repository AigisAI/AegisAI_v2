import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AppShell } from "./AppShell";
import { useAuth } from "../../hooks/useAuth";

vi.mock("../../hooks/useAuth", () => ({
  useAuth: vi.fn(),
}));

describe("AppShell", () => {
  beforeEach(() => {
    vi.mocked(useAuth).mockReset();
    vi.mocked(useAuth).mockReturnValue({
      user: {
        id: "user-1",
        email: "user@example.com",
        name: "Aegis User",
        avatarUrl: null,
        connectedProviders: ["github", "gitlab"],
      },
      isLoading: false,
      isAuthenticated: true,
      logout: vi.fn(),
      refresh: vi.fn(),
    });
  });

  it("renders navigation chrome and nested route content", () => {
    render(
      <MemoryRouter initialEntries={["/dashboard"]}>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/dashboard" element={<div>dashboard content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByRole("navigation", { name: /primary/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /dashboard/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /repositories/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /scan/i })).toBeInTheDocument();
    expect(screen.getByText("Aegis User")).toBeInTheDocument();
    expect(screen.getByText("dashboard content")).toBeInTheDocument();
  });
});
