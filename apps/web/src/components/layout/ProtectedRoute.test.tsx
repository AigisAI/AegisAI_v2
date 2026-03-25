import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ProtectedRoute } from "./ProtectedRoute";
import { useAuth } from "../../hooks/useAuth";

vi.mock("../../hooks/useAuth", () => ({
  useAuth: vi.fn(),
}));

describe("ProtectedRoute", () => {
  beforeEach(() => {
    vi.mocked(useAuth).mockReset();
  });

  it("redirects unauthenticated users to /login", () => {
    vi.mocked(useAuth).mockReturnValue({
      user: null,
      isLoading: false,
      isAuthenticated: false,
      logout: vi.fn(),
      refresh: vi.fn(),
    });

    render(
      <MemoryRouter initialEntries={["/dashboard"]}>
        <Routes>
          <Route path="/login" element={<div>login route</div>} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <div>dashboard route</div>
              </ProtectedRoute>
            }
          />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText("login route")).toBeInTheDocument();
  });

  it("renders children for authenticated users", () => {
    vi.mocked(useAuth).mockReturnValue({
      user: {
        id: "user-1",
        email: "user@example.com",
        name: "Aegis User",
        avatarUrl: null,
        connectedProviders: ["github"],
      },
      isLoading: false,
      isAuthenticated: true,
      logout: vi.fn(),
      refresh: vi.fn(),
    });

    render(
      <MemoryRouter>
        <ProtectedRoute>
          <div>dashboard route</div>
        </ProtectedRoute>
      </MemoryRouter>
    );

    expect(screen.getByText("dashboard route")).toBeInTheDocument();
  });
});
