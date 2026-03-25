import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useAuth } from "../hooks/useAuth";
import { LoginPage } from "./LoginPage";

vi.mock("../hooks/useAuth", () => ({
  useAuth: vi.fn(),
}));

const mockedUseAuth = vi.mocked(useAuth);

function renderLoginPage(initialEntry = "/login") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={<div>dashboard landing</div>} />
      </Routes>
    </MemoryRouter>
  );
}

describe("LoginPage", () => {
  beforeEach(() => {
    mockedUseAuth.mockReset();
    mockedUseAuth.mockReturnValue({
      user: null,
      isLoading: false,
      isAuthenticated: false,
      bootstrapState: "ready",
      logout: vi.fn(),
      refresh: vi.fn(),
    });
  });

  it("renders provider CTAs for unauthenticated users", () => {
    renderLoginPage();

    expect(
      screen.getByRole("heading", { name: /secure java scanning that stays in your provider flow/i })
    ).toBeInTheDocument();
    expect(screen.getByText(/session-based auth/i)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /continue with github/i })
    ).toHaveAttribute("href", "http://localhost:3000/api/auth/github");
    expect(
      screen.getByRole("link", { name: /continue with gitlab/i })
    ).toHaveAttribute("href", "http://localhost:3000/api/auth/gitlab");
  });

  it("renders a loading state during auth bootstrap", () => {
    mockedUseAuth.mockReturnValue({
      user: null,
      isLoading: true,
      isAuthenticated: false,
      bootstrapState: "loading",
      logout: vi.fn(),
      refresh: vi.fn(),
    });

    renderLoginPage();

    expect(screen.getByText(/checking your session/i)).toBeInTheDocument();
  });

  it("renders an oauth failure message from the query string", () => {
    renderLoginPage("/login?error=oauth_failed");

    expect(screen.getByRole("alert")).toHaveTextContent(
      /login did not complete successfully/i
    );
  });

  it("redirects authenticated users away from /login", () => {
    mockedUseAuth.mockReturnValue({
      user: {
        id: "user-1",
        email: "user@example.com",
        name: "Aegis User",
        avatarUrl: null,
        connectedProviders: ["github"],
      },
      isLoading: false,
      isAuthenticated: true,
      bootstrapState: "ready",
      logout: vi.fn(),
      refresh: vi.fn(),
    });

    renderLoginPage();

    expect(screen.getByText("dashboard landing")).toBeInTheDocument();
  });

  it("renders retry guidance when session bootstrap fails", () => {
    mockedUseAuth.mockReturnValue({
      user: null,
      isLoading: false,
      isAuthenticated: false,
      bootstrapState: "error",
      logout: vi.fn(),
      refresh: vi.fn(),
    });

    renderLoginPage();

    expect(screen.getByRole("alert")).toHaveTextContent(
      /we could not verify your existing session/i
    );
  });
});
