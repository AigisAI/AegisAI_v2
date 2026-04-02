import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { fetchCurrentUser, logout } from "../api/auth";
import { useAuth } from "./useAuth";
import { useAuthStore } from "../store/auth.store";

vi.mock("../api/auth", () => ({
  fetchCurrentUser: vi.fn(),
  logout: vi.fn(),
}));

function renderHarness() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  function Harness() {
    const auth = useAuth();

    return (
      <div>
        <span data-testid="loading-state">{auth.isLoading ? "loading" : "ready"}</span>
        <span data-testid="bootstrap-state">{auth.bootstrapState}</span>
        <span>{auth.user?.name ?? "guest"}</span>
        <button onClick={() => void auth.logout()}>logout</button>
      </div>
    );
  }

  return render(
    <QueryClientProvider client={queryClient}>
      <Harness />
    </QueryClientProvider>
  );
}

describe("useAuth", () => {
  beforeEach(() => {
    vi.mocked(fetchCurrentUser).mockReset();
    vi.mocked(logout).mockReset();
    useAuthStore.getState().reset();
  });

  it("hydrates the auth store from GET /api/auth/me", async () => {
    vi.mocked(fetchCurrentUser).mockResolvedValue({
      id: "user-1",
      email: "user@example.com",
      name: "Aegis User",
      avatarUrl: null,
      connectedProviders: ["github"],
    });

    renderHarness();

    expect(await screen.findByText("Aegis User")).toBeInTheDocument();
    expect(screen.getByTestId("loading-state")).toHaveTextContent("ready");
    expect(screen.getByTestId("bootstrap-state")).toHaveTextContent("ready");

    await waitFor(() => {
      expect(useAuthStore.getState().user?.id).toBe("user-1");
      expect(useAuthStore.getState().initialized).toBe(true);
    });
  });

  it("clears local auth state when logout succeeds", async () => {
    vi.mocked(fetchCurrentUser).mockResolvedValue({
      id: "user-1",
      email: "user@example.com",
      name: "Aegis User",
      avatarUrl: null,
      connectedProviders: ["github"],
    });
    vi.mocked(logout).mockResolvedValue(null);

    renderHarness();

    expect(await screen.findByText("Aegis User")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /logout/i }));

    await waitFor(() => {
      expect(useAuthStore.getState().user).toBeNull();
      expect(useAuthStore.getState().initialized).toBe(true);
    });
  });

  it("exposes an error bootstrap state when GET /api/auth/me fails", async () => {
    vi.mocked(fetchCurrentUser).mockRejectedValue(new Error("session bootstrap failed"));

    renderHarness();

    expect(screen.getByTestId("loading-state")).toHaveTextContent("loading");

    await waitFor(() => {
      expect(screen.getByTestId("bootstrap-state")).toHaveTextContent("error");
      expect(useAuthStore.getState().user).toBeNull();
      expect(useAuthStore.getState().initialized).toBe(true);
    });
  });

  it("clears local auth state when logout returns unauthorized", async () => {
    vi.mocked(fetchCurrentUser).mockResolvedValue({
      id: "user-1",
      email: "user@example.com",
      name: "Aegis User",
      avatarUrl: null,
      connectedProviders: ["github"],
    });
    vi.mocked(logout).mockRejectedValue({
      response: {
        status: 401,
      },
    });

    renderHarness();

    expect(await screen.findByText("Aegis User")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /logout/i }));

    await waitFor(() => {
      expect(useAuthStore.getState().user).toBeNull();
      expect(useAuthStore.getState().initialized).toBe(true);
    });
  });
});
