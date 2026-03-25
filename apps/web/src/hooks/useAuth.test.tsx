import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
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
        <span>{auth.isLoading ? "loading" : "ready"}</span>
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

    await waitFor(() => {
      expect(useAuthStore.getState().user?.id).toBe("user-1");
      expect(useAuthStore.getState().initialized).toBe(true);
    });
  });
});
