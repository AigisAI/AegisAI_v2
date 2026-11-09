import type { AuthUser } from "@aegisai/shared";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import axios from "axios";
import { useEffect } from "react";

import { fetchCurrentUser, logout as logoutRequest } from "../api/auth";
import {
  clearDemoSession,
  DEMO_USER,
  isDemoAuthenticated,
  isDemoMode,
} from "../demo/demoMode";
import { useAuthStore } from "../store/auth.store";

const AUTH_QUERY_KEY = ["auth", "me"] as const;

type AuthBootstrapState = "loading" | "ready" | "error";

export function useAuth() {
  const demoMode = isDemoMode();
  const demoAuthenticated = demoMode && isDemoAuthenticated();
  const queryClient = useQueryClient();
  const user = useAuthStore((state) => state.user);
  const initialized = useAuthStore((state) => state.initialized);
  const setUser = useAuthStore((state) => state.setUser);
  const clearUser = useAuthStore((state) => state.clearUser);
  const markInitialized = useAuthStore((state) => state.markInitialized);

  const meQuery = useQuery<AuthUser | null>({
    queryKey: AUTH_QUERY_KEY,
    queryFn: fetchCurrentUser,
    staleTime: 5 * 60 * 1000,
    retry: false,
    enabled: !demoMode,
  });

  useEffect(() => {
    if (demoMode) {
      if (demoAuthenticated) {
        setUser(DEMO_USER);
      } else {
        clearUser();
      }
      markInitialized();
      return;
    }

    if (meQuery.status === "success") {
      setUser(meQuery.data);
      markInitialized();
      return;
    }

    if (meQuery.status === "error") {
      clearUser();
      markInitialized();
    }
  }, [
    clearUser,
    demoAuthenticated,
    demoMode,
    markInitialized,
    meQuery.data,
    meQuery.status,
    setUser,
  ]);

  const finalizeLogout = async () => {
    await queryClient.cancelQueries({
      queryKey: AUTH_QUERY_KEY,
    });
    clearUser();
    markInitialized();
    queryClient.setQueryData(AUTH_QUERY_KEY, null);
  };

  const logoutMutation = useMutation({
    mutationFn: logoutRequest,
    onSuccess: async () => {
      await finalizeLogout();
    },
  });

  return {
    user: demoAuthenticated ? DEMO_USER : demoMode ? null : user,
    isLoading: demoMode ? false : !initialized || meQuery.isLoading,
    isAuthenticated: demoAuthenticated || (!demoMode && Boolean(user)),
    bootstrapState: demoMode ? "ready" : getBootstrapState(initialized, meQuery.status),
    logout: async () => {
      if (demoMode) {
        clearDemoSession();
        await finalizeLogout();
        window.location.assign("/login");
        return;
      }

      try {
        await logoutMutation.mutateAsync();
      } catch (error) {
        if (isTerminalLogoutError(error)) {
          await finalizeLogout();
          return;
        }

        throw error;
      }
    },
    refresh: async () => {
      if (demoMode) {
        return;
      }

      await queryClient.invalidateQueries({
        queryKey: AUTH_QUERY_KEY,
      });
    },
  };
}

function getBootstrapState(
  initialized: boolean,
  status: "pending" | "error" | "success"
): AuthBootstrapState {
  if (!initialized && status === "pending") {
    return "loading";
  }

  if (status === "error") {
    return "error";
  }

  return "ready";
}

function isTerminalLogoutError(error: unknown): boolean {
  const status = getErrorStatus(error);

  return status === 401 || status === 403;
}

function getErrorStatus(error: unknown): number | undefined {
  if (axios.isAxiosError(error)) {
    return error.response?.status;
  }

  if (typeof error !== "object" || error === null || !("response" in error)) {
    return undefined;
  }

  const { response } = error as { response?: { status?: unknown } };

  return typeof response?.status === "number" ? response.status : undefined;
}
