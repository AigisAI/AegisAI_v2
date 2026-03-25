import type { AuthUser } from "@aegisai/shared";
import { create } from "zustand";

interface AuthState {
  user: AuthUser | null;
  initialized: boolean;
  setUser: (user: AuthUser | null) => void;
  clearUser: () => void;
  markInitialized: () => void;
  reset: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  initialized: false,
  setUser: (user) =>
    set({
      user,
    }),
  clearUser: () =>
    set({
      user: null,
    }),
  markInitialized: () =>
    set({
      initialized: true,
    }),
  reset: () =>
    set({
      user: null,
      initialized: false,
    }),
}));
