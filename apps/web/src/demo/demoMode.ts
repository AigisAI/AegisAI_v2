import type { AuthUser } from "@aegisai/shared";

const DEMO_MODE_KEY = "aegisai.demo.enabled";
const DEMO_AUTH_KEY = "aegisai.demo.authenticated";

export const DEMO_USER: AuthUser = {
  id: "usr-demo-reviewer",
  tenantId: "tenant-acme-payments",
  email: "reviewer@acme-payments.example",
  name: "Mina Park",
  avatarUrl: null,
  connectedProviders: ["github"],
};

function getSessionStorage(): Storage | null {
  if (typeof window === "undefined") {
    return null;
  }

  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function isDemoMode(search = typeof window === "undefined" ? "" : window.location.search) {
  const storage = getSessionStorage();
  const explicitValue = new URLSearchParams(search).get("demo");

  if (explicitValue === "1") {
    storage?.setItem(DEMO_MODE_KEY, "1");
    return true;
  }

  if (explicitValue === "0") {
    storage?.removeItem(DEMO_MODE_KEY);
    storage?.removeItem(DEMO_AUTH_KEY);
    return false;
  }

  return storage?.getItem(DEMO_MODE_KEY) === "1";
}

export function isDemoAuthenticated(
  search = typeof window === "undefined" ? "" : window.location.search
) {
  const storage = getSessionStorage();
  const explicitValue = new URLSearchParams(search).get("demoAuth");

  if (explicitValue === "1") {
    storage?.setItem(DEMO_AUTH_KEY, "1");
    return true;
  }

  return storage?.getItem(DEMO_AUTH_KEY) === "1";
}

export function buildDemoPath(path: string) {
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}demo=1`;
}

export function buildDemoProviderCompletionPath(provider: "github" | "gitlab") {
  return `/dashboard?demo=1&demoAuth=1&provider=${provider}`;
}

export function clearDemoSession() {
  const storage = getSessionStorage();
  storage?.removeItem(DEMO_MODE_KEY);
  storage?.removeItem(DEMO_AUTH_KEY);
}

export function resetDemoSessionForTests() {
  clearDemoSession();
}
