import type { Provider } from "@aegisai/shared";
import { Navigate } from "react-router-dom";

import { buildDemoProviderCompletionPath } from "../../demo/demoMode";

const LOCAL_DEMO_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function isLocalDemoAuthAvailable(
  hostname = typeof window === "undefined" ? "" : window.location.hostname
) {
  return import.meta.env.DEV && LOCAL_DEMO_HOSTS.has(hostname);
}

export function LocalDemoAuthRedirect({ provider }: { provider: Provider }) {
  const destination = isLocalDemoAuthAvailable()
    ? buildDemoProviderCompletionPath(provider)
    : "/login?error=oauth_failed";

  return <Navigate replace to={destination} />;
}
