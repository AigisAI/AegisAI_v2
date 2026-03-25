import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";

function reportGlobalError(error: unknown) {
  if (typeof window === "undefined") {
    return;
  }

  window.dispatchEvent(
    new CustomEvent("aegisai:query-error", {
      detail: error,
    })
  );
}

export function createQueryClient() {
  return new QueryClient({
    queryCache: new QueryCache({
      onError: reportGlobalError,
    }),
    mutationCache: new MutationCache({
      onError: reportGlobalError,
    }),
    defaultOptions: {
      queries: {
        retry: false,
        refetchOnWindowFocus: false,
      },
    },
  });
}

export const appQueryClient = createQueryClient();
