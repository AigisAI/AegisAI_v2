/** Identity returned only after server-side owner session admission. */
export const OBSERVABILITY_PROXY_HEADERS = {
  user: "X-AegisAI-User",
  role: "X-AegisAI-Role"
} as const;
