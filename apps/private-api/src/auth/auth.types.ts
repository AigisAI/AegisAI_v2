import type { Request } from "express";

export interface AuthenticatedPrincipal {
  userId: string;
  tenantId: string;
  email: string;
  name: string;
  avatarUrl?: string;
  provider: "GITHUB";
  providerUserId: string;
}

export interface PendingGithubOauth {
  state: string;
  codeVerifier: string;
  expiresAt: number;
}

declare module "express-session" {
  interface SessionData {
    auth?: AuthenticatedPrincipal;
    pendingGithubOauth?: PendingGithubOauth;
  }
}

export interface AuthenticatedRequest extends Request {
  auth?: AuthenticatedPrincipal;
}
