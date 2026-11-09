import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { ForbiddenException, Injectable, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import type { Session, SessionData } from "express-session";

import { ConfigService } from "../config/config.service";
import type { AuthenticatedPrincipal } from "./auth.types";
import { IdentityStoreService } from "./identity-store.service";

interface GithubTokenResponse {
  access_token?: string;
  error?: string;
  error_description?: string;
}

interface GithubUserResponse {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string | null;
}

interface GithubEmailResponse {
  email: string;
  primary: boolean;
  verified: boolean;
}

const GITHUB_API_VERSION = "2026-03-10";
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const GITHUB_REQUEST_TIMEOUT_MS = 10_000;
type SessionWithData = Session & Partial<SessionData>;

@Injectable()
export class AuthService {
  constructor(
    private readonly config: ConfigService,
    private readonly identities: IdentityStoreService
  ) {}

  beginGithubAuthentication(session: SessionWithData): string {
    const stateNonce = randomBytes(32).toString("base64url");
    const stateSignature = createHmac("sha256", this.config.get("CSRF_SECRET"))
      .update(stateNonce)
      .digest("base64url");
    const state = `${stateNonce}.${stateSignature}`;
    const codeVerifier = randomBytes(32).toString("base64url");
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

    session.pendingGithubOauth = {
      state,
      codeVerifier,
      expiresAt: Date.now() + OAUTH_STATE_TTL_MS
    };

    const authorizationUrl = new URL("https://github.com/login/oauth/authorize");
    authorizationUrl.searchParams.set("client_id", this.config.get("GITHUB_CLIENT_ID"));
    authorizationUrl.searchParams.set("redirect_uri", this.githubCallbackUrl());
    if (this.config.get("GITHUB_LOGIN_KIND") === "oauth-app") {
      authorizationUrl.searchParams.set("scope", "read:user user:email");
    }
    authorizationUrl.searchParams.set("state", state);
    authorizationUrl.searchParams.set("code_challenge", codeChallenge);
    authorizationUrl.searchParams.set("code_challenge_method", "S256");

    return authorizationUrl.toString();
  }

  async completeGithubAuthentication(
    session: SessionWithData,
    code: string,
    returnedState: string
  ): Promise<AuthenticatedPrincipal> {
    const pending = session.pendingGithubOauth;
    delete session.pendingGithubOauth;

    if (
      !pending ||
      pending.expiresAt < Date.now() ||
      !this.safeEqual(pending.state, returnedState)
    ) {
      throw new UnauthorizedException({
        errorCode: "OAUTH_STATE_INVALID",
        message: "GitHub authentication state is invalid or expired."
      });
    }

    const accessToken = await this.exchangeGithubCode(code, pending.codeVerifier);
    const user = await this.fetchGithubUser(accessToken);
    if (!Number.isSafeInteger(user.id) || user.id <= 0 || !this.config.isGithubIdentityAllowed(String(user.id))) {
      throw new ForbiddenException({
        errorCode: "DEPLOYMENT_ACCOUNT_NOT_ALLOWED",
        message: "This private deployment does not admit this GitHub account."
      });
    }
    const email = await this.fetchVerifiedGithubEmail(accessToken);

    if (!email) {
      throw new UnauthorizedException({
        errorCode: "VERIFIED_EMAIL_REQUIRED",
        message: "A verified GitHub email address is required."
      });
    }

    const identityDigest = createHash("sha256")
      .update(`github:${user.id}`)
      .digest("hex")
      .slice(0, 32);

    const principal: AuthenticatedPrincipal = {
      userId: `user_${identityDigest}`,
      tenantId: `tenant_${identityDigest}`,
      email,
      name: user.name?.trim() || user.login,
      avatarUrl: user.avatar_url || undefined,
      provider: "GITHUB",
      providerUserId: String(user.id)
    };
    await this.identities.persist(principal);
    return principal;
  }

  frontendUrl(): string {
    return this.config.get("FRONTEND_URL");
  }

  private githubCallbackUrl(): string {
    return new URL("api/auth/github/callback", this.ensureTrailingSlash(this.config.get("APP_URL"))).toString();
  }

  private async exchangeGithubCode(code: string, codeVerifier: string): Promise<string> {
    const response = await this.githubFetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        client_id: this.config.get("GITHUB_CLIENT_ID"),
        client_secret: this.config.get("GITHUB_CLIENT_SECRET"),
        code,
        code_verifier: codeVerifier,
        redirect_uri: this.githubCallbackUrl()
      })
    });

    const payload = (await response.json()) as GithubTokenResponse;
    if (!response.ok || !payload.access_token) {
      throw new UnauthorizedException({
        errorCode: "GITHUB_TOKEN_EXCHANGE_FAILED",
        message: payload.error_description || "GitHub authentication failed."
      });
    }

    return payload.access_token;
  }

  private async fetchGithubUser(accessToken: string): Promise<GithubUserResponse> {
    const response = await this.githubFetch("https://api.github.com/user", {
      headers: this.githubHeaders(accessToken)
    });

    if (!response.ok) {
      throw new UnauthorizedException({
        errorCode: "GITHUB_IDENTITY_FAILED",
        message: "Unable to verify the GitHub identity."
      });
    }

    return (await response.json()) as GithubUserResponse;
  }

  private async fetchVerifiedGithubEmail(accessToken: string): Promise<string | null> {
    const response = await this.githubFetch("https://api.github.com/user/emails", {
      headers: this.githubHeaders(accessToken)
    });

    if (!response.ok) {
      return null;
    }

    const emails = (await response.json()) as GithubEmailResponse[];
    return (
      emails.find((entry) => entry.primary && entry.verified)?.email ??
      emails.find((entry) => entry.verified)?.email ??
      null
    );
  }

  private githubHeaders(accessToken: string): Record<string, string> {
    return {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${accessToken}`,
      "X-GitHub-Api-Version": GITHUB_API_VERSION,
      "User-Agent": "AegisAI"
    };
  }

  private async githubFetch(url: string, init: RequestInit): Promise<Response> {
    try {
      return await fetch(url, {
        ...init,
        signal: AbortSignal.timeout(GITHUB_REQUEST_TIMEOUT_MS)
      });
    } catch {
      throw new ServiceUnavailableException({
        errorCode: "GITHUB_UNAVAILABLE",
        message: "GitHub authentication is temporarily unavailable."
      });
    }
  }

  private safeEqual(expected: string, actual: string): boolean {
    const expectedBuffer = Buffer.from(expected);
    const actualBuffer = Buffer.from(actual);
    return expectedBuffer.length === actualBuffer.length && timingSafeEqual(expectedBuffer, actualBuffer);
  }

  private ensureTrailingSlash(value: string): string {
    return value.endsWith("/") ? value : `${value}/`;
  }
}
