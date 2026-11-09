import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";

import { ForbiddenException, Injectable, ServiceUnavailableException } from "@nestjs/common";
import type { ResolvedGithubCommit } from "@aegisai/shared";

import { ConfigService } from "../config/config.service";
import type { InstallRepositoryDto } from "./control-plane.dto";
import { GithubReadSession } from "./github-read-session";

const API = "https://api.github.com";
const MAX_RESPONSE_BYTES = 1024 * 1024;
const TIMEOUT_MS = 10_000;

function unavailable(): ServiceUnavailableException {
  return new ServiceUnavailableException({
    errorCode: "GITHUB_APP_UNAVAILABLE", message: "GitHub App verification is unavailable."
  });
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw unavailable();
  return value as Record<string, unknown>;
}

function numericId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

@Injectable()
export class GithubAppClient {
  constructor(private readonly config: ConfigService) {}

  async openReadSession(installationId: number, repositoryId: number, providerUserId: string,
    deadline: number, onRevocationUnconfirmed: () => Promise<void>): Promise<GithubReadSession> {
    if (!Number.isFinite(deadline) || deadline <= Date.now() || deadline > Date.now()+600_000) throw unavailable();
    await this.discoverInstallation(installationId, [repositoryId], providerUserId);
    if (deadline <= Date.now()) throw unavailable();
    const issued = record(await this.call(`/app/installations/${installationId}/access_tokens`, this.appJwt(),
      "POST", { repository_ids: [repositoryId], permissions: { contents: "read", metadata: "read" } }));
    if (typeof issued.token !== "string" || !issued.token || issued.token.length > 512 || /[\r\n]/.test(issued.token)) throw unavailable();
    const token = issued.token;
    try {
      const expiry = typeof issued.expires_at === "string" ? Date.parse(issued.expires_at) : NaN;
      const granted = record(issued.permissions);
      if (!Number.isFinite(expiry) || expiry <= Date.now() || expiry > Date.now()+65*60_000 ||
          granted.contents !== "read" || granted.metadata !== "read" ||
          Object.keys(granted).some((key) => key !== "contents" && key !== "metadata")) throw unavailable();
      return new GithubReadSession(token, Math.min(deadline,expiry),
        async (value) => { await this.call("/installation/token",value,"DELETE"); }, onRevocationUnconfirmed);
    } catch {
      await this.call("/installation/token",token,"DELETE");
      throw unavailable();
    }
  }

  async resolveBranchCommit(
    installationId: number, repositoryId: number, providerUserId: string, targetRef: string
  ): Promise<ResolvedGithubCommit> {
    if (typeof targetRef !== "string" || !targetRef || targetRef.length > 255 ||
        /[\p{Cc}\s~^:?*\\]/u.test(targetRef) || targetRef.includes("[") || targetRef.includes("..") ||
        targetRef.includes("@{") || targetRef === "@" ||
        targetRef.split("/").some((part) => !part || part.startsWith(".") || part.endsWith(".") || part.endsWith(".lock"))) {
      throw new ForbiddenException("Invalid GitHub branch scope");
    }
    const [repository] = await this.discoverInstallation(installationId, [repositoryId], providerUserId);
    const issued = record(await this.call(`/app/installations/${installationId}/access_tokens`,
      this.appJwt(), "POST", { repository_ids: [repositoryId], permissions: { contents: "read", metadata: "read" } }));
    if (typeof issued.token !== "string" || !issued.token || issued.token.length > 512 ||
        /[\r\n]/.test(issued.token)) throw unavailable();
    const token = issued.token;
    try {
      const expiry = typeof issued.expires_at === "string" ? Date.parse(issued.expires_at) : NaN;
      const granted = record(issued.permissions);
      if (!Number.isFinite(expiry) || expiry <= Date.now() || expiry > Date.now() + 65 * 60_000 ||
          granted.contents !== "read" || granted.metadata !== "read" ||
          Object.keys(granted).some((key) => key !== "contents" && key !== "metadata")) throw unavailable();
      const ref = record(await this.call(
        `/repos/${repository.fullName}/git/ref/heads/${encodeURIComponent(targetRef)}`, token
      ));
      const object = record(ref.object);
      if (ref.ref !== `refs/heads/${targetRef}` || object.type !== "commit" ||
          typeof object.sha !== "string" || !/^[a-f0-9]{40}$/.test(object.sha)) throw unavailable();
      return { providerRepoId: String(repositoryId), targetRef, commitSha: object.sha };
    } finally {
      await this.call("/installation/token", token, "DELETE");
    }
  }

  private appJwt(): string {
    const appId = this.config.getOptional("GITHUB_APP_ID");
    const keyPath = this.config.getOptional("GITHUB_APP_PRIVATE_KEY_PATH");
    const keyPem = this.config.getOptional("GITHUB_APP_PRIVATE_KEY_PEM");
    if (!appId || (!keyPem && !keyPath)) throw unavailable();
    try {
      const key = createPrivateKey(keyPem || readFileSync(keyPath!));
      if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
        throw unavailable();
      }
      const now = Math.floor(Date.now() / 1000);
      const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
      const claims = Buffer.from(JSON.stringify({ iss: appId, iat: now - 60, exp: now + 540 }))
        .toString("base64url");
      const body = `${header}.${claims}`;
      return `${body}.${sign("RSA-SHA256", Buffer.from(body), key).toString("base64url")}`;
    } catch {
      throw unavailable();
    }
  }

  private async call(path: string, token: string, method = "GET", body?: unknown): Promise<unknown> {
    try {
      const response = await fetch(`${API}${path}`, {
        method, redirect: "error", signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: {
          Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "AegisAI",
          ...(body === undefined ? {} : { "Content-Type": "application/json" })
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) })
      });
      if (method === "DELETE" && path === "/installation/token" && response.status === 401) {
        await response.body?.cancel();
        return undefined; // Already unusable; revocation remains fail-closed for other errors.
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw unavailable();
      }
      if (response.status === 204) return undefined;
      if (!response.headers.get("content-type")?.includes("json")) {
        await response.body?.cancel();
        throw unavailable();
      }
      const reader = response.body?.getReader();
      if (!reader) throw unavailable();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const chunk = await reader.read();
          if (chunk.done) break;
          size += chunk.value.byteLength;
          if (size > MAX_RESPONSE_BYTES) throw unavailable();
          chunks.push(chunk.value);
        }
      } finally {
        await reader.cancel();
      }
      return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    } catch {
      // Provider response bodies, signing material and tokens must never escape.
      throw unavailable();
    }
  }

  async discoverInstallation(
    installationId: number, repositoryIds: number[], providerUserId: string
  ): Promise<InstallRepositoryDto[]> {
    if (!numericId(installationId) || !/^[1-9][0-9]*$/.test(providerUserId) ||
        repositoryIds.length < 1 || repositoryIds.length > 100 ||
        repositoryIds.some((id) => !numericId(id)) || new Set(repositoryIds).size !== repositoryIds.length) {
      throw new ForbiddenException("Invalid GitHub installation scope");
    }
    const jwt = this.appJwt();
    const installation = record(await this.call(`/app/installations/${installationId}`, jwt));
    const account = record(installation.account);
    const permissions = record(installation.permissions);
    const organization = account.type === "Organization";
    if (installation.id !== installationId ||
        String(installation.app_id) !== this.config.get("GITHUB_APP_ID") ||
        installation.suspended_at !== null || !numericId(account.id) ||
        (!organization && (account.type !== "User" || String(account.id) !== providerUserId)) ||
        (organization && (typeof account.login !== "string" ||
          !/^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$/.test(account.login) || permissions.members !== "read")) ||
        !["read", "write"].includes(String(permissions.contents))) {
      throw new ForbiddenException({
        errorCode: "GITHUB_INSTALLATION_FORBIDDEN",
        message: "An active GitHub installation with verified personal ownership or organization administration is required."
      });
    }
    const issued = record(await this.call(`/app/installations/${installationId}/access_tokens`, jwt,
      "POST", { repository_ids: repositoryIds,
        permissions: { metadata: "read", ...(organization ? { members: "read" } : {}) } }));
    if (typeof issued.token !== "string" || !issued.token || issued.token.length > 512 ||
        /[\r\n]/.test(issued.token)) throw unavailable();
    const token = issued.token;
    try {
      const expiry = typeof issued.expires_at === "string" ? Date.parse(issued.expires_at) : NaN;
      const granted = record(issued.permissions);
      if (!Number.isFinite(expiry) || expiry <= Date.now() || expiry > Date.now() + 65 * 60_000 ||
          granted.metadata !== "read" || (organization && granted.members !== "read") ||
          Object.keys(granted).some((key) => key !== "metadata" && !(organization && key === "members"))) {
        throw unavailable();
      }
      if (organization) {
        const identity = record(await this.call(`/user/${providerUserId}`, token));
        if (!numericId(identity.id) || String(identity.id) !== providerUserId || typeof identity.login !== "string" ||
            !/^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$/.test(identity.login)) throw unavailable();
        const membership = record(await this.call(`/orgs/${account.login}/memberships/${identity.login}`, token));
        if (membership.state !== "active" || membership.role !== "admin" ||
            record(membership.user).id !== identity.id ||
            record(membership.organization).id !== account.id) {
          throw new ForbiddenException({
            errorCode: "GITHUB_ORGANIZATION_ADMIN_REQUIRED",
            message: "Active administration of this organization is required."
          });
        }
      }
      const payload = record(await this.call("/installation/repositories?per_page=100&page=1", token));
      if (payload.total_count !== repositoryIds.length || !Array.isArray(payload.repositories) ||
          payload.repositories.length !== repositoryIds.length) throw unavailable();
      const seen = new Set<number>();
      return payload.repositories.map((value: unknown) => {
        const repo = record(value);
        if (!numericId(repo.id) || !repositoryIds.includes(repo.id) || seen.has(repo.id) ||
            typeof repo.full_name !== "string" || repo.full_name.length > 201 ||
            !/^[a-zA-Z0-9-]+\/[a-zA-Z0-9_.-]+$/.test(repo.full_name) ||
            typeof repo.default_branch !== "string" || repo.default_branch.length < 1 ||
            repo.default_branch.length > 255 || /[\p{Cc}]/u.test(repo.default_branch) ||
            typeof repo.private !== "boolean") throw unavailable();
        seen.add(repo.id);
        return {
          providerRepoId: String(repo.id), fullName: repo.full_name,
          defaultBranch: repo.default_branch, isPrivate: repo.private
        };
      });
    } finally {
      // A failed revocation also rejects discovery: no integration is persisted.
      await this.call("/installation/token", token, "DELETE");
    }
  }
}
