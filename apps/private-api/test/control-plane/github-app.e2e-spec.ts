import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ForbiddenException, ServiceUnavailableException } from "@nestjs/common";
import type { NestExpressApplication } from "@nestjs/platform-express";
import request from "supertest";

import { ConfigService } from "../../src/config/config.service";
import { ControlPlaneService } from "../../src/control-plane/control-plane.service";
import { GithubAppClient } from "../../src/control-plane/github-app.client";
import { GithubInstallationService } from "../../src/control-plane/github-installation.service";
import { PrismaService } from "../../src/prisma/prisma.service";
import { createTestApplication, loginTestAgent } from "../support/test-app";

const repository = { id: 123, full_name: "owner/private-repo", default_branch: "main", private: true };
const principal = {
  userId: "user_42", tenantId: "tenant_42", provider: "GITHUB" as const,
  providerUserId: "42", email: "owner@example.test", name: "Owner"
};

describe("Trusted GitHub App installation discovery", () => {
  let directory: string;
  let client: GithubAppClient;
  let publicKey: ReturnType<typeof generateKeyPairSync>["publicKey"];
  let fetchMock: jest.SpyInstance;

  function json(value: unknown, status = 200): Response {
    return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
  }

  function installation(extra: Record<string, unknown> = {}) {
    return { id: 99, app_id: 7, account: { id: 42, type: "User" },
      suspended_at: null, permissions: { contents: "read", metadata: "read" }, ...extra };
  }

  function issued(extra: Record<string, unknown> = {}) {
    return { token: "discovery-secret-do-not-log", expires_at: new Date(Date.now() + 3600_000).toISOString(),
      permissions: { metadata: "read" }, ...extra };
  }

  beforeAll(() => {
    directory = mkdtempSync(join(tmpdir(), "aegisai-github-key-test-"));
    const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
    publicKey = keys.publicKey;
    writeFileSync(join(directory, "app.pem"), keys.privateKey.export({ format: "pem", type: "pkcs8" }),
      { mode: 0o600 });
  });

  beforeEach(() => {
    const values: Record<string, string> = { GITHUB_APP_ID: "7", GITHUB_APP_PRIVATE_KEY_PATH: join(directory, "app.pem") };
    client = new GithubAppClient({ get: (key: string) => values[key], getOptional: (key: string) => values[key] } as ConfigService);
    fetchMock = jest.spyOn(global, "fetch");
  });

  afterEach(() => { jest.restoreAllMocks(); });
  afterAll(() => { rmSync(directory, { recursive: true, force: true }); });

  function successResponses() {
    fetchMock.mockResolvedValueOnce(json(installation())).mockResolvedValueOnce(json(issued()))
      .mockResolvedValueOnce(json({ total_count: 1, repositories: [repository] }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
  }

  function branchResponses(ref: unknown, grant: Record<string, unknown> = {}) {
    successResponses();
    fetchMock.mockResolvedValueOnce(json(issued({
      permissions: { metadata: "read", contents: "read" }, ...grant
    }))).mockResolvedValueOnce(json(ref)).mockResolvedValueOnce(new Response(null, { status: 204 }));
  }

  it("opens a gateway-only repository read resource after authority checks and accepts already-unusable revocation", async () => {
    successResponses();
    fetchMock.mockResolvedValueOnce(json(issued({permissions:{contents:"read",metadata:"read"}})))
      .mockResolvedValueOnce(json({message:"already expired"},401));
    const resource=await client.openReadSession(99,123,"42",Date.now()+60_000,async()=>undefined);
    expect(()=>JSON.stringify(resource)).toThrow();
    const request=JSON.parse((fetchMock.mock.calls[4][1] as RequestInit).body as string);
    expect(request).toEqual({repository_ids:[123],permissions:{contents:"read",metadata:"read"}});
    await resource.revoke();
    expect((fetchMock.mock.calls[5][1] as RequestInit).method).toBe("DELETE");
  });

  it.each([{contents:"write",metadata:"read"},{contents:"read",metadata:"read",members:"read"}])(
    "rejects excess upstream gateway authority and revokes it: %j", async permissions => {
      successResponses();
      fetchMock.mockResolvedValueOnce(json(issued({permissions})))
        .mockResolvedValueOnce(new Response(null,{status:204}));
      await expect(client.openReadSession(99,123,"42",Date.now()+60_000,async()=>undefined))
        .rejects.toBeInstanceOf(ServiceUnavailableException);
      expect((fetchMock.mock.calls[5][1] as RequestInit).method).toBe("DELETE");
    }
  );

  it("refuses excessive gateway resource lifetime before contacting the provider", async()=>{
    await expect(client.openReadSession(99,123,"42",Date.now()+3_600_000,async()=>undefined))
      .rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("resolves an encoded branch through ref metadata with a single-repository token and revokes before returning", async () => {
    branchResponses({ ref: "refs/heads/feature/security", object: { type: "commit", sha: "a".repeat(40) } });
    await expect(client.resolveBranchCommit(99, 123, "42", "feature/security")).resolves.toEqual({
      providerRepoId: "123", targetRef: "feature/security", commitSha: "a".repeat(40)
    });
    const calls = fetchMock.mock.calls;
    expect(JSON.parse((calls[4][1] as RequestInit).body as string)).toEqual({
      repository_ids: [123], permissions: { contents: "read", metadata: "read" }
    });
    expect(calls[5][0]).toBe("https://api.github.com/repos/owner/private-repo/git/ref/heads/feature%2Fsecurity");
    expect((calls[6][1] as RequestInit).method).toBe("DELETE");
    expect(calls.some(([url]) => String(url).includes("/commits/"))).toBe(false);
  });

  it.each(["", "../main", "main.lock", "/main", "main//other", "main\n", "main@{1}", "main ", "x".repeat(256)])(
    "rejects invalid branch names before provider access: %j", async (branch) => {
      await expect(client.resolveBranchCommit(99, 123, "42", branch)).rejects.toBeInstanceOf(ForbiddenException);
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it.each([
    { ref: "refs/heads/other", object: { type: "commit", sha: "a".repeat(40) } },
    { ref: "refs/heads/main", object: { type: "tag", sha: "a".repeat(40) } },
    { ref: "refs/heads/main", object: { type: "commit", sha: "main" } },
    { ref: "refs/heads/main", object: { type: "commit", sha: "A".repeat(40) } }
  ])("rejects mismatched or mutable ref responses and revokes: %j", async (ref) => {
    branchResponses(ref);
    await expect(client.resolveBranchCommit(99, 123, "42", "main")).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect((fetchMock.mock.calls[6][1] as RequestInit).method).toBe("DELETE");
  });

  it("does not resolve a branch when installation authority fails", async () => {
    fetchMock.mockResolvedValueOnce(json(installation({account:{id:43,type:"User"}})));
    await expect(client.resolveBranchCommit(99,123,"42","main")).rejects.toBeInstanceOf(ForbiddenException);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("revokes a broader commit-resolution token grant before rejecting", async () => {
    successResponses();
    fetchMock.mockResolvedValueOnce(json(issued({ permissions:{contents:"write",metadata:"read"} })))
      .mockResolvedValueOnce(new Response(null,{status:204}));
    await expect(client.resolveBranchCommit(99,123,"42","main")).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect((fetchMock.mock.calls[5][1] as RequestInit).method).toBe("DELETE");
  });

  it("rejects commit resolution when its token cannot be revoked", async () => {
    successResponses();
    fetchMock.mockResolvedValueOnce(json(issued({permissions:{contents:"read",metadata:"read"}})))
      .mockResolvedValueOnce(json({ref:"refs/heads/main",object:{type:"commit",sha:"a".repeat(40)}}))
      .mockResolvedValueOnce(json({message:"discovery-secret-do-not-log"},500));
    await expect(client.resolveBranchCommit(99,123,"42","main")).rejects.toBeInstanceOf(ServiceUnavailableException);
  });

  it("signs an RS256 App JWT, restricts discovery to selected metadata and revokes before returning", async () => {
    successResponses();
    await expect(client.discoverInstallation(99, [123], "42")).resolves.toEqual([
      { providerRepoId: "123", fullName: "owner/private-repo", defaultBranch: "main", isPrivate: true }
    ]);
    const calls = fetchMock.mock.calls;
    const options = calls[0][1] as RequestInit;
    const jwt = (options.headers as Record<string, string>).Authorization.slice(7);
    const parts = jwt.split(".");
    expect(JSON.parse(Buffer.from(parts[0], "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString()) as { iss: string; iat: number; exp: number };
    expect(claims.iss).toBe("7");
    expect(claims.exp - claims.iat).toBe(600);
    expect(verify("RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`), publicKey,
      Buffer.from(parts[2], "base64url"))).toBe(true);
    expect(JSON.parse((calls[1][1] as RequestInit).body as string)).toEqual({
      repository_ids: [123], permissions: { metadata: "read" }
    });
    expect(calls[2][0]).toBe("https://api.github.com/installation/repositories?per_page=100&page=1");
    expect(calls[3][0]).toBe("https://api.github.com/installation/token");
    expect((calls[3][1] as RequestInit).method).toBe("DELETE");
    for (const call of calls) {
      expect((call[1] as RequestInit).redirect).toBe("error");
      expect((call[1] as RequestInit).signal).toBeInstanceOf(AbortSignal);
    }
  });

  it.each([
    { account: { id: 43, type: "User" } },
    { account: { id: 42, type: "Organization" } },
    { suspended_at: "2026-11-01T00:00:00Z" },
    { app_id: 8 }, { permissions: { metadata: "read" } }
  ])("rejects unowned, organization, suspended or insufficient installations: %j", async (extra) => {
    fetchMock.mockResolvedValueOnce(json(installation(extra)));
    await expect(client.discoverInstallation(99, [123], "42")).rejects.toBeInstanceOf(ForbiddenException);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    { total_count: 2, repositories: [repository] },
    { total_count: 1, repositories: [{ ...repository, id: 124 }] },
    { total_count: 1, repositories: [{ ...repository, default_branch: "bad\nbranch" }] }
  ])("revokes on malformed or out-of-scope repository responses: %j", async (payload) => {
    fetchMock.mockResolvedValueOnce(json(installation())).mockResolvedValueOnce(json(issued()))
      .mockResolvedValueOnce(json(payload)).mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(client.discoverInstallation(99, [123], "42")).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect((fetchMock.mock.calls[3][1] as RequestInit).method).toBe("DELETE");
  });

  it("rejects a broader token grant and still revokes it", async () => {
    fetchMock.mockResolvedValueOnce(json(installation()))
      .mockResolvedValueOnce(json(issued({ permissions: { contents: "write", metadata: "read" } })))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(client.discoverInstallation(99, [123], "42")).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect((fetchMock.mock.calls[2][1] as RequestInit).method).toBe("DELETE");
  });

  it("bounds metadata response size and revokes after provider failure", async () => {
    fetchMock.mockResolvedValueOnce(json(installation())).mockResolvedValueOnce(json(issued()))
      .mockResolvedValueOnce(json({ data: "x".repeat(1024 * 1024 + 1) }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(client.discoverInstallation(99, [123], "42")).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("does not persist an integration when token revocation fails and hides provider secrets", async () => {
    fetchMock.mockResolvedValueOnce(json(installation())).mockResolvedValueOnce(json(issued()))
      .mockResolvedValueOnce(json({ total_count: 1, repositories: [repository] }))
      .mockResolvedValueOnce(json({ message: "discovery-secret-do-not-log" }, 500));
    const installIntegration = jest.fn();
    const service = new GithubInstallationService(
      { tenant: { findFirst: async () => ({ id: "tenant_42" }) } } as unknown as PrismaService,
      client, { installIntegration } as unknown as ControlPlaneService
    );
    try {
      await service.link(principal, { installationId: 99, repositoryIds: [123] });
      throw new Error("Expected failure");
    } catch (error) {
      expect(error).toBeInstanceOf(ServiceUnavailableException);
      expect(JSON.stringify(error)).not.toContain("discovery-secret-do-not-log");
    }
    expect(installIntegration).not.toHaveBeenCalled();
  });

  it("persists only provider metadata after successful revocation", async () => {
    successResponses();
    const installIntegration = jest.fn().mockImplementation(async (input: unknown) => {
      expect(fetchMock).toHaveBeenCalledTimes(4);
      return input;
    });
    const service = new GithubInstallationService(
      { tenant: { findFirst: async () => ({ id: "tenant_42" }) } } as unknown as PrismaService,
      client, { installIntegration } as unknown as ControlPlaneService
    );
    await service.link(principal, { installationId: 99, repositoryIds: [123] });
    expect(installIntegration).toHaveBeenCalledWith({
      tenantId: "tenant_42", externalInstallationId: "99", repoReadPrincipalId: "github-app:99:contents-read",
      repositories: [{ providerRepoId: "123", fullName: "owner/private-repo", defaultBranch: "main", isPrivate: true }]
    }, { provider: "GITHUB", integrationType: "GITHUB_APP" });
  });

  it("denies suspended tenants before using App credentials", async () => {
    const service = new GithubInstallationService(
      { tenant: { findFirst: async () => null } } as unknown as PrismaService,
      client, {} as ControlPlaneService
    );
    await expect(service.link(principal, { installationId: 99, repositoryIds: [123] }))
      .rejects.toBeInstanceOf(ForbiddenException);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fails closed with no configured signing key", async () => {
    client = new GithubAppClient({ getOptional: () => "" } as unknown as ConfigService);
    await expect(client.discoverInstallation(99, [123], "42")).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  function organizationResponses(membership: Record<string, unknown> = {}) {
    fetchMock.mockResolvedValueOnce(json(installation({
      account: { id: 55, type: "Organization", login: "verified-org" },
      permissions: { contents: "read", metadata: "read", members: "read" }
    }))).mockResolvedValueOnce(json(issued({ permissions: { metadata: "read", members: "read" } })))
      .mockResolvedValueOnce(json({ id: 42, login: "owner" }))
      .mockResolvedValueOnce(json({ state: "active", role: "admin", user: { id: 42 },
        organization: { id: 55 }, ...membership }));
  }

  it("verifies organization administration with a read-only membership token before repository discovery", async () => {
    organizationResponses();
    fetchMock.mockResolvedValueOnce(json({ total_count: 1, repositories: [repository] }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(client.discoverInstallation(99, [123], "42")).resolves.toEqual([
      { providerRepoId: "123", fullName: "owner/private-repo", defaultBranch: "main", isPrivate: true }
    ]);
    expect(JSON.parse((fetchMock.mock.calls[1][1] as RequestInit).body as string)).toEqual({
      repository_ids: [123], permissions: { metadata: "read", members: "read" }
    });
    expect(fetchMock.mock.calls[2][0]).toBe("https://api.github.com/user/42");
    expect(fetchMock.mock.calls[3][0]).toBe("https://api.github.com/orgs/verified-org/memberships/owner");
    expect(fetchMock.mock.calls[5][0]).toBe("https://api.github.com/installation/token");
  });

  it.each([
    { role: "member" }, { state: "pending" }, { user: { id: 43 } }, { organization: { id: 56 } }
  ])("rejects non-admin or mismatched organization membership and revokes: %j", async (membership) => {
    organizationResponses(membership);
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(client.discoverInstallation(99, [123], "42")).rejects.toBeInstanceOf(ForbiddenException);
    expect(fetchMock).toHaveBeenCalledTimes(5);
    expect((fetchMock.mock.calls[4][1] as RequestInit).method).toBe("DELETE");
  });
});

describe("GitHub installation HTTP security boundary", () => {
  let app: NestExpressApplication;
  beforeAll(async () => { app = await createTestApplication(); });
  afterAll(async () => { jest.restoreAllMocks(); await app.close(); });

  it("requires session and CSRF, rejects fabricated metadata, and derives tenant from the session", async () => {
    const link = jest.spyOn(app.get(GithubInstallationService), "link").mockResolvedValue({
      id: "integration_verified", tenantId: "tenant_install", externalInstallationId: "99",
      repoReadPrincipalId: "github-app:99:contents-read", provider: "GITHUB", integrationType: "GITHUB_APP", status: "ACTIVE"
    });
    await request(app.getHttpServer()).post("/api/integrations/github-app/install")
      .send({ installationId: 99, repositoryIds: [123] }).expect(403);
    const anonymous = request.agent(app.getHttpServer());
    const anonymousSession = await anonymous.get("/api/auth/me").expect(200);
    await anonymous.post("/api/integrations/github-app/install")
      .set("X-CSRF-Token", anonymousSession.body.csrfToken as string)
      .send({ installationId: 99, repositoryIds: [123] }).expect(401);
    const agent = request.agent(app.getHttpServer());
    const csrf = await loginTestAgent(agent, "tenant_install");
    await agent.post("/api/integrations/github-app/install").send({ installationId: 99, repositoryIds: [123] }).expect(403);
    for (const body of [
      { installationId: 99, repositoryIds: [123], tenantId: "tenant_other" },
      { installationId: 99, repositoryIds: [123], repositories: [repository] },
      { installationId: 99, repositoryIds: [123, 123] },
      { installationId: 99, repositoryIds: [] }, { installationId: "../other", repositoryIds: [123] }
    ]) {
      await agent.post("/api/integrations/github-app/install").set("X-CSRF-Token", csrf).send(body).expect(400);
    }
    expect(link).not.toHaveBeenCalled();
    const response = await agent.post("/api/integrations/github-app/install").set("X-CSRF-Token", csrf)
      .send({ installationId: 99, repositoryIds: [123] }).expect(201);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(link).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant_install" }),
      { installationId: 99, repositoryIds: [123] });
    expect(JSON.stringify(response.body)).not.toContain("token");
  });
});
