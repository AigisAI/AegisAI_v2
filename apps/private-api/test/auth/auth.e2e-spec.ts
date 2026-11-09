import type { NestExpressApplication } from "@nestjs/platform-express";
import request from "supertest";

import { createTestApplication, loginTestAgent } from "../support/test-app";
import { ConfigService } from "../../src/config/config.service";
import { IdentityStoreService } from "../../src/auth/identity-store.service";

describe("GitHub user authentication boundary (e2e)", () => {
  let app: NestExpressApplication;

  beforeAll(async () => {
    app = await createTestApplication();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(async () => {
    await app.close();
  });

  it("uses session-bound state and PKCE, then keeps the OAuth access token transient", async () => {
    const agent = request.agent(app.getHttpServer());
    const start = await agent.get("/api/auth/github").expect(302);
    const authorizationUrl = new URL(start.headers.location as string);
    const state = authorizationUrl.searchParams.get("state");

    expect(authorizationUrl.origin).toBe("https://github.com");
    expect(authorizationUrl.searchParams.get("scope")).toBe("read:user user:email");
    expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizationUrl.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(state).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

    const fetchMock = jest
      .spyOn(global, "fetch")
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: "transient-github-token" })
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 12345,
          login: "octocat",
          name: "Octo Cat",
          email: "octo@example.test",
          avatar_url: "https://avatars.example.test/octocat"
        })
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => [
          {
            email: "octo@example.test",
            primary: true,
            verified: true
          }
        ]
      } as Response);

    await agent
      .get("/api/auth/github/callback")
      .query({ code: "validcode123", state, iss: "https://github.com/login/oauth" })
      .expect(302)
      .expect("Location", "http://localhost:5173");

    expect(fetchMock).toHaveBeenCalledTimes(3);
    const tokenExchangeBody = fetchMock.mock.calls[0][1]?.body;
    expect(String(tokenExchangeBody)).toContain("code_verifier=");

    const session = await agent.get("/api/auth/me").expect(200);
    expect(session.body).toMatchObject({
      authenticated: true,
      user: {
        email: "octo@example.test",
        name: "Octo Cat"
      }
    });
    expect(JSON.stringify(session.body)).not.toContain("transient-github-token");

    await agent
      .get("/api/auth/github/callback")
      .query({ code: "validcode123", state })
      .expect(401);
  });

  it("rejects callback state that was not issued to the current session", async () => {
    await request(app.getHttpServer())
      .get("/api/auth/github/callback")
      .query({
        code: "validcode123",
        state: `${"a".repeat(43)}.${"b".repeat(43)}`
      })
      .expect(401);
  });

  it("rejects a different issuer before exchanging any authorization code", async () => {
    const agent = request.agent(app.getHttpServer());
    const start = await agent.get("/api/auth/github").expect(302);
    const state = new URL(start.headers.location as string).searchParams.get("state");
    const fetchMock = jest.spyOn(global, "fetch");
    await agent.get("/api/auth/github/callback").query({
      code: "validcode123", state, iss: "https://other.example/login/oauth"
    }).expect(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("denies a non-admitted GitHub account before persistence in the private production profile", async () => {
    const agent = request.agent(app.getHttpServer());
    const start = await agent.get("/api/auth/github").expect(302);
    const state = new URL(start.headers.location as string).searchParams.get("state");
    jest.spyOn(app.get(ConfigService), "isProduction").mockReturnValue(true);
    const persist = jest.spyOn(app.get(IdentityStoreService), "persist");
    jest.spyOn(global, "fetch")
      .mockResolvedValueOnce({ ok: true, json: async () => ({ access_token: "transient-test-token" }) } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => ({ id: 99, login: "other" }) } as Response);
    const response = await agent.get("/api/auth/github/callback").query({ code: "validcode123", state }).expect(403);
    expect(JSON.stringify(response.body)).toContain("DEPLOYMENT_ACCOUNT_NOT_ALLOWED");
    expect(persist).not.toHaveBeenCalled();
    expect((await agent.get("/api/auth/me").expect(200)).body.authenticated).toBe(false);
  });

  it("uses the separate identity App permissions without requesting OAuth repository scopes", async () => {
    const config = app.get(ConfigService);
    const original = config.get.bind(config);
    jest.spyOn(config, "get").mockImplementation((key) => {
      if (key === "GITHUB_LOGIN_KIND") return "github-app" as never;
      return original(key);
    });
    const response = await request(app.getHttpServer()).get("/api/auth/github").expect(302);
    const url = new URL(response.headers.location as string);
    expect(url.searchParams.has("scope")).toBe(false);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("rechecks admission for existing sessions and clears a no-longer-admitted identity", async () => {
    const agent = request.agent(app.getHttpServer());
    await loginTestAgent(agent, "tenant_admission");
    const config = app.get(ConfigService);
    jest.spyOn(config, "isProduction").mockReturnValue(true);
    await agent.get("/api/integrations").expect(200);
    const admission = jest.spyOn(config, "isGithubIdentityAllowed").mockReturnValue(false);
    await agent.get("/api/integrations").expect(403);
    expect((await agent.get("/api/auth/me").expect(200)).body.authenticated).toBe(false);
    admission.mockRestore();
    await agent.get("/api/integrations").expect(401);
  });
});
