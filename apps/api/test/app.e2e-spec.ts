import type { NestExpressApplication } from "@nestjs/platform-express";
import request from "supertest";

import { createTestApplication, loginTestAgent } from "./support/test-app";

describe("App bootstrap and security middleware (e2e)", () => {
  let app: NestExpressApplication;

  beforeAll(async () => {
    app = await createTestApplication();
  });

  afterAll(async () => {
    await app.close();
  });

  it("returns bootstrap and dependency-aware health metadata", async () => {
    await request(app.getHttpServer())
      .get("/api")
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          docs: "specs/002-production-scan-architecture/quickstart.md",
          service: "api",
          status: "bootstrapped"
        });
      });

    await request(app.getHttpServer()).get("/api/health").expect(200, {
      service: "api",
      status: "ok",
      dependencies: {
        database: "skipped",
        sessionStore: "memory"
      }
    });
  });

  it("bootstraps CSRF state and rejects a state-changing request without the token", async () => {
    const agent = request.agent(app.getHttpServer());
    const csrfToken = await loginTestAgent(agent, "tenant_security");

    const session = await agent.get("/api/auth/me").expect(200).expect(({ body }) => {
      expect(body.authenticated).toBe(true);
      expect(body.csrfToken).toEqual(expect.any(String));
      expect(body.user.email).toBe("tenant_security@example.test");
    });
    expect(session.headers["cache-control"]).toBe("no-store");

    await agent.post("/api/auth/logout").expect(403);
    await agent.post("/api/auth/logout").set("X-CSRF-Token", csrfToken).expect(204);
    await agent.get("/api/auth/me").expect(200).expect(({ body }) => {
      expect(body.authenticated).toBe(false);
      expect(body.user).toBeNull();
    });
  });
});
