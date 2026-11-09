import type { NestExpressApplication } from "@nestjs/platform-express";
import request from "supertest";

import { ConfigService } from "../../src/config/config.service";
import { createTestApplication, loginTestAgent, TEST_INTERNAL_API_SECRET } from "../support/test-app";

describe("Unimplemented production mutation gates", () => {
  let app: NestExpressApplication;
  beforeAll(async () => { app = await createTestApplication(); });
  afterAll(async () => { jest.restoreAllMocks(); await app.close(); });

  it("rejects simulated operations even with valid user or internal authentication", async () => {
    const agent = request.agent(app.getHttpServer());
    const csrf = await loginTestAgent(agent, "tenant_prod_gate");
    jest.spyOn(app.get(ConfigService), "isProduction").mockReturnValue(true);
    for (const route of ["integrations/github/install", "integrations/gitlab/install", "scan-requests"]) {
      const response = await agent.post(`/api/${route}`).set("X-CSRF-Token", csrf).send({}).expect(503);
      expect(JSON.stringify(response.body)).toContain("PRODUCTION_RUNTIME_NOT_READY");
    }
    for (const route of ["scan-plane/mock-runs", "token-broker/issue"]) {
      const response = await request(app.getHttpServer()).post(`/api/${route}`)
        .set("Authorization", `Bearer ${TEST_INTERNAL_API_SECRET}`).send({}).expect(503);
      expect(JSON.stringify(response.body)).toContain("PRODUCTION_RUNTIME_NOT_READY");
    }
    await agent.get("/api/integrations").expect(200, []);
  });
});
