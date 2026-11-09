import { Body, Controller, Post, Req } from "@nestjs/common";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { Test } from "@nestjs/testing";
import type { Request } from "express";
import request from "supertest";

import { AppModule } from "../../src/app.module";
import { configureApplication } from "../../src/bootstrap/configure-application";
import { generateCsrfToken } from "../../src/common/security/csrf";
import { ControlPlaneService } from "../../src/control-plane/control-plane.service";
import { IdentityStoreService } from "../../src/auth/identity-store.service";
import { MemoryControlPlaneService } from "./memory-control-plane";

interface TestSessionBody {
  tenantId?: string;
  userId?: string;
  email?: string;
  name?: string;
}

@Controller("_test")
class TestSessionController {
  @Post("session")
  createSession(@Req() request: Request, @Body() body: TestSessionBody) {
    const tenantId = body.tenantId ?? "tenant_test";
    request.session.auth = {
      userId: body.userId ?? `user_${tenantId}`,
      tenantId,
      email: body.email ?? `${tenantId}@example.test`,
      name: body.name ?? "Test User",
      provider: "GITHUB",
      providerUserId: "42"
    };

    return {
      csrfToken: generateCsrfToken(request),
      tenantId
    };
  }
}

export const TEST_INTERNAL_API_SECRET = "test-internal-api-secret-at-least-32-characters";

export async function createTestApplication(): Promise<NestExpressApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
    controllers: [TestSessionController]
  })
    .overrideProvider(ControlPlaneService).useClass(MemoryControlPlaneService)
    .overrideProvider(IdentityStoreService).useValue({ persist: async () => undefined })
    .compile();
  const app = moduleRef.createNestApplication<NestExpressApplication>();
  await configureApplication(app);
  await app.init();
  return app;
}

export async function loginTestAgent(
  agent: request.Agent,
  tenantId: string
): Promise<string> {
  const response = await agent.post("/api/_test/session").send({ tenantId }).expect(201);
  return response.body.csrfToken as string;
}
