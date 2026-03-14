import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";

import { AppModule } from "../src/app.module";

describe("App bootstrap (e2e)", () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    }).compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix("api");

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it("returns bootstrap metadata from GET /api", async () => {
    await request(app.getHttpServer())
      .get("/api")
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          docs: "specs/001-aegisai-mvp-foundation/quickstart.md",
          service: "api",
          status: "bootstrapped"
        });
      });
  });
});
