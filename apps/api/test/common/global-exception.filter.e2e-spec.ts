import { BadRequestException, Controller, Get, INestApplication, Logger, Module } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";

import { GlobalExceptionFilter } from "../../src/common/filters/global-exception.filter";

@Controller()
class ThrowingController {
  @Get("boom")
  throwUnhandledError() {
    throw new Error("boom");
  }

  @Get("bad-request")
  throwBadRequest() {
    throw new BadRequestException({
      errorCode: "BAD_REQUEST",
      message: "Bad request."
    });
  }
}

@Module({
  controllers: [ThrowingController],
  providers: [GlobalExceptionFilter]
})
class ThrowingModule {}

describe("GlobalExceptionFilter (e2e)", () => {
  let app: INestApplication;
  let errorSpy: jest.SpyInstance;

  beforeAll(async () => {
    errorSpy = jest.spyOn(Logger.prototype, "error").mockImplementation(() => undefined);

    const moduleRef = await Test.createTestingModule({
      imports: [ThrowingModule]
    }).compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix("api");
    app.useGlobalFilters(moduleRef.get(GlobalExceptionFilter));

    await app.init();
  });

  afterEach(() => {
    errorSpy.mockClear();
  });

  afterAll(async () => {
    errorSpy.mockRestore();
    await app.close();
  });

  it("logs runtime_error payloads for unhandled 5xx failures", async () => {
    await request(app.getHttpServer())
      .get("/api/boom")
      .expect(500)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          data: null,
          errorCode: "INTERNAL_ERROR",
          message: "Internal server error.",
          success: false
        });
        expect(body.timestamp).toEqual(expect.any(String));
      });

    expect(errorSpy).toHaveBeenCalledTimes(1);

    const [message, stack] = errorSpy.mock.calls[0];
    expect(String(message)).toContain('"marker":"runtime_error"');
    expect(String(message)).toContain('"status":500');
    expect(String(message)).toContain('"errorCode":"INTERNAL_ERROR"');
    expect(String(message)).toContain('"method":"GET"');
    expect(String(message)).toContain('"path":"/api/boom"');
    expect(String(message)).toContain('"message":"Internal server error."');
    expect(String(stack)).toContain("boom");
  });

  it("does not log runtime_error payloads for handled 4xx failures", async () => {
    await request(app.getHttpServer())
      .get("/api/bad-request")
      .expect(400)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          data: null,
          errorCode: "BAD_REQUEST",
          message: "Bad request.",
          success: false
        });
        expect(body.timestamp).toEqual(expect.any(String));
      });

    expect(errorSpy).not.toHaveBeenCalled();
  });
});
