import { ValidationPipe } from "@nestjs/common";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { RedisStore } from "connect-redis";
import type { NextFunction, Request, Response } from "express";
import session, { MemoryStore, type Store } from "express-session";
import helmet from "helmet";
import { createClient } from "redis";

import { csrfProtectionMiddleware } from "../common/security/csrf";
import { GlobalExceptionFilter } from "../common/filters/global-exception.filter";
import { ConfigService } from "../config/config.service";
import { RuntimeResourcesService } from "../runtime/runtime-resources.service";

const INTERNAL_CSRF_EXEMPT_PATHS = ["/api/token-broker", "/api/scan-plane"];
const SENSITIVE_RESPONSE_PATHS = [
  "/api/runtime",
  "/api/auth",
  "/api/integrations",
  "/api/repository-bindings",
  "/api/token-broker",
  "/api/audit-events",
  "/api/findings",
  "/api/evidence"
];

function matchesPathBoundary(requestPath: string, routePrefix: string): boolean {
  return requestPath === routePrefix || requestPath.startsWith(`${routePrefix}/`);
}

async function createSessionStore(
  config: ConfigService,
  resources: RuntimeResourcesService
): Promise<Store> {
  if (config.isTest()) {
    return new MemoryStore();
  }

  const redisClient = createClient({ url: config.get("REDIS_URL") });
  await redisClient.connect();
  resources.registerRedisClient(redisClient);

  return new RedisStore({
    client: redisClient,
    prefix: "aegisai:session:",
    ttl: config.get("SESSION_TTL_SECONDS"),
    disableTouch: true
  });
}

function shouldSkipCsrf(request: Request, config: ConfigService): boolean {
  if (
    INTERNAL_CSRF_EXEMPT_PATHS.some(
      (path) => matchesPathBoundary(request.path, path)
    )
  ) {
    return true;
  }

  return config.isTest() && request.path.startsWith("/api/_test/");
}

export async function configureApplication(app: NestExpressApplication): Promise<void> {
  const config = app.get(ConfigService);
  const resources = app.get(RuntimeResourcesService);
  const sessionStore = await createSessionStore(config, resources);
  const secureCookie = config.get("COOKIE_SECURE") === "true";
  const cookieDomain = config.getOptional("COOKIE_DOMAIN") || undefined;
  const frontendOrigin = new URL(config.get("FRONTEND_URL")).origin;

  app.set("trust proxy", config.isProduction() ? 1 : false);
  app.use(helmet());
  app.use((request: Request, response: Response, next: NextFunction) => {
    if (SENSITIVE_RESPONSE_PATHS.some((path) => matchesPathBoundary(request.path, path))) {
      response.setHeader("Cache-Control", "no-store");
    }
    next();
  });
  app.enableCors({
    origin: frontendOrigin,
    credentials: true,
    methods: ["GET", "HEAD", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-CSRF-Token", "Authorization"]
  });
  app.use(
    session({
      name: config.get("SESSION_COOKIE_NAME"),
      secret: config.get("SESSION_SECRET"),
      store: sessionStore,
      resave: false,
      saveUninitialized: false,
      rolling: false,
      cookie: {
        domain: cookieDomain,
        httpOnly: true,
        maxAge: config.get("SESSION_TTL_SECONDS") * 1000,
        sameSite: "lax",
        secure: secureCookie
      }
    })
  );
  app.use((request: Request, response: Response, next: NextFunction) => {
    if (shouldSkipCsrf(request, config)) {
      next();
      return;
    }

    csrfProtectionMiddleware(request, response, next);
  });
  app.setGlobalPrefix("api");
  app.useGlobalPipes(
    new ValidationPipe({
      forbidNonWhitelisted: true,
      transform: true,
      whitelist: true
    })
  );
  app.useGlobalFilters(app.get(GlobalExceptionFilter));
  app.enableShutdownHooks();
}
