import { ValidationPipe, type INestApplication } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import { RedisStore } from 'connect-redis';
import type { NextFunction, Request, Response } from 'express';
import session from 'express-session';
import helmet from 'helmet';
import passport from 'passport';
import { createClient, type RedisClientType } from 'redis';

import { ConfigService } from '../config/config.service';
import { csrfProtectionMiddleware } from '../common/security/csrf';

const INTERNAL_CSRF_EXEMPT_PATHS = [
  '/api/token-broker',
  '/api/scan-plane',
  '/api/policy-decisions/evaluate',
  '/api/ai-advisories',
  '/api/comment-dispatches',
  '/api/sast-planning',
  '/api/webhooks'
];
const SENSITIVE_RESPONSE_PATHS = [
  '/api/auth',
  '/api/integrations',
  '/api/repository-bindings',
  '/api/scan-requests',
  '/api/scan-plane',
  '/api/sast-planning',
  '/api/token-broker',
  '/api/audit-events',
  '/api/findings',
  '/api/evidence',
  '/api/policy-decisions',
  '/api/ai-advisories'
];

export async function configureApp(app: INestApplication): Promise<void> {
  const config = app.get(ConfigService);
  const httpAdapter = app.getHttpAdapter().getInstance() as { set?: (name: string, value: unknown) => void };
  const sessionOptions: session.SessionOptions = {
    name: config.get('SESSION_COOKIE_NAME'),
    secret: config.get('SESSION_SECRET'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: config.get('SESSION_TTL_SECONDS') * 1000,
      httpOnly: true,
      sameSite: 'lax',
      secure: config.get('COOKIE_SECURE') === 'true',
      domain: config.getOptional('COOKIE_DOMAIN') || undefined
    }
  };

  if (!config.isDevelopment() && !config.isProduction()) {
    sessionOptions.store = new session.MemoryStore();
  } else {
    const redisClient = createClient({ url: config.get('REDIS_URL') });
    await redisClient.connect();
    sessionOptions.store = new RedisStore({
      client: redisClient,
      prefix: 'aegisai:session:',
      ttl: config.get('SESSION_TTL_SECONDS'),
      disableTouch: true
    });
    wrapAppCloseWithRedisCleanup(app, redisClient);
  }

  app.setGlobalPrefix('api');
  if (config.isProduction()) {
    httpAdapter.set?.('trust proxy', 1);
  }

  app.use(helmet());
  app.use((request: Request, response: Response, next: NextFunction) => {
    if (SENSITIVE_RESPONSE_PATHS.some((path) => matchesPathBoundary(request.path, path))) {
      response.setHeader('Cache-Control', 'no-store');
    }
    next();
  });
  app.enableCors({
    origin: new URL(config.get('FRONTEND_URL')).origin,
    credentials: true,
    methods: ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'Authorization']
  });
  app.use(cookieParser());
  app.use(session(sessionOptions));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use((request: Request, response: Response, next: NextFunction) => {
    if (shouldSkipCsrf(request, config)) {
      next();
      return;
    }

    csrfProtectionMiddleware(request, response, next);
  });
  app.useGlobalPipes(
    new ValidationPipe({
      forbidNonWhitelisted: true,
      transform: true,
      whitelist: true
    })
  );
  app.enableShutdownHooks();
}

function matchesPathBoundary(requestPath: string, routePrefix: string): boolean {
  return requestPath === routePrefix || requestPath.startsWith(`${routePrefix}/`);
}

function shouldSkipCsrf(request: Request, config: ConfigService): boolean {
  if (config.isTest() && !matchesPathBoundary(request.path, '/api/auth')) {
    return true;
  }

  return (
    INTERNAL_CSRF_EXEMPT_PATHS.some((path) => matchesPathBoundary(request.path, path)) ||
    (config.isTest() && request.path.startsWith('/api/_test/'))
  );
}

function wrapAppCloseWithRedisCleanup(
  app: INestApplication,
  redisClient: Pick<RedisClientType, 'disconnect' | 'isOpen'>
): void {
  const originalClose = app.close.bind(app);

  app.close = async () => {
    try {
      if (redisClient.isOpen) {
        await redisClient.disconnect();
      }
    } finally {
      await originalClose();
    }
  };
}
