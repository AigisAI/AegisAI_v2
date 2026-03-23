import type { INestApplication } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import { RedisStore } from 'connect-redis';
import session from 'express-session';
import passport from 'passport';
import { createClient } from 'redis';

import { ConfigService } from '../config/config.service';

export async function configureApp(app: INestApplication): Promise<void> {
  const config = app.get(ConfigService);
  const httpAdapter = app.getHttpAdapter().getInstance() as { set?: (name: string, value: unknown) => void };
  const sessionOptions: session.SessionOptions = {
    name: config.get('SESSION_COOKIE_NAME'),
    secret: config.get('SESSION_SECRET'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true,
      sameSite: 'lax',
      secure: config.isProduction(),
      domain: config.getOptional('COOKIE_DOMAIN') || undefined
    }
  };

  if (!config.isDevelopment() && !config.isProduction()) {
    sessionOptions.store = new session.MemoryStore();
  } else {
    const redisClient = createClient({ url: config.get('REDIS_URL') });
    await redisClient.connect();
    sessionOptions.store = new RedisStore({ client: redisClient });
  }

  app.setGlobalPrefix('api');
  if (config.isProduction()) {
    httpAdapter.set?.('trust proxy', 1);
  }

  app.use(cookieParser());
  app.use(session(sessionOptions));
  app.use(passport.initialize());
  app.use(passport.session());
}
