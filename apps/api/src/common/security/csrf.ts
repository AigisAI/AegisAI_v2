import { ForbiddenException } from '@nestjs/common';
import { csrfSync } from 'csrf-sync';
import type { NextFunction, Request, Response } from 'express';

const {
  csrfSynchronisedProtection,
  generateToken: generateCsrfToken,
  revokeToken: revokeCsrfToken
} = csrfSync({
  size: 32,
  errorConfig: {
    statusCode: 403,
    message: 'Invalid CSRF token.',
    code: 'CSRF_INVALID'
  }
});

export { generateCsrfToken, revokeCsrfToken };

export function csrfProtectionMiddleware(
  request: Request,
  response: Response,
  next: NextFunction
): void {
  csrfSynchronisedProtection(request, response, (error?: unknown) => {
    if (error) {
      next(
        new ForbiddenException({
          errorCode: 'CSRF_INVALID',
          message: 'Invalid CSRF token.'
        })
      );
      return;
    }

    next();
  });
}
