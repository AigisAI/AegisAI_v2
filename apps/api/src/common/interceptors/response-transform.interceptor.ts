import type { SuccessResponse } from '@aegisai/shared';
import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import { SKIP_TRANSFORM_KEY } from '../decorators/skip-transform.decorator';

@Injectable()
export class ResponseTransformInterceptor<T>
  implements NestInterceptor<T, SuccessResponse<T> | T | undefined>
{
  constructor(private readonly reflector: Reflector) {}

  intercept(
    context: ExecutionContext,
    next: CallHandler<T>
  ): Observable<SuccessResponse<T> | T | undefined> {
    return next.handle().pipe(
      map((data) => {
        const skipTransform = this.reflector.getAllAndOverride<boolean>(SKIP_TRANSFORM_KEY, [
          context.getHandler(),
          context.getClass()
        ]);
        const response = context.switchToHttp().getResponse<{ statusCode?: number }>();

        if (skipTransform || response.statusCode === 204 || data === undefined) {
          return data;
        }

        return {
          success: true,
          data,
          message: null,
          timestamp: new Date().toISOString()
        };
      })
    );
  }
}
