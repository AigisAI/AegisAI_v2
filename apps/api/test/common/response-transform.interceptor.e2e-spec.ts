import { Reflector } from '@nestjs/core';
import { lastValueFrom, of } from 'rxjs';

import { SkipTransform } from '../../src/common/decorators/skip-transform.decorator';
import { ResponseTransformInterceptor } from '../../src/common/interceptors/response-transform.interceptor';

class TestController {
  normal() {
    return undefined;
  }

  @SkipTransform()
  raw() {
    return undefined;
  }
}

describe('ResponseTransformInterceptor', () => {
  it('wraps normal controller responses in the shared success envelope', async () => {
    const interceptor = new ResponseTransformInterceptor(new Reflector());
    const controller = new TestController();
    const context = createContext({
      handler: controller.normal,
      controller: TestController,
      statusCode: 200
    });

    const result = (await lastValueFrom(
      interceptor.intercept(context as never, {
        handle: () => of({ status: 'bootstrapped' })
      } as never)
    )) as {
      success: true;
      data: { status: string };
      message: null;
      timestamp: string;
    };

    expect(result).toMatchObject({
      success: true,
      data: { status: 'bootstrapped' },
      message: null
    });
    expect(result.timestamp).toEqual(expect.any(String));
  });

  it('skips wrapping when the route is marked with SkipTransform', async () => {
    const interceptor = new ResponseTransformInterceptor(new Reflector());
    const controller = new TestController();
    const context = createContext({
      handler: controller.raw,
      controller: TestController,
      statusCode: 200
    });

    const result = await lastValueFrom(
      interceptor.intercept(context as never, {
        handle: () => of({ status: 'ok' })
      } as never)
    );

    expect(result).toEqual({ status: 'ok' });
  });

  it('skips wrapping for 204 and undefined responses', async () => {
    const interceptor = new ResponseTransformInterceptor(new Reflector());
    const controller = new TestController();
    const context = createContext({
      handler: controller.normal,
      controller: TestController,
      statusCode: 204
    });

    const result = await lastValueFrom(
      interceptor.intercept(context as never, {
        handle: () => of(undefined)
      } as never)
    );

    expect(result).toBeUndefined();
  });
});

function createContext(input: {
  handler: () => unknown;
  controller: new () => unknown;
  statusCode: number;
}) {
  return {
    getHandler: () => input.handler,
    getClass: () => input.controller,
    switchToHttp: () => ({
      getResponse: () => ({ statusCode: input.statusCode })
    })
  };
}
