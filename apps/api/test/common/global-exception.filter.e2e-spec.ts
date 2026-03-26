import { ForbiddenException } from '@nestjs/common';
import { Logger } from '@nestjs/common';

import { GlobalExceptionFilter } from '../../src/common/filters/global-exception.filter';

describe('GlobalExceptionFilter', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('normalizes HttpException responses into the shared error shape', () => {
    const notifier = { notifyRuntimeError: jest.fn().mockResolvedValue(undefined) };
    const filter = new GlobalExceptionFilter(notifier as never);
    const response = createResponse();

    filter.catch(
      new ForbiddenException({
        message: 'You do not own this resource.',
        errorCode: 'FORBIDDEN_RESOURCE_ACCESS'
      }),
      createHost(response) as never
    );

    expect(response.status).toHaveBeenCalledWith(403);
    expect(response.json).toHaveBeenCalledWith({
      success: false,
      data: null,
      message: 'You do not own this resource.',
      errorCode: 'FORBIDDEN_RESOURCE_ACCESS',
      timestamp: expect.any(String)
    });
    expect(notifier.notifyRuntimeError).not.toHaveBeenCalled();
  });

  it('falls back to a 500 internal error shape and logs server errors', () => {
    const notifier = { notifyRuntimeError: jest.fn().mockResolvedValue(undefined) };
    const filter = new GlobalExceptionFilter(notifier as never);
    const response = createResponse();
    const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation();

    filter.catch(new Error('database exploded'), createHost(response) as never);

    expect(response.status).toHaveBeenCalledWith(500);
    expect(response.json).toHaveBeenCalledWith({
      success: false,
      data: null,
      message: 'Internal server error.',
      errorCode: 'INTERNAL_ERROR',
      timestamp: expect.any(String)
    });
    expect(loggerSpy).toHaveBeenCalled();
    expect(notifier.notifyRuntimeError).toHaveBeenCalledWith({
      status: 500,
      errorCode: 'INTERNAL_ERROR',
      message: 'Internal server error.',
      method: 'GET',
      path: '/',
      timestamp: expect.any(String)
    });
  });
});

function createResponse() {
  return {
    status: jest.fn().mockReturnThis(),
    json: jest.fn()
  };
}

function createHost(response: ReturnType<typeof createResponse>) {
  return {
    switchToHttp: () => ({
      getResponse: () => response,
      getRequest: () => ({
        method: 'GET',
        originalUrl: '/'
      })
    })
  };
}
