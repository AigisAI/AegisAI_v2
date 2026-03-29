import { ForbiddenException } from '@nestjs/common';
import { Logger } from '@nestjs/common';

import { GlobalExceptionFilter } from '../../src/common/filters/global-exception.filter';

describe('GlobalExceptionFilter', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('normalizes HttpException responses into the shared error shape', () => {
    const filter = new GlobalExceptionFilter();
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
  });

  it('falls back to a 500 internal error shape and logs runtime_error server errors', () => {
    const filter = new GlobalExceptionFilter();
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
    expect(loggerSpy).toHaveBeenCalledTimes(1);
    expect(String(loggerSpy.mock.calls[0]?.[0])).toContain('"marker":"runtime_error"');
    expect(String(loggerSpy.mock.calls[0]?.[0])).toContain('"status":500');
    expect(String(loggerSpy.mock.calls[0]?.[0])).toContain('"errorCode":"INTERNAL_ERROR"');
    expect(String(loggerSpy.mock.calls[0]?.[0])).toContain('"method":"GET"');
    expect(String(loggerSpy.mock.calls[0]?.[0])).toContain('"path":"/"');
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
