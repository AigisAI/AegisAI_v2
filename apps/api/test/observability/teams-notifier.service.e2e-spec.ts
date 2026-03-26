import { Logger } from '@nestjs/common';

import { TeamsNotifierService } from '../../src/observability/teams-notifier.service';

describe('TeamsNotifierService', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  it('does nothing when no webhook is configured', async () => {
    global.fetch = jest.fn() as never;
    const service = new TeamsNotifierService(createConfigService(undefined) as never);

    await service.notifyRuntimeError({
      status: 500,
      errorCode: 'INTERNAL_ERROR',
      message: 'Internal server error.',
      method: 'GET',
      path: '/api/health',
      timestamp: new Date().toISOString()
    });

    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('posts a Teams message card when a webhook is configured', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true
    }) as never;
    const service = new TeamsNotifierService(createConfigService('https://teams.example/webhook') as never);

    await service.notifyRuntimeError({
      status: 500,
      errorCode: 'INTERNAL_ERROR',
      message: 'Internal server error.',
      method: 'POST',
      path: '/api/scans',
      timestamp: '2026-03-26T00:00:00.000Z'
    });

    expect(global.fetch).toHaveBeenCalledWith(
      'https://teams.example/webhook',
      expect.objectContaining({
        method: 'POST',
        headers: {
          'content-type': 'application/json'
        }
      })
    );
  });

  it('swallows webhook delivery failures and logs a warning', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('network down')) as never;
    const loggerSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    const service = new TeamsNotifierService(createConfigService('https://teams.example/webhook') as never);

    await service.notifyRuntimeError({
      status: 500,
      errorCode: 'INTERNAL_ERROR',
      message: 'Internal server error.',
      method: 'GET',
      path: '/api/repos',
      timestamp: '2026-03-26T00:00:00.000Z'
    });

    expect(loggerSpy).toHaveBeenCalled();
  });
});

function createConfigService(webhookUrl?: string) {
  return {
    getOptional: (key: string) => {
      if (key === 'TEAMS_WEBHOOK_URL') {
        return webhookUrl;
      }

      return undefined;
    }
  };
}
