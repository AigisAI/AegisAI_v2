import { getSessionAwareTracker } from '../../src/common/guards/session-aware-throttler.guard';

describe('SessionAwareThrottlerGuard', () => {
  it('uses the session id when the request is authenticated', () => {
    expect(
      getSessionAwareTracker({
        sessionID: 'session-123',
        ip: '10.0.0.1'
      })
    ).toBe('session-123');
  });

  it('falls back to the request ip when no session id is present', () => {
    expect(
      getSessionAwareTracker({
        ip: '10.0.0.1'
      })
    ).toBe('10.0.0.1');
  });
});
