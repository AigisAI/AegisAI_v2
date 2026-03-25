import { getSessionAwareTracker } from '../../src/common/guards/session-aware-throttler.guard';

describe('SessionAwareThrottlerGuard', () => {
  it('uses the session id when the request is authenticated', () => {
    expect(
      getSessionAwareTracker({
        user: { id: 'user-1' },
        sessionID: 'session-123',
        ip: '10.0.0.1'
      })
    ).toBe('session-123');
  });

  it('falls back to the request ip for anonymous traffic without a session id', () => {
    expect(
      getSessionAwareTracker({
        ip: '10.0.0.1'
      })
    ).toBe('10.0.0.1');
  });

  it('ignores anonymous session ids and uses the request ip instead', () => {
    expect(
      getSessionAwareTracker({
        sessionID: 'anonymous-session',
        ip: '10.0.0.2'
      })
    ).toBe('10.0.0.2');
  });
});
