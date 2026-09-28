import {
  buildFrontendRedirectUrl,
  buildProviderCallbackUrl,
  shouldUseSecureCookies
} from '../../src/auth/auth-runtime.util';

describe('auth runtime url helpers', () => {
  it('uses the configured HTTPS origin for provider callbacks', () => {
    expect(
      buildProviderCallbackUrl('https://aegisai.tailaca7d2.ts.net', 'github')
    ).toBe('https://aegisai.tailaca7d2.ts.net/api/auth/github/callback');
    expect(
      buildProviderCallbackUrl('https://aegisai.tailaca7d2.ts.net', 'gitlab')
    ).toBe('https://aegisai.tailaca7d2.ts.net/api/auth/gitlab/callback');
  });

  it('uses the configured frontend origin for post-login redirects', () => {
    expect(
      buildFrontendRedirectUrl('https://aegisai.tailaca7d2.ts.net', '/dashboard')
    ).toBe('https://aegisai.tailaca7d2.ts.net/dashboard');
  });

  it('keeps a separately hosted frontend origin intact', () => {
    expect(
      buildFrontendRedirectUrl('http://localhost:5173', '/dashboard')
    ).toBe('http://localhost:5173/dashboard');
  });

  it('uses the configured public scheme for cookie security', () => {
    expect(shouldUseSecureCookies('https://aegisai.tailaca7d2.ts.net')).toBe(true);
    expect(shouldUseSecureCookies('http://localhost:3000')).toBe(false);
  });
});
