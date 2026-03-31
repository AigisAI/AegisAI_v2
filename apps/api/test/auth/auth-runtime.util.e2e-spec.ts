import {
  buildFrontendRedirectUrl,
  buildProviderCallbackUrl,
  shouldUseSecureCookies
} from '../../src/auth/auth-runtime.util';

describe('auth runtime url helpers', () => {
  const request = {
    protocol: 'http',
    secure: false,
    headers: {
      host: '161.33.220.227'
    }
  };

  it('prefers the incoming request origin for provider callbacks when only the scheme differs', () => {
    expect(
      buildProviderCallbackUrl(request, 'https://161.33.220.227', 'github')
    ).toBe('http://161.33.220.227/api/auth/github/callback');
  });

  it('prefers the incoming request origin for frontend redirects when only the scheme differs', () => {
    expect(
      buildFrontendRedirectUrl(request, 'https://161.33.220.227', '/dashboard')
    ).toBe('http://161.33.220.227/dashboard');
  });

  it('keeps a separately hosted frontend origin intact', () => {
    expect(
      buildFrontendRedirectUrl(
        {
          protocol: 'http',
          secure: false,
          headers: {
            host: 'localhost:3000'
          }
        },
        'http://localhost:5173',
        '/dashboard'
      )
    ).toBe('http://localhost:5173/dashboard');
  });

  it('does not force secure cookies for plain-http requests', () => {
    expect(shouldUseSecureCookies(request, 'https://161.33.220.227')).toBe(false);
  });

  it('uses secure cookies when the forwarded protocol is https', () => {
    expect(
      shouldUseSecureCookies(
        {
          protocol: 'http',
          secure: false,
          headers: {
            host: 'aegisai.example.com',
            'x-forwarded-proto': 'https'
          }
        },
        'https://aegisai.example.com'
      )
    ).toBe(true);
  });
});
