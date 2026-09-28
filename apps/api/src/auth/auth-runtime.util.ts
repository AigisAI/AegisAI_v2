type Provider = 'github' | 'gitlab';

export function buildProviderCallbackUrl(
  configuredAppUrl: string,
  provider: Provider
): string {
  return new URL(`/api/auth/${provider}/callback`, configuredAppUrl).toString();
}

export function buildFrontendRedirectUrl(
  configuredFrontendUrl: string,
  pathname: string
): string {
  return new URL(pathname, configuredFrontendUrl).toString();
}

export function shouldUseSecureCookies(configuredAppUrl: string): boolean {
  return new URL(configuredAppUrl).protocol === 'https:';
}
