type RequestLike = {
  protocol?: string;
  secure?: boolean;
  headers?: Record<string, string | string[] | undefined>;
  get?: (name: string) => string | undefined;
};

type Provider = 'github' | 'gitlab';

export function buildProviderCallbackUrl(
  request: RequestLike,
  configuredAppUrl: string,
  provider: Provider
): string {
  return new URL(
    `/api/auth/${provider}/callback`,
    resolveRuntimeBaseUrl(request, configuredAppUrl)
  ).toString();
}

export function buildFrontendRedirectUrl(
  request: RequestLike,
  configuredFrontendUrl: string,
  pathname: string
): string {
  return new URL(pathname, resolveRuntimeBaseUrl(request, configuredFrontendUrl)).toString();
}

export function shouldUseSecureCookies(
  request: RequestLike,
  fallbackUrl: string
): boolean {
  return new URL(resolveRequestOrigin(request, fallbackUrl)).protocol === 'https:';
}

function resolveRuntimeBaseUrl(request: RequestLike, configuredUrl: string): string {
  const configured = new URL(configuredUrl);
  const requestOrigin = new URL(resolveRequestOrigin(request, configuredUrl));

  return configured.host === requestOrigin.host ? requestOrigin.origin : configured.origin;
}

function resolveRequestOrigin(request: RequestLike, fallbackUrl: string): string {
  const fallback = new URL(fallbackUrl);
  const protocol =
    normalizeForwardedValue(getHeader(request, 'x-forwarded-proto')) ??
    normalizeScheme(request.protocol) ??
    (request.secure ? 'https' : null) ??
    normalizeScheme(fallback.protocol);
  const host =
    normalizeForwardedValue(getHeader(request, 'x-forwarded-host')) ??
    normalizeForwardedValue(getHeader(request, 'host'));

  if (!host) {
    return fallback.origin;
  }

  return `${protocol}://${host}`;
}

function getHeader(request: RequestLike, name: string): string | undefined {
  const directHeader = request.get?.(name);

  if (directHeader) {
    return directHeader;
  }

  const headerValue = request.headers?.[name] ?? request.headers?.[name.toLowerCase()];
  if (Array.isArray(headerValue)) {
    return headerValue[0];
  }

  return headerValue;
}

function normalizeForwardedValue(value: string | undefined): string | null {
  if (!value) {
    return null;
  }

  const [first] = value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

  return first ?? null;
}

function normalizeScheme(value: string | undefined): string | null {
  if (!value) {
    return null;
  }

  return value.replace(/:$/, '').trim().toLowerCase();
}
