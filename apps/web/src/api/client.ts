import axios, {
  type AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from "axios";
import type { ApiResponse } from "@aegisai/shared";

const CSRF_COOKIE_NAME = "csrf_token";
const LOGIN_PATH = "/login";
const AUTH_BOOTSTRAP_PATH = "/auth/me";

interface RedirectCheckInput {
  pathname: string;
  status?: number;
  requestUrl?: string;
}

interface ApiClientOptions {
  getPathname?: () => string;
  redirectToLogin?: () => void;
  getCookieValue?: (name: string) => string | null;
}

export function resolveApiBaseUrl(): string {
  const viteApiUrl = import.meta.env.VITE_API_URL?.trim();
  if (viteApiUrl && viteApiUrl.length > 0) {
    return viteApiUrl;
  }

  const viteApiBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim();
  if (viteApiBaseUrl && viteApiBaseUrl.length > 0) {
    return viteApiBaseUrl;
  }

  return "/api";
}

export function getCookie(name: string, cookieSource = document.cookie): string | null {
  const cookie = cookieSource
    .split("; ")
    .find((entry) => entry.startsWith(`${name}=`));

  if (!cookie) {
    return null;
  }

  return decodeURIComponent(cookie.slice(name.length + 1));
}

export function attachCsrfHeader(
  config: InternalAxiosRequestConfig,
  getCookieValue: (name: string) => string | null = getCookie
): InternalAxiosRequestConfig {
  const method = config.method?.toUpperCase();

  if (!method || !["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    return config;
  }

  const csrfToken = getCookieValue(CSRF_COOKIE_NAME);
  if (!csrfToken) {
    return config;
  }

  config.headers["X-CSRF-Token"] = csrfToken;
  return config;
}

export function shouldRedirectToLogin({
  pathname,
  status,
  requestUrl,
}: RedirectCheckInput): boolean {
  if (status !== 401) {
    return false;
  }

  if (pathname === LOGIN_PATH) {
    return false;
  }

  if (normalizeRequestPath(requestUrl) === AUTH_BOOTSTRAP_PATH) {
    return false;
  }

  return true;
}

export function createApiClient(options: ApiClientOptions = {}): AxiosInstance {
  const instance = axios.create({
    baseURL: resolveApiBaseUrl(),
    withCredentials: true,
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
  });

  const getPathname =
    options.getPathname ?? (() => window.location.pathname);
  const redirectToLogin =
    options.redirectToLogin ?? (() => window.location.assign(LOGIN_PATH));
  const getCookieValue = options.getCookieValue ?? getCookie;

  instance.interceptors.request.use((config) => attachCsrfHeader(config, getCookieValue));
  instance.interceptors.response.use(
    (response) => response,
    (error: AxiosError) => {
      if (
        shouldRedirectToLogin({
          pathname: getPathname(),
          status: error.response?.status,
          requestUrl: error.config?.url,
        })
      ) {
        redirectToLogin();
      }

      return Promise.reject(error);
    }
  );

  return instance;
}

export function unwrapApiResponse<T>(response: ApiResponse<T>): T {
  if (!response.success) {
    throw new Error(response.message);
  }

  return response.data;
}

function normalizeRequestPath(requestUrl?: string): string | null {
  if (!requestUrl) {
    return null;
  }

  try {
    return new URL(requestUrl, resolveApiBaseUrl()).pathname.replace(/\/api$/, "");
  } catch {
    return requestUrl.startsWith("/api")
      ? requestUrl.slice(4)
      : requestUrl;
  }
}

export const apiClient = createApiClient();

export type ApiClientError = AxiosError;
