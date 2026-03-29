import type { InternalAxiosRequestConfig } from "axios";
import type { ErrorResponse, SuccessResponse } from "@aegisai/shared";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  attachCsrfHeader,
  resolveApiBaseUrl,
  shouldRedirectToLogin,
  unwrapApiResponse,
} from "./client";
import { getProviderLoginUrl } from "./auth";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("api client helpers", () => {
  it("attaches the csrf token for mutating requests", () => {
    const config = attachCsrfHeader(
      {
        method: "post",
        headers: {},
      } as InternalAxiosRequestConfig,
      () => "csrf-token"
    );

    expect(config.headers["X-CSRF-Token"]).toBe("csrf-token");
  });

  it("does not redirect to login for auth bootstrap and login page requests", () => {
    expect(
      shouldRedirectToLogin({
        pathname: "/dashboard",
        status: 401,
        requestUrl: "/auth/me",
      })
    ).toBe(false);

    expect(
      shouldRedirectToLogin({
        pathname: "/login",
        status: 401,
        requestUrl: "/repos",
      })
    ).toBe(false);
  });

  it("redirects to login for unauthorized non-bootstrap API responses", () => {
    expect(
      shouldRedirectToLogin({
        pathname: "/dashboard",
        status: 401,
        requestUrl: "/repos",
      })
    ).toBe(true);
  });

  it("builds provider login URLs from relative API base paths", () => {
    vi.stubEnv("VITE_API_URL", "/api");

    expect(getProviderLoginUrl("github")).toBe("/api/auth/github");
  });

  it("uses VITE_API_URL when it is set", () => {
    vi.stubEnv("VITE_API_URL", "https://api.example.com");

    expect(resolveApiBaseUrl()).toBe("https://api.example.com");
  });

  it("uses VITE_API_BASE_URL when VITE_API_URL is not set", () => {
    vi.stubEnv("VITE_API_BASE_URL", "https://base.example.com");

    expect(resolveApiBaseUrl()).toBe("https://base.example.com");
  });

  it("prefers VITE_API_URL when both env vars are set", () => {
    vi.stubEnv("VITE_API_URL", "https://api.example.com");
    vi.stubEnv("VITE_API_BASE_URL", "https://base.example.com");

    expect(resolveApiBaseUrl()).toBe("https://api.example.com");
  });

  it("unwraps successful API envelopes", () => {
    const response = {
      success: true,
      data: { id: "scan-1" },
      message: null,
      timestamp: "2026-03-25T00:00:00.000Z",
    } satisfies SuccessResponse<{ id: string }>;

    expect(unwrapApiResponse(response)).toEqual({ id: "scan-1" });
  });

  it("throws when given an error API envelope", () => {
    const response = {
      success: false,
      data: null,
      message: "Request failed",
      errorCode: "REQUEST_FAILED",
      timestamp: "2026-03-25T00:00:00.000Z",
    } satisfies ErrorResponse;

    expect(() => unwrapApiResponse(response)).toThrow("Request failed");
  });
});
