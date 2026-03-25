import type { InternalAxiosRequestConfig } from "axios";
import type { ErrorResponse, SuccessResponse } from "@aegisai/shared";
import { describe, expect, it } from "vitest";

import {
  attachCsrfHeader,
  shouldRedirectToLogin,
  unwrapApiResponse,
} from "./client";

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
