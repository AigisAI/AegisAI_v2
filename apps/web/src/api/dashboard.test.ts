import { beforeEach, describe, expect, it, vi } from "vitest";

import { unwrapApiResponse } from "./client";
import { getDashboardWorkspaceData } from "./dashboard";

const { mockedGet } = vi.hoisted(() => ({
  mockedGet: vi.fn(),
}));

vi.mock("./client", () => ({
  apiClient: {
    get: mockedGet,
  },
  unwrapApiResponse: vi.fn(),
}));

const mockedUnwrapApiResponse = vi.mocked(unwrapApiResponse);

describe("dashboard api helper", () => {
  beforeEach(() => {
    mockedGet.mockReset();
    mockedUnwrapApiResponse.mockReset();
  });

  it("loads the dashboard workspace snapshot from the dashboard api", async () => {
    mockedGet.mockResolvedValue({
      data: { success: true },
    });
    mockedUnwrapApiResponse.mockReturnValue({
      totalRepos: 2,
      totalScans: 7,
      openVulnerabilities: {
        critical: 1,
        high: 2,
        medium: 1,
        low: 0,
        info: 0,
      },
      recentScans: [],
      trend: [],
      connectedRepos: [],
      completedScans: [],
      severitySummary: {
        critical: 1,
        high: 2,
        medium: 1,
        low: 0,
        info: 0,
      },
      degraded: false,
    });

    const result = await getDashboardWorkspaceData();

    expect(mockedGet).toHaveBeenCalledWith("/dashboard");
    expect(result.totalRepos).toBe(2);
    expect(result.severitySummary.high).toBe(2);
    expect(result.degraded).toBe(false);
  });
});
