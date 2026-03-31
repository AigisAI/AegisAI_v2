import { beforeEach, describe, expect, it, vi } from "vitest";

import { getDashboardWorkspaceData } from "./dashboard";
import { listConnectedRepos } from "./repos";
import { listRepoScans } from "./scans";

vi.mock("./repos", () => ({
  listConnectedRepos: vi.fn(),
}));

vi.mock("./scans", () => ({
  listRepoScans: vi.fn(),
}));

const mockedListConnectedRepos = vi.mocked(listConnectedRepos);
const mockedListRepoScans = vi.mocked(listRepoScans);

describe("dashboard api helper", () => {
  beforeEach(() => {
    mockedListConnectedRepos.mockReset();
    mockedListRepoScans.mockReset();
  });

  it("aggregates connected repositories into a recent dashboard snapshot", async () => {
    mockedListConnectedRepos.mockResolvedValue([
      {
        id: "repo-1",
        provider: "github",
        fullName: "acme/payments-service",
        cloneUrl: "https://github.com/acme/payments-service.git",
        defaultBranch: "main",
        isPrivate: true,
        lastScanAt: "2026-03-31T08:00:00.000Z",
        lastScanStatus: "DONE",
      },
      {
        id: "repo-2",
        provider: "gitlab",
        fullName: "ops/compliance-service",
        cloneUrl: "https://gitlab.com/ops/compliance-service.git",
        defaultBranch: "trunk",
        isPrivate: true,
        lastScanAt: "2026-03-31T07:30:00.000Z",
        lastScanStatus: "RUNNING",
      },
    ]);

    mockedListRepoScans.mockImplementation(async (repoId) => {
      if (repoId === "repo-1") {
        return {
          items: [
            {
              id: "scan-1",
              repoFullName: "acme/payments-service",
              branch: "main",
              commitSha: "abc1234",
              status: "DONE",
              language: "java",
              totalFiles: 40,
              totalLines: 8100,
              summary: {
                critical: 1,
                high: 2,
                medium: 1,
                low: 0,
                info: 0,
              },
              startedAt: "2026-03-31T08:00:00.000Z",
              completedAt: "2026-03-31T08:06:00.000Z",
              errorMessage: null,
              createdAt: "2026-03-31T07:58:00.000Z",
            },
          ],
          totalCount: 3,
          page: 1,
          totalPages: 1,
        };
      }

      return {
        items: [
          {
            id: "scan-2",
            repoFullName: "ops/compliance-service",
            branch: "release/2026",
            commitSha: "def5678",
            status: "RUNNING",
            language: "java",
            totalFiles: 12,
            totalLines: 1900,
            summary: {
              critical: 0,
              high: 1,
              medium: 2,
              low: 1,
              info: 0,
            },
            startedAt: "2026-03-31T09:00:00.000Z",
            completedAt: null,
            errorMessage: null,
            createdAt: "2026-03-31T08:55:00.000Z",
          },
        ],
        totalCount: 4,
        page: 1,
        totalPages: 1,
      };
    });

    const result = await getDashboardWorkspaceData();

    expect(result.totalRepos).toBe(2);
    expect(result.totalScans).toBe(7);
    expect(result.openVulnerabilities).toEqual({
      critical: 1,
      high: 3,
      medium: 3,
      low: 1,
      info: 0,
    });
    expect(result.recentScans.map((scan) => scan.id)).toEqual(["scan-2", "scan-1"]);
    expect(result.completedScans.map((scan) => scan.id)).toEqual(["scan-1"]);
    expect(result.severitySummary).toEqual({
      critical: 1,
      high: 3,
      medium: 3,
      low: 1,
      info: 0,
    });
    expect(result.trend).toEqual([
      {
        date: "Mar 31",
        critical: 1,
        high: 2,
        medium: 1,
      },
    ]);
  });

  it("keeps trend labels stable for users west of UTC", async () => {
    const originalTimezone = process.env.TZ;
    process.env.TZ = "America/New_York";

    mockedListConnectedRepos.mockResolvedValue([
      {
        id: "repo-1",
        provider: "github",
        fullName: "acme/payments-service",
        cloneUrl: "https://github.com/acme/payments-service.git",
        defaultBranch: "main",
        isPrivate: true,
        lastScanAt: "2026-03-31T08:00:00.000Z",
        lastScanStatus: "DONE",
      },
    ]);

    mockedListRepoScans.mockResolvedValue({
      items: [
        {
          id: "scan-1",
          repoFullName: "acme/payments-service",
          branch: "main",
          commitSha: "abc1234",
          status: "DONE",
          language: "java",
          totalFiles: 40,
          totalLines: 8100,
          summary: {
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
          },
          startedAt: "2026-03-31T08:00:00.000Z",
          completedAt: "2026-03-31T08:06:00.000Z",
          errorMessage: null,
          createdAt: "2026-03-31T07:58:00.000Z",
        },
      ],
      totalCount: 1,
      page: 1,
      totalPages: 1,
    });

    const result = await getDashboardWorkspaceData();

    expect(result.trend[0]?.date).toBe("Mar 31");

    process.env.TZ = originalTimezone;
  });

  it("marks the dashboard degraded when only part of the scan surface can be loaded", async () => {
    mockedListConnectedRepos.mockResolvedValue([
      {
        id: "repo-1",
        provider: "github",
        fullName: "acme/payments-service",
        cloneUrl: "https://github.com/acme/payments-service.git",
        defaultBranch: "main",
        isPrivate: true,
        lastScanAt: "2026-03-31T08:00:00.000Z",
        lastScanStatus: "DONE",
      },
      {
        id: "repo-2",
        provider: "gitlab",
        fullName: "ops/compliance-service",
        cloneUrl: "https://gitlab.com/ops/compliance-service.git",
        defaultBranch: "trunk",
        isPrivate: true,
        lastScanAt: "2026-03-31T07:30:00.000Z",
        lastScanStatus: "FAILED",
      },
    ]);

    mockedListRepoScans
      .mockResolvedValueOnce({
        items: [],
        totalCount: 1,
        page: 1,
        totalPages: 1,
      })
      .mockRejectedValueOnce(new Error("Provider archive unavailable."));

    const result = await getDashboardWorkspaceData();

    expect(result.degraded).toBe(true);
    expect(result.totalScans).toBe(1);
  });
});
