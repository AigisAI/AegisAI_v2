import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { listConnectedRepos, listRepoBranches } from "../api/repos";
import { getScan, listRepoScans, requestScan } from "../api/scans";
import { createQueryClient } from "../query-client";
import { ScanPage } from "./ScanPage";

vi.mock("../api/repos", () => ({
  listConnectedRepos: vi.fn(),
  listRepoBranches: vi.fn(),
}));

vi.mock("../api/scans", () => ({
  requestScan: vi.fn(),
  getScan: vi.fn(),
  listRepoScans: vi.fn(),
}));

const mockedListConnectedRepos = vi.mocked(listConnectedRepos);
const mockedListRepoBranches = vi.mocked(listRepoBranches);
const mockedRequestScan = vi.mocked(requestScan);
const mockedListRepoScans = vi.mocked(listRepoScans);
const mockedGetScan = vi.mocked(getScan);

function renderScanPage() {
  return render(
    <QueryClientProvider client={createQueryClient()}>
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("ScanPage", () => {
  beforeEach(() => {
    mockedListConnectedRepos.mockReset();
    mockedListRepoBranches.mockReset();
    mockedRequestScan.mockReset();
    mockedListRepoScans.mockReset();
    mockedGetScan.mockReset();

    mockedListConnectedRepos.mockResolvedValue([
      {
        id: "repo-1",
        provider: "github",
        fullName: "acme/payments-service",
        cloneUrl: "https://github.com/acme/payments-service.git",
        defaultBranch: "main",
        isPrivate: true,
        lastScanAt: "2026-03-27T08:00:00.000Z",
        lastScanStatus: "RUNNING",
      },
      {
        id: "repo-2",
        provider: "gitlab",
        fullName: "ops/compliance-service",
        cloneUrl: "https://gitlab.com/ops/compliance-service.git",
        defaultBranch: "trunk",
        isPrivate: true,
        lastScanAt: null,
        lastScanStatus: null,
      },
    ]);

    mockedListRepoBranches.mockImplementation(async (repoId) => {
      if (repoId === "repo-2") {
        return {
          items: [
            {
              name: "trunk",
              isDefault: true,
              lastCommitSha: "ghi9012",
            },
          ],
          page: 1,
          size: 30,
          hasNextPage: false,
          nextPage: null,
        };
      }

      return {
        items: [
          {
            name: "main",
            isDefault: true,
            lastCommitSha: "abc1234",
          },
          {
            name: "release/2026",
            isDefault: false,
            lastCommitSha: "def5678",
          },
        ],
        page: 1,
        size: 30,
        hasNextPage: false,
        nextPage: null,
      };
    });

    mockedListRepoScans.mockImplementation(async (repoId) => {
      if (repoId === "repo-2") {
        return {
          items: [],
          totalCount: 0,
          page: 1,
          totalPages: 1,
        };
      }

      return {
        items: [
          {
            id: "scan-1",
            repoFullName: "acme/payments-service",
            branch: "main",
            commitSha: "abc1234",
            status: "RUNNING",
            language: "java",
            totalFiles: 42,
            totalLines: 8140,
            summary: {
              critical: 1,
              high: 2,
              medium: 4,
              low: 1,
              info: 0,
            },
            startedAt: "2026-03-27T08:00:00.000Z",
            completedAt: null,
            errorMessage: null,
            createdAt: "2026-03-27T07:58:00.000Z",
          },
          {
            id: "scan-0",
            repoFullName: "acme/payments-service",
            branch: "release/2026",
            commitSha: "def5678",
            status: "DONE",
            language: "java",
            totalFiles: 40,
            totalLines: 7990,
            summary: {
              critical: 0,
              high: 1,
              medium: 3,
              low: 2,
              info: 1,
            },
            startedAt: "2026-03-26T08:00:00.000Z",
            completedAt: "2026-03-26T08:06:00.000Z",
            errorMessage: null,
            createdAt: "2026-03-26T07:58:00.000Z",
          },
        ],
        totalCount: 2,
        page: 1,
        totalPages: 1,
      };
    });

    mockedGetScan.mockResolvedValue({
      id: "scan-1",
      repoFullName: "acme/payments-service",
      branch: "main",
      commitSha: "abc1234",
      status: "RUNNING",
      language: "java",
      totalFiles: 42,
      totalLines: 8140,
      summary: {
        critical: 1,
        high: 2,
        medium: 4,
        low: 1,
        info: 0,
      },
      startedAt: "2026-03-27T08:00:00.000Z",
      completedAt: null,
      errorMessage: null,
      createdAt: "2026-03-27T07:58:00.000Z",
    });

    mockedRequestScan.mockResolvedValue({
      scanId: "scan-2",
      status: "PENDING",
      message: "Scan queued successfully.",
    });
  });

  it("renders the scan workspace with request controls, recent history, and selected scan detail", async () => {
    renderScanPage();

    expect(
      screen.getByRole("heading", { name: /orchestrate the next review/i })
    ).toBeInTheDocument();

    const requestSection = screen.getByRole("region", {
      name: /scan request form/i,
    });
    expect(
      await within(requestSection).findByRole("button", { name: /acme\/payments-service/i })
    ).toBeInTheDocument();
    expect(await within(requestSection).findByRole("option", { name: "release/2026" })).toBeInTheDocument();

    const recentScansSection = screen.getByRole("region", {
      name: /recent scans/i,
    });
    expect(await within(recentScansSection).findByText("scan-1")).toBeInTheDocument();

    const statusSection = screen.getByRole("region", {
      name: /selected scan status/i,
    });
    expect(await within(statusSection).findByText(/running/i)).toBeInTheDocument();
    expect(within(statusSection).getByText("abc1234")).toBeInTheDocument();
    expect(within(statusSection).getByText("Critical")).toBeInTheDocument();
  });

  it("requests a new scan for the selected repository and branch", async () => {
    const user = userEvent.setup();

    renderScanPage();

    const branchSelect = await screen.findByLabelText(/branch selector/i);
    await screen.findByRole("option", { name: "release/2026" });
    await user.selectOptions(branchSelect, "release/2026");
    await user.click(screen.getByRole("button", { name: /queue java scan/i }));

    await waitFor(() => {
      expect(mockedRequestScan).toHaveBeenCalledTimes(1);
      expect(mockedRequestScan.mock.calls[0]?.[0]).toEqual({
        repoId: "repo-1",
        branch: "release/2026",
      });
    });

    expect(await screen.findByText(/scan queued successfully/i)).toBeInTheDocument();
  });

  it("renders a connect-first empty state when no repositories are available for scanning", async () => {
    mockedListConnectedRepos.mockResolvedValueOnce([]);

    renderScanPage();

    expect(
      await screen.findByText(/connect a repository before requesting a scan/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/recent scans will appear once a repository is linked/i)).toBeInTheDocument();
  });
});
