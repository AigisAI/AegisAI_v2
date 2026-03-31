import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getDashboardWorkspaceData } from "../api/dashboard";
import { getReportDetail, requestPdfReport } from "../api/reports";
import { createQueryClient } from "../query-client";
import { DashboardPage } from "./DashboardPage";

vi.mock("../api/dashboard", () => ({
  getDashboardWorkspaceData: vi.fn(),
}));

vi.mock("../api/reports", () => ({
  requestPdfReport: vi.fn(),
  getReportDetail: vi.fn(),
  getReportDownloadUrl: (reportId: string) => `/api/reports/${reportId}/download`,
}));

const mockedGetDashboardWorkspaceData = vi.mocked(getDashboardWorkspaceData);
const mockedRequestPdfReport = vi.mocked(requestPdfReport);
const mockedGetReportDetail = vi.mocked(getReportDetail);

function renderDashboardPage() {
  return render(
    <QueryClientProvider client={createQueryClient()}>
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("DashboardPage", () => {
  beforeEach(() => {
    mockedGetDashboardWorkspaceData.mockReset();
    mockedRequestPdfReport.mockReset();
    mockedGetReportDetail.mockReset();

    mockedGetDashboardWorkspaceData.mockResolvedValue({
      totalRepos: 2,
      totalScans: 8,
      openVulnerabilities: {
        critical: 1,
        high: 3,
        medium: 2,
        low: 1,
        info: 0,
      },
      trend: [
        {
          date: "Mar 30",
          critical: 0,
          high: 1,
          medium: 1,
        },
        {
          date: "Mar 31",
          critical: 1,
          high: 2,
          medium: 0,
        },
      ],
      recentScans: [
        {
          id: "scan-1",
          repoFullName: "acme/payments-service",
          branch: "main",
          commitSha: "abc1234",
          status: "DONE",
          language: "java",
          totalFiles: 44,
          totalLines: 8120,
          summary: {
            critical: 1,
            high: 2,
            medium: 0,
            low: 1,
            info: 0,
          },
          startedAt: "2026-03-31T08:00:00.000Z",
          completedAt: "2026-03-31T08:06:00.000Z",
          errorMessage: null,
          createdAt: "2026-03-31T07:58:00.000Z",
        },
        {
          id: "scan-2",
          repoFullName: "ops/compliance-service",
          branch: "release/2026",
          commitSha: "def5678",
          status: "RUNNING",
          language: "java",
          totalFiles: 18,
          totalLines: 2200,
          summary: {
            critical: 0,
            high: 1,
            medium: 2,
            low: 0,
            info: 0,
          },
          startedAt: "2026-03-31T09:00:00.000Z",
          completedAt: null,
          errorMessage: null,
          createdAt: "2026-03-31T08:58:00.000Z",
        },
      ],
      severitySummary: {
        critical: 1,
        high: 3,
        medium: 2,
        low: 1,
        info: 0,
      },
      completedScans: [
        {
          id: "scan-1",
          repoFullName: "acme/payments-service",
          branch: "main",
          commitSha: "abc1234",
          status: "DONE",
          language: "java",
          totalFiles: 44,
          totalLines: 8120,
          summary: {
            critical: 1,
            high: 2,
            medium: 0,
            low: 1,
            info: 0,
          },
          startedAt: "2026-03-31T08:00:00.000Z",
          completedAt: "2026-03-31T08:06:00.000Z",
          errorMessage: null,
          createdAt: "2026-03-31T07:58:00.000Z",
        },
      ],
      connectedRepos: [
        {
          id: "repo-1",
          provider: "github",
          fullName: "acme/payments-service",
          cloneUrl: "https://github.com/acme/payments-service.git",
          defaultBranch: "main",
          isPrivate: true,
          lastScanAt: "2026-03-31T08:06:00.000Z",
          lastScanStatus: "DONE",
        },
        {
          id: "repo-2",
          provider: "gitlab",
          fullName: "ops/compliance-service",
          cloneUrl: "https://gitlab.com/ops/compliance-service.git",
          defaultBranch: "trunk",
          isPrivate: true,
          lastScanAt: "2026-03-31T09:00:00.000Z",
          lastScanStatus: "RUNNING",
        },
      ],
      degraded: false,
    });

    mockedRequestPdfReport.mockResolvedValue({
      reportId: "report-1",
      status: "GENERATING",
      message: "PDF report generation has started.",
    });

    mockedGetReportDetail.mockResolvedValue({
      id: "report-1",
      scanId: "scan-1",
      status: "READY",
      downloadUrl: null,
      errorMessage: null,
      createdAt: "2026-03-31T08:07:00.000Z",
      expiresAt: "2026-03-31T20:07:00.000Z",
    });
  });

  it("renders the dashboard workspace and connects report entry to a completed scan", async () => {
    const user = userEvent.setup();

    renderDashboardPage();

    expect(
      screen.getByRole("heading", { name: /read the latest security posture/i })
    ).toBeInTheDocument();

    const summaryRegion = await screen.findByRole("region", { name: /summary snapshot/i });
    expect(within(summaryRegion).getByText(/^Connected repos$/)).toBeInTheDocument();
    expect(within(summaryRegion).getByText(/^Tracked scans$/)).toBeInTheDocument();

    const reportRegion = screen.getByRole("region", { name: /report entry/i });
    expect(await within(reportRegion).findByText("acme/payments-service")).toBeInTheDocument();

    await user.click(
      within(reportRegion).getByRole("button", { name: /generate pdf report/i })
    );

    await waitFor(() => {
      expect(mockedRequestPdfReport).toHaveBeenCalledWith(
        "scan-1",
        expect.objectContaining({
          client: expect.any(Object),
        })
      );
    });

    expect(await within(reportRegion).findByText(/generation has started/i)).toBeInTheDocument();
    expect(await within(reportRegion).findByText("READY")).toBeInTheDocument();
    expect(
      within(reportRegion).getByRole("link", { name: /download pdf report/i })
    ).toHaveAttribute("href", "/api/reports/report-1/download");
  });

  it("renders a degraded state when only part of the dashboard surface is available", async () => {
    mockedGetDashboardWorkspaceData.mockResolvedValueOnce({
      totalRepos: 1,
      totalScans: 2,
      openVulnerabilities: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      trend: [],
      recentScans: [],
      severitySummary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      completedScans: [],
      connectedRepos: [
        {
          id: "repo-1",
          provider: "github",
          fullName: "acme/payments-service",
          cloneUrl: "https://github.com/acme/payments-service.git",
          defaultBranch: "main",
          isPrivate: true,
          lastScanAt: null,
          lastScanStatus: null,
        },
      ],
      degraded: true,
    });

    renderDashboardPage();

    expect(await screen.findByText(/dashboard is running in a degraded mode/i)).toBeInTheDocument();
  });

  it("keeps polling report detail after a transient status failure", async () => {
    const user = userEvent.setup();

    mockedGetReportDetail
      .mockRejectedValueOnce(new Error("Temporary report status outage."))
      .mockResolvedValue({
        id: "report-1",
        scanId: "scan-1",
        status: "READY",
        downloadUrl: null,
        errorMessage: null,
        createdAt: "2026-03-31T08:07:00.000Z",
        expiresAt: "2026-03-31T20:07:00.000Z",
      });

    renderDashboardPage();

    const reportRegion = await screen.findByRole("region", { name: /report entry/i });

    await user.click(
      within(reportRegion).getByRole("button", { name: /generate pdf report/i })
    );

    expect(await within(reportRegion).findByText(/report status unavailable/i)).toBeInTheDocument();
    expect(
      await within(reportRegion).findByRole("link", { name: /download pdf report/i }, { timeout: 5000 })
    ).toHaveAttribute("href", "/api/reports/report-1/download");
  });

  it("renders an empty state when no repositories are connected yet", async () => {
    mockedGetDashboardWorkspaceData.mockResolvedValueOnce({
      totalRepos: 0,
      totalScans: 0,
      openVulnerabilities: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      trend: [],
      recentScans: [],
      severitySummary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      completedScans: [],
      connectedRepos: [],
      degraded: false,
    });

    renderDashboardPage();

    expect(
      await screen.findByText(/connect a repository before the dashboard can summarize activity/i)
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /go to repository connections/i })).toHaveAttribute(
      "href",
      "/repos"
    );
  });
});
