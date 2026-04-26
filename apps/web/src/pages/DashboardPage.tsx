import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { getDashboardWorkspaceData } from "../api/dashboard";
import {
  getReportDetail,
  getReportDownloadUrl,
  requestPdfReport,
} from "../api/reports";

const ACTIVE_SCAN_STATUSES = new Set(["PENDING", "RUNNING"]);

export function DashboardPage() {
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [reportIdsByScan, setReportIdsByScan] = useState<Record<string, string>>({});
  const [reportMessage, setReportMessage] = useState<string | null>(null);

  const dashboardQuery = useQuery({
    queryKey: ["dashboard", "workspace"],
    queryFn: getDashboardWorkspaceData,
    refetchInterval: (query) =>
      query.state.data?.recentScans.some((scan) => ACTIVE_SCAN_STATUSES.has(scan.status))
        ? 5000
        : false,
  });

  useEffect(() => {
    const firstScanId = dashboardQuery.data?.recentScans[0]?.id ?? null;

    if (!selectedScanId && firstScanId) {
      setSelectedScanId(firstScanId);
      return;
    }

    if (
      selectedScanId &&
      dashboardQuery.data &&
      !dashboardQuery.data.recentScans.some((scan) => scan.id === selectedScanId)
    ) {
      setSelectedScanId(firstScanId);
    }
  }, [dashboardQuery.data, selectedScanId]);

  const selectedScan =
    dashboardQuery.data?.recentScans.find((scan) => scan.id === selectedScanId) ?? null;
  const selectedReportId = selectedScan ? reportIdsByScan[selectedScan.id] ?? null : null;

  const selectedReportQuery = useQuery({
    queryKey: ["reports", "detail", selectedReportId],
    queryFn: () => getReportDetail(selectedReportId!),
    enabled: Boolean(selectedReportId),
    refetchInterval: (query) => {
      if (!selectedReportId) {
        return false;
      }

      if (query.state.data?.status === "GENERATING") {
        return 4000;
      }

      if (!query.state.data && query.state.error) {
        return 4000;
      }

      return false;
    },
  });

  const requestReportMutation = useMutation({
    mutationFn: requestPdfReport,
    onSuccess: (response, scanId) => {
      setReportIdsByScan((current) => ({
        ...current,
        [scanId]: response.reportId,
      }));
      setReportMessage(response.message);
    },
  });

  const severitySummary = dashboardQuery.data?.severitySummary ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  const selectedScanFindings = useMemo(() => {
    if (!selectedScan) {
      return 0;
    }

    return (
      selectedScan.summary.critical +
      selectedScan.summary.high +
      selectedScan.summary.medium +
      selectedScan.summary.low +
      selectedScan.summary.info
    );
  }, [selectedScan]);

  const reportActionLabel = getReportActionLabel({
    isPending:
      requestReportMutation.isPending && requestReportMutation.variables === selectedScan?.id,
    reportStatus: selectedReportQuery.data?.status,
  });

  return (
    <section className="dashboard-page">
      <header className="dashboard-hero">
        <div className="dashboard-hero-copy">
          <p className="eyebrow">Operational overview</p>
          <h2>Read the latest security posture before you open the next report</h2>
          <div className="dashboard-hero-accent">
            <p>
              AegisAI summarizes the most recent repository reviews, highlights where
              severity is clustering, and keeps PDF export one click away for completed scans.
            </p>
          </div>
        </div>

        <div className="dashboard-hero-panel" aria-hidden="true">
          <span className="dashboard-hero-panel-kicker">Recent signal, not vanity totals.</span>
        </div>
      </header>

      {dashboardQuery.error ? (
        <div className="dashboard-inline-alert" role="alert">
          <strong>Dashboard summary unavailable</strong>
          <p>{getErrorMessage(dashboardQuery.error)}</p>
        </div>
      ) : dashboardQuery.isLoading ? (
        <section className="dashboard-section">
          <p className="dashboard-state-copy">Loading recent scan posture...</p>
        </section>
      ) : !dashboardQuery.data?.connectedRepos.length ? (
        <section className="dashboard-section dashboard-empty-state">
          <strong>Connect a repository before the dashboard can summarize activity.</strong>
          <p>
            Once a source is linked, AegisAI will surface recent scans, severity movement,
            and PDF report entry from this workspace.
          </p>
          <div className="dashboard-empty-actions">
            <Link className="dashboard-secondary-link" to="/repos">
              Go to repository connections
            </Link>
          </div>
        </section>
      ) : (
        <div className="dashboard-layout">
          <div className="dashboard-main">
            {dashboardQuery.data.degraded ? (
              <div className="dashboard-inline-alert dashboard-inline-alert-neutral" role="status">
                <strong>Dashboard is running in a degraded mode.</strong>
                <p>
                  One or more repository histories could not be refreshed. The snapshot below
                  still reflects the scan data that was available.
                </p>
              </div>
            ) : null}

            <section className="dashboard-section" aria-label="Summary snapshot">
              <div className="dashboard-section-heading">
                <p className="eyebrow">Summary snapshot</p>
                <h3>Recent signal across connected repositories</h3>
              </div>

              <div className="dashboard-metric-grid">
                <article className="dashboard-metric-tile">
                  <span>Connected repos</span>
                  <strong>{dashboardQuery.data.totalRepos}</strong>
                  <p>Sources with active session access.</p>
                </article>
                <article className="dashboard-metric-tile">
                  <span>Tracked scans</span>
                  <strong>{dashboardQuery.data.totalScans}</strong>
                  <p>Known scan records across connected repos.</p>
                </article>
                <article className="dashboard-metric-tile">
                  <span>Recent findings</span>
                  <strong>{getTotalFindingsFromSummary(dashboardQuery.data.openVulnerabilities)}</strong>
                  <p>Severity volume inside the current dashboard window.</p>
                </article>
                <article className="dashboard-metric-tile">
                  <span>Report-ready scans</span>
                  <strong>{dashboardQuery.data.completedScans.length}</strong>
                  <p>Completed reviews that can open PDF export.</p>
                </article>
              </div>

              <div className="dashboard-severity-band">
                {Object.entries(severitySummary).map(([severity, count]) => (
                  <div
                    key={severity}
                    className={`dashboard-severity-tile is-${severity}`}
                  >
                    <span>{capitalize(severity)}</span>
                    <strong>{count}</strong>
                  </div>
                ))}
              </div>
            </section>

            <section className="dashboard-section" aria-label="Severity trend">
              <div className="dashboard-section-heading">
                <p className="eyebrow">Trend</p>
                <h3>Where critical and high findings were surfacing most recently</h3>
              </div>

              {dashboardQuery.data.trend.length ? (
                <div className="dashboard-trend-grid">
                  {dashboardQuery.data.trend.map((item) => (
                    <article key={item.date} className="dashboard-trend-card">
                      <strong>{item.date}</strong>
                      <div className="dashboard-trend-stack">
                        <span>
                          Critical <b>{item.critical}</b>
                        </span>
                        <span>
                          High <b>{item.high}</b>
                        </span>
                        <span>
                          Medium <b>{item.medium}</b>
                        </span>
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <p className="dashboard-state-copy">
                  Trend tiles appear once completed scans are available in the recent window.
                </p>
              )}
            </section>

            <section className="dashboard-section" aria-label="Recent scans">
              <div className="dashboard-section-heading">
                <p className="eyebrow">Recent scans</p>
                <h3>Choose the scan that should anchor the next report</h3>
              </div>

              {dashboardQuery.data.recentScans.length ? (
                <div className="dashboard-scan-list">
                  {dashboardQuery.data.recentScans.map((scan) => (
                    <button
                      key={scan.id}
                      className={`dashboard-scan-card${
                        scan.id === selectedScanId ? " is-selected" : ""
                      }`}
                      onClick={() => {
                        setSelectedScanId(scan.id);
                        setReportMessage(null);
                      }}
                      type="button"
                      aria-pressed={scan.id === selectedScanId}
                    >
                      <div className="dashboard-scan-header">
                        <strong>{scan.repoFullName}</strong>
                        <span className={`scan-status-pill is-${scan.status.toLowerCase()}`}>
                          {formatStatus(scan.status)}
                        </span>
                      </div>
                      <p>{scan.branch}</p>
                      <div className="dashboard-scan-meta">
                        <span>Findings {getTotalFindings(scan)}</span>
                        <span>Files {scan.totalFiles ?? "??"}</span>
                        <span>
                          {scan.status === "DONE"
                            ? "Report ready"
                            : "Report opens after completion"}
                        </span>
                      </div>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="dashboard-empty-state">
                  <strong>No recent scans are available yet.</strong>
                  <p>Queue the first repository review to populate dashboard reporting.</p>
                  <div className="dashboard-empty-actions">
                    <Link className="dashboard-secondary-link" to="/scan">
                      Open scan workspace
                    </Link>
                  </div>
                </div>
              )}
            </section>
          </div>

          <aside className="dashboard-aside">
            <section className="dashboard-aside-card" aria-label="Report entry">
              <p className="eyebrow">Report entry</p>
              <h3>Turn the selected scan into a downloadable briefing</h3>

              {!selectedScan ? (
                <p className="dashboard-state-copy">
                  Choose a recent scan to open report generation controls.
                </p>
              ) : (
                <>
                  <div className="dashboard-report-header">
                    <strong>{selectedScan.repoFullName}</strong>
                    <span className={`scan-status-pill is-${selectedScan.status.toLowerCase()}`}>
                      {formatStatus(selectedScan.status)}
                    </span>
                  </div>

                  <dl className="dashboard-detail-grid">
                    <div>
                      <dt>Branch</dt>
                      <dd>{selectedScan.branch}</dd>
                    </div>
                    <div>
                      <dt>Findings</dt>
                      <dd>{selectedScanFindings}</dd>
                    </div>
                    <div>
                      <dt>Commit</dt>
                      <dd>{selectedScan.commitSha ?? "Pending SHA"}</dd>
                    </div>
                    <div>
                      <dt>Finished</dt>
                      <dd>{formatTimestamp(selectedScan.completedAt ?? selectedScan.createdAt)}</dd>
                    </div>
                  </dl>

                  {selectedScan.status !== "DONE" ? (
                    <div className="dashboard-inline-alert dashboard-inline-alert-neutral" role="status">
                      <strong>PDF export opens after a completed scan.</strong>
                      <p>
                        Keep this scan selected to follow progress, or move to the scan workspace
                        for deeper status tracking.
                      </p>
                    </div>
                  ) : (
                    <>
                      {requestReportMutation.error ? (
                        <div className="dashboard-inline-alert" role="alert">
                          <strong>Report request failed</strong>
                          <p>{getErrorMessage(requestReportMutation.error)}</p>
                        </div>
                      ) : null}

                      {reportMessage ? (
                        <p className="dashboard-success-note" role="status">
                          {reportMessage}
                        </p>
                      ) : null}

                      {selectedReportId && selectedReportQuery.error ? (
                        <div className="dashboard-inline-alert" role="alert">
                          <strong>Report status unavailable</strong>
                          <p>{getErrorMessage(selectedReportQuery.error)}</p>
                        </div>
                      ) : null}

                      <div className="dashboard-report-status-card">
                        <div className="dashboard-report-status-header">
                          <span>PDF status</span>
                          <strong>
                            {selectedReportQuery.data?.status ??
                              (selectedReportId ? "Checking..." : "Not requested")}
                          </strong>
                        </div>

                        <p>
                          {getReportNarrative(
                            selectedScan.status,
                            selectedReportQuery.data?.status ?? null
                          )}
                        </p>

                        {selectedReportQuery.data?.expiresAt ? (
                          <p className="dashboard-report-expiry">
                            Expires {formatTimestamp(selectedReportQuery.data.expiresAt)}
                          </p>
                        ) : null}

                        {selectedReportQuery.data?.errorMessage ? (
                          <p className="dashboard-report-expiry">
                            {selectedReportQuery.data.errorMessage}
                          </p>
                        ) : null}
                      </div>

                      <div className="dashboard-report-actions">
                        <button
                          className="dashboard-primary-action"
                          disabled={
                            requestReportMutation.isPending ||
                            selectedScan.status !== "DONE"
                          }
                          onClick={() => {
                            setReportMessage(null);
                            requestReportMutation.mutate(selectedScan.id);
                          }}
                          type="button"
                        >
                          {reportActionLabel}
                        </button>

                        {selectedReportId && selectedReportQuery.data?.status === "READY" ? (
                          <a
                            className="dashboard-secondary-link dashboard-secondary-link-strong"
                            href={getReportDownloadUrl(selectedReportId)}
                          >
                            Download PDF report
                          </a>
                        ) : null}

                        {selectedScan.status === "DONE" ? (
                          <Link className="dashboard-secondary-link" to={`/scan/${selectedScan.id}/review`}>
                            Open vulnerability review
                          </Link>
                        ) : (
                          <Link className="dashboard-secondary-link" to="/scan">
                            Open scan workspace
                          </Link>
                        )}
                      </div>
                    </>
                  )}
                </>
              )}
            </section>

            <section className="dashboard-aside-card" aria-label="Report protocol">
              <p className="eyebrow">Report protocol</p>
              <h3>Keep the exported brief aligned with repository state</h3>
              <ul className="dashboard-trust-list">
                <li>PDF export only opens after a completed repository review.</li>
                <li>Each request reuses an active report when one is already generating or ready.</li>
                <li>Expired reports are regenerated from the current persisted scan snapshot.</li>
              </ul>
            </section>
          </aside>
        </div>
      )}
    </section>
  );
}

function capitalize(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function formatStatus(status: string) {
  return status.charAt(0) + status.slice(1).toLowerCase();
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function getTotalFindings(scan: {
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}) {
  return (
    scan.summary.critical +
    scan.summary.high +
    scan.summary.medium +
    scan.summary.low +
    scan.summary.info
  );
}

function getTotalFindingsFromSummary(summary: {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}) {
  return summary.critical + summary.high + summary.medium + summary.low + summary.info;
}

function getReportNarrative(
  scanStatus: string,
  reportStatus: "GENERATING" | "READY" | "FAILED" | "EXPIRED" | null
) {
  if (scanStatus !== "DONE") {
    return "A scan must complete before AegisAI can open report generation.";
  }

  switch (reportStatus) {
    case "GENERATING":
      return "AegisAI is composing the PDF brief and will refresh this status automatically.";
    case "READY":
      return "The latest PDF brief is ready to download from the selected scan.";
    case "FAILED":
      return "The last PDF generation attempt failed. Request a fresh export to try again.";
    case "EXPIRED":
      return "The previous PDF expired. Generate a new copy from the stored scan snapshot.";
    default:
      return "Request a PDF brief for this completed scan when you are ready to share results.";
  }
}

function getReportActionLabel({
  isPending,
  reportStatus,
}: {
  isPending: boolean;
  reportStatus: "GENERATING" | "READY" | "FAILED" | "EXPIRED" | undefined;
}) {
  if (isPending) {
    return "Preparing PDF...";
  }

  switch (reportStatus) {
    case "GENERATING":
      return "Refresh report status";
    case "READY":
      return "Reuse current PDF";
    case "FAILED":
    case "EXPIRED":
      return "Generate fresh PDF";
    default:
      return "Generate PDF report";
  }
}

function getErrorMessage(error: unknown) {
  if (
    error &&
    typeof error === "object" &&
    "response" in error &&
    error.response &&
    typeof error.response === "object" &&
    "data" in error.response &&
    error.response.data &&
    typeof error.response.data === "object" &&
    "message" in error.response.data &&
    typeof error.response.data.message === "string"
  ) {
    return error.response.data.message;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "An unexpected error occurred.";
}
