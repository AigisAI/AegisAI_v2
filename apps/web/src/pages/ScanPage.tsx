import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";

import { listConnectedRepos, listRepoBranches } from "../api/repos";
import { getScan, listRepoScans, requestScan } from "../api/scans";

const BRANCH_PAGE_SIZE = 100;
const RECENT_SCANS_PAGE_SIZE = 8;
const ACTIVE_SCAN_STATUSES = new Set(["PENDING", "RUNNING"]);

export function ScanPage() {
  const queryClient = useQueryClient();
  const [selectedRepoId, setSelectedRepoId] = useState<string | null>(null);
  const [selectedBranch, setSelectedBranch] = useState("");
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [submissionMessage, setSubmissionMessage] = useState<string | null>(null);

  const connectedReposQuery = useQuery({
    queryKey: ["repos", "connected"],
    queryFn: listConnectedRepos,
  });

  useEffect(() => {
    const firstRepoId = connectedReposQuery.data?.[0]?.id ?? null;

    if (!selectedRepoId && firstRepoId) {
      setSelectedRepoId(firstRepoId);
      return;
    }

    if (
      selectedRepoId &&
      connectedReposQuery.data &&
      !connectedReposQuery.data.some((repo) => repo.id === selectedRepoId)
    ) {
      setSelectedRepoId(firstRepoId);
    }
  }, [connectedReposQuery.data, selectedRepoId]);

  const selectedRepo =
    connectedReposQuery.data?.find((repo) => repo.id === selectedRepoId) ?? null;

  const branchesQuery = useQuery({
    queryKey: ["scan", "branches", selectedRepoId],
    queryFn: () =>
      listRepoBranches(selectedRepoId!, {
        page: 1,
        size: BRANCH_PAGE_SIZE,
      }),
    enabled: Boolean(selectedRepoId),
  });

  useEffect(() => {
    const branches = branchesQuery.data?.items ?? [];
    if (!branches.length) {
      setSelectedBranch("");
      return;
    }

    const preferredBranch =
      branches.find((branch) => branch.name === selectedRepo?.defaultBranch)?.name ??
      branches.find((branch) => branch.isDefault)?.name ??
      branches[0]?.name ??
      "";

    if (!selectedBranch || !branches.some((branch) => branch.name === selectedBranch)) {
      setSelectedBranch(preferredBranch);
    }
  }, [branchesQuery.data, selectedBranch, selectedRepo?.defaultBranch]);

  const recentScansQuery = useQuery({
    queryKey: ["scan", "recent", selectedRepoId],
    queryFn: () => listRepoScans(selectedRepoId!, 1, RECENT_SCANS_PAGE_SIZE),
    enabled: Boolean(selectedRepoId),
    refetchInterval: (query) => {
      const scans = query.state.data?.items ?? [];
      return scans.some((scan) => ACTIVE_SCAN_STATUSES.has(scan.status)) ? 5000 : false;
    },
  });

  useEffect(() => {
    const firstScanId = recentScansQuery.data?.items[0]?.id ?? null;

    if (!selectedScanId && firstScanId) {
      setSelectedScanId(firstScanId);
      return;
    }

    if (
      selectedScanId &&
      recentScansQuery.data &&
      !recentScansQuery.data.items.some((scan) => scan.id === selectedScanId)
    ) {
      setSelectedScanId(firstScanId);
    }
  }, [recentScansQuery.data, selectedScanId]);

  const selectedScanSummary =
    recentScansQuery.data?.items.find((scan) => scan.id === selectedScanId) ?? null;

  const selectedScanQuery = useQuery({
    queryKey: ["scan", "detail", selectedScanId],
    queryFn: () => getScan(selectedScanId!),
    enabled: Boolean(selectedScanId),
    refetchInterval: (query) =>
      query.state.data && ACTIVE_SCAN_STATUSES.has(query.state.data.status) ? 5000 : false,
  });

  const requestScanMutation = useMutation({
    mutationFn: requestScan,
    onSuccess: async (response) => {
      setSubmissionMessage(response.message);
      setSelectedScanId(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["scan", "recent"] }),
        queryClient.invalidateQueries({ queryKey: ["scan", "detail"] }),
        queryClient.invalidateQueries({ queryKey: ["repos", "connected"] }),
      ]);
    },
  });

  const selectedScan = selectedScanQuery.data ?? selectedScanSummary;
  const branchOptions = branchesQuery.data?.items ?? [];

  const requestDisabled =
    !selectedRepoId ||
    !selectedBranch ||
    requestScanMutation.isPending ||
    connectedReposQuery.isLoading ||
    branchesQuery.isLoading;

  const totals = useMemo(() => {
    if (!selectedScan) {
      return null;
    }

    return {
      findings:
        selectedScan.summary.critical +
        selectedScan.summary.high +
        selectedScan.summary.medium +
        selectedScan.summary.low +
        selectedScan.summary.info,
      files: selectedScan.totalFiles ?? "—",
      lines: selectedScan.totalLines ?? "—",
    };
  }, [selectedScan]);

  return (
    <section className="scan-page">
      <header className="scan-hero">
        <div className="scan-hero-copy">
          <p className="eyebrow">Scan orchestration</p>
          <h2>Orchestrate the next review</h2>
          <div className="scan-hero-accent">
            <p>
              Queue Java analysis against a controlled branch archive, then monitor the scan
              as AegisAI moves from repository snapshot to severity summary.
            </p>
          </div>
        </div>

        <div className="scan-hero-panel" aria-hidden="true">
          <span className="scan-hero-panel-kicker">Read only. Queue first.</span>
        </div>
      </header>

      <div className="scan-layout">
        <div className="scan-main">
          <section className="scan-section scan-request-card" aria-label="Scan request form">
            <div className="scan-section-heading">
              <p className="eyebrow">Request a scan</p>
              <h3>Select the source before analysis starts</h3>
            </div>

            {connectedReposQuery.error ? (
              <div className="scan-inline-alert" role="alert">
                <strong>Connected repositories unavailable</strong>
                <p>{getErrorMessage(connectedReposQuery.error)}</p>
              </div>
            ) : connectedReposQuery.isLoading ? (
              <p className="scan-state-copy">Loading connected repositories...</p>
            ) : connectedReposQuery.data?.length ? (
              <>
                <div className="scan-repo-selector" role="list" aria-label="Connected repositories">
                  {connectedReposQuery.data.map((repo) => (
                    <button
                      key={repo.id}
                      className={`scan-repo-option${
                        selectedRepoId === repo.id ? " is-selected" : ""
                      }`}
                      onClick={() => {
                        setSelectedRepoId(repo.id);
                        setSubmissionMessage(null);
                      }}
                      type="button"
                      aria-pressed={selectedRepoId === repo.id}
                    >
                      <span className="scan-repo-option-provider">{repo.provider}</span>
                      <strong>{repo.fullName}</strong>
                      <span>
                        {repo.isPrivate ? "Private" : "Public"} · default {repo.defaultBranch}
                      </span>
                    </button>
                  ))}
                </div>

                <div className="scan-form-grid">
                  <label className="scan-field">
                    <span>Repository</span>
                    <select
                      aria-label="Repository selector"
                      value={selectedRepoId ?? ""}
                      onChange={(event) => {
                        setSelectedRepoId(event.target.value);
                        setSubmissionMessage(null);
                      }}
                    >
                      {connectedReposQuery.data.map((repo) => (
                        <option key={repo.id} value={repo.id}>
                          {repo.fullName}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="scan-field">
                    <span>Branch selector</span>
                    <select
                      aria-label="Branch selector"
                      disabled={!branchOptions.length || branchesQuery.isLoading}
                      value={selectedBranch}
                      onChange={(event) => {
                        setSelectedBranch(event.target.value);
                        setSubmissionMessage(null);
                      }}
                    >
                      {branchOptions.map((branch) => (
                        <option key={branch.name} value={branch.name}>
                          {branch.name}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>

                {branchesQuery.error ? (
                  <div className="scan-inline-alert" role="alert">
                    <strong>Branch archive unavailable</strong>
                    <p>{getErrorMessage(branchesQuery.error)}</p>
                  </div>
                ) : null}

                {requestScanMutation.error ? (
                  <div className="scan-inline-alert" role="alert">
                    <strong>Scan request failed</strong>
                    <p>{getErrorMessage(requestScanMutation.error)}</p>
                  </div>
                ) : null}

                <div className="scan-form-footer">
                  <div className="scan-form-hint">
                    <p>Language</p>
                    <strong>Java-first analysis</strong>
                  </div>

                  <button
                    className="scan-primary-action"
                    disabled={requestDisabled}
                    onClick={() => {
                      if (!selectedRepoId || !selectedBranch) {
                        return;
                      }

                      requestScanMutation.mutate({
                        repoId: selectedRepoId,
                        branch: selectedBranch,
                      });
                    }}
                    type="button"
                  >
                    {requestScanMutation.isPending ? "Queueing..." : "Queue Java scan"}
                  </button>
                </div>

                {submissionMessage ? (
                  <p className="scan-success-note" role="status" aria-live="polite">
                    {submissionMessage}
                  </p>
                ) : null}
              </>
            ) : (
              <div className="scan-empty-state">
                <strong>Connect a repository before requesting a scan.</strong>
                <p>Recent scans will appear once a repository is linked and queued.</p>
              </div>
            )}
          </section>

          <section className="scan-section" aria-label="Recent scans">
            <div className="scan-section-heading">
              <p className="eyebrow">Recent scans</p>
              <h3>Track the latest branch reviews</h3>
            </div>

            {!selectedRepoId ? (
              <p className="scan-state-copy">Select a connected repository to inspect scans.</p>
            ) : recentScansQuery.error ? (
              <div className="scan-inline-alert" role="alert">
                <strong>Scan history unavailable</strong>
                <p>{getErrorMessage(recentScansQuery.error)}</p>
              </div>
            ) : recentScansQuery.isLoading ? (
              <p className="scan-state-copy">Loading recent scans...</p>
            ) : recentScansQuery.data?.items.length ? (
              <div className="scan-history-list">
                {recentScansQuery.data.items.map((scan) => (
                  <button
                    key={scan.id}
                    className={`scan-history-card${scan.id === selectedScanId ? " is-selected" : ""}`}
                    onClick={() => setSelectedScanId(scan.id)}
                    type="button"
                    aria-pressed={scan.id === selectedScanId}
                  >
                    <div className="scan-history-header">
                      <strong>{scan.id}</strong>
                      <span className={`scan-status-pill is-${scan.status.toLowerCase()}`}>
                        {formatStatus(scan.status)}
                      </span>
                    </div>
                    <p>{scan.branch}</p>
                    <div className="scan-severity-list">
                      <span>Critical {scan.summary.critical}</span>
                      <span>High {scan.summary.high}</span>
                      <span>Medium {scan.summary.medium}</span>
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <p className="scan-state-copy">No scans have been queued for this repository yet.</p>
            )}
          </section>
        </div>

        <aside className="scan-aside">
          <section className="scan-aside-card" aria-label="Selected scan status">
            <p className="eyebrow">Selected scan status</p>
            <h3>Read the current scan without leaving the queue</h3>

            {selectedScanQuery.error ? (
              <div className="scan-inline-alert" role="alert">
                <strong>Selected scan unavailable</strong>
                <p>{getErrorMessage(selectedScanQuery.error)}</p>
              </div>
            ) : selectedScan ? (
              <>
                <div className="scan-detail-header">
                  <strong>{selectedScan.repoFullName}</strong>
                  <span className={`scan-status-pill is-${selectedScan.status.toLowerCase()}`}>
                    {formatStatus(selectedScan.status)}
                  </span>
                </div>

                <dl className="scan-detail-grid">
                  <div>
                    <dt>Branch</dt>
                    <dd>{selectedScan.branch}</dd>
                  </div>
                  <div>
                    <dt>Commit</dt>
                    <dd>{selectedScan.commitSha ?? "Pending SHA"}</dd>
                  </div>
                  <div>
                    <dt>Files</dt>
                    <dd>{totals?.files}</dd>
                  </div>
                  <div>
                    <dt>Lines</dt>
                    <dd>{totals?.lines}</dd>
                  </div>
                </dl>

                <div className="scan-summary-band">
                  <div>
                    <span>Total findings</span>
                    <strong>{totals?.findings ?? 0}</strong>
                  </div>
                  <div>
                    <span>Language</span>
                    <strong>{selectedScan.language}</strong>
                  </div>
                </div>

                <div className="scan-severity-matrix">
                  {Object.entries(selectedScan.summary).map(([severity, count]) => (
                    <div key={severity}>
                      <span>{capitalize(severity)}</span>
                      <strong>{count}</strong>
                    </div>
                  ))}
                </div>

                {selectedScan.errorMessage ? (
                  <div className="scan-inline-alert" role="alert">
                    <strong>Scan error</strong>
                    <p>{selectedScan.errorMessage}</p>
                  </div>
                ) : null}
              </>
            ) : (
              <p className="scan-state-copy">Choose a repository or queue a scan to inspect status.</p>
            )}
          </section>

          <section className="scan-aside-card scan-trust-card">
            <p className="eyebrow">Privacy protocol</p>
            <h3>Repository access remains controlled throughout the queue</h3>
            <ul className="scan-trust-list">
              <li>Read-only repository access is used for branch collection.</li>
              <li>Java-first analysis remains scoped to the selected branch snapshot.</li>
              <li>Queued scans surface status and severity without exposing source content in the UI.</li>
            </ul>
          </section>
        </aside>
      </div>
    </section>
  );
}

function formatStatus(status: string) {
  return status.charAt(0) + status.slice(1).toLowerCase();
}

function capitalize(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
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
