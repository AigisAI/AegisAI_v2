import type { Provider } from "@aegisai/shared";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import {
  connectRepo,
  disconnectRepo,
  listAvailableRepos,
  listConnectedRepos,
  listRepoBranches,
} from "../api/repos";

const AVAILABLE_PAGE_SIZE = 30;
const BRANCH_PAGE_SIZE = 30;

const providerOptions: Array<{ value: Provider; label: string }> = [
  { value: "github", label: "GitHub" },
  { value: "gitlab", label: "GitLab" },
] as const;

export function ReposPage() {
  const queryClient = useQueryClient();
  const [activeProvider, setActiveProvider] = useState<Provider>("github");
  const [selectedRepoId, setSelectedRepoId] = useState<string | null>(null);

  const connectedReposQuery = useQuery({
    queryKey: ["repos", "connected"],
    queryFn: listConnectedRepos,
  });

  const availableReposQuery = useQuery({
    queryKey: ["repos", "available", activeProvider],
    queryFn: () =>
      listAvailableRepos({
        provider: activeProvider,
        page: 1,
        size: AVAILABLE_PAGE_SIZE,
      }),
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

  const branchInsightQuery = useQuery({
    queryKey: ["repos", "branches", selectedRepoId],
    queryFn: () =>
      listRepoBranches(selectedRepoId!, {
        page: 1,
        size: BRANCH_PAGE_SIZE,
      }),
    enabled: Boolean(selectedRepoId),
  });

  const connectMutation = useMutation({
    mutationFn: connectRepo,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: ["repos", "connected"],
        }),
        queryClient.invalidateQueries({
          queryKey: ["repos", "available"],
        }),
      ]);
    },
  });

  const disconnectMutation = useMutation({
    mutationFn: disconnectRepo,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: ["repos", "connected"],
        }),
        queryClient.invalidateQueries({
          queryKey: ["repos", "available"],
        }),
      ]);
    },
  });

  const queryErrorMessage =
    getErrorMessage(connectedReposQuery.error) ??
    getErrorMessage(availableReposQuery.error) ??
    getErrorMessage(branchInsightQuery.error);
  const mutationErrorMessage =
    getErrorMessage(connectMutation.error) ??
    getErrorMessage(disconnectMutation.error);
  const pageErrorMessage = queryErrorMessage ?? mutationErrorMessage;

  return (
    <section className="repos-page">
      <header className="repos-hero">
        <div className="repos-hero-copy">
          <p className="eyebrow">Connection hub</p>
          <h2>Begin the Archive</h2>
          <div className="repos-hero-accent">
            <p>
              AegisAI uses read-only repository access for high-fidelity Java scans. Your code
              stays in your perimeter while we orchestrate security context around it.
            </p>
          </div>
        </div>

        <div className="repos-hero-panel" aria-hidden="true">
          <span className="repos-hero-panel-kicker">Protocol secured</span>
        </div>
      </header>

      <div className="repos-toolbar">
        <div className="repos-provider-filter" role="toolbar" aria-label="Repository provider">
          {providerOptions.map((option) => (
            <button
              key={option.value}
              className={`repos-filter-button${
                activeProvider === option.value ? " is-active" : ""
              }`}
              onClick={() => setActiveProvider(option.value)}
              type="button"
            >
              {option.label}
            </button>
          ))}
        </div>

        <p className="repos-toolbar-copy">
          Filter available sources without leaving the connected repository registry.
        </p>
      </div>

      {pageErrorMessage ? (
        <div className="repos-alert" role="alert">
          <strong>Repository access unavailable</strong>
          <p>{pageErrorMessage}</p>
        </div>
      ) : null}

      <div className="repos-layout">
        <div className="repos-main">
          <section
            className="repos-section"
            aria-label="Connected repositories"
          >
            <div className="repos-section-heading">
              <p className="eyebrow">Connected repositories</p>
              <h3>Protected sources already in scope</h3>
            </div>

            {connectedReposQuery.isLoading ? (
              <p className="repos-state-copy">Loading connected repositories...</p>
            ) : connectedReposQuery.data?.length ? (
              <div className="repos-list">
                {connectedReposQuery.data.map((repo) => (
                  <article
                    key={repo.id}
                    className={`repos-record${
                      selectedRepoId === repo.id ? " is-selected" : ""
                    }`}
                  >
                    <button
                      className="repos-record-body"
                      onClick={() => setSelectedRepoId(repo.id)}
                      type="button"
                    >
                      <div className="repos-record-header">
                        <span className="repos-provider-badge">
                          {repo.provider}
                        </span>
                        <span className="repos-privacy-badge">
                          {repo.isPrivate ? "Private" : "Public"}
                        </span>
                      </div>

                      <div className="repos-record-copy">
                        <h4>{repo.fullName}</h4>
                        <p>Default branch: {repo.defaultBranch}</p>
                      </div>

                      <dl className="repos-record-meta">
                        <div>
                          <dt>Last scan</dt>
                          <dd>{formatScanStatus(repo.lastScanStatus)}</dd>
                        </div>
                        <div>
                          <dt>Last activity</dt>
                          <dd>{formatTimestamp(repo.lastScanAt)}</dd>
                        </div>
                      </dl>
                    </button>

                    <button
                      className="repos-secondary-action"
                      disabled={disconnectMutation.isPending}
                      onClick={() => disconnectMutation.mutate(repo.id)}
                      type="button"
                      aria-label={`Disconnect ${repo.fullName}`}
                    >
                      Disconnect
                    </button>
                  </article>
                ))}
              </div>
            ) : (
              <p className="repos-state-copy">No repositories connected yet.</p>
            )}
          </section>

          <section
            className="repos-section"
            aria-label="Available repositories"
          >
            <div className="repos-section-heading">
              <p className="eyebrow">Available repositories</p>
              <h3>Bring new sources into the scanning archive</h3>
            </div>

            {availableReposQuery.isLoading ? (
              <p className="repos-state-copy">Loading available repositories...</p>
            ) : availableReposQuery.data?.items.length ? (
              <div className="repos-list">
                {availableReposQuery.data.items.map((repo) => (
                  <article key={repo.providerRepoId} className="repos-record">
                    <div className="repos-record-header">
                      <span className="repos-provider-badge">{activeProvider}</span>
                      <span className="repos-privacy-badge">
                        {repo.isPrivate ? "Private" : "Public"}
                      </span>
                    </div>

                    <div className="repos-record-copy">
                      <h4>{repo.fullName}</h4>
                      <p>Default branch: {repo.defaultBranch}</p>
                    </div>

                    <div className="repos-available-actions">
                      {repo.alreadyConnected ? (
                        <span className="repos-connected-chip">
                          Already connected
                        </span>
                      ) : (
                        <button
                          className="repos-primary-action"
                          disabled={connectMutation.isPending}
                          onClick={() =>
                            connectMutation.mutate({
                              provider: activeProvider,
                              providerRepoId: repo.providerRepoId,
                            })
                          }
                          type="button"
                          aria-label={`Connect ${repo.fullName}`}
                        >
                          Connect
                        </button>
                      )}
                    </div>
                  </article>
                ))}
              </div>
            ) : (
              <p className="repos-state-copy">No repositories ready for connection.</p>
            )}
          </section>
        </div>

        <aside className="repos-aside">
          <section className="repos-aside-card">
            <p className="eyebrow">Branch insight</p>
            <h3>Inspect the branch surface before scanning</h3>

            {selectedRepo ? (
              <>
                <p className="repos-aside-copy">
                  {selectedRepo.fullName} exposes the following branch archive for scan routing.
                </p>

                {branchInsightQuery.isLoading ? (
                  <p className="repos-state-copy">Loading branch insight...</p>
                ) : branchInsightQuery.data?.items.length ? (
                  <ul className="repos-branch-list">
                    {branchInsightQuery.data.items.map((branch) => (
                      <li key={branch.name}>
                        <div>
                          <strong>{branch.name}</strong>
                          <span>
                            {branch.isDefault ? "Default branch" : "Branch"}
                          </span>
                        </div>
                        <code>{branch.lastCommitSha ?? "No commit SHA"}</code>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="repos-state-copy">No branch metadata available yet.</p>
                )}
              </>
            ) : (
              <p className="repos-aside-copy">
                Connect a repository to inspect branches.
              </p>
            )}
          </section>

          <section className="repos-aside-card">
            <p className="eyebrow">Privacy protocol</p>
            <h3>Read-only access, zero archive drift</h3>
            <ul className="repos-protocol-list">
              <li>Read-only provider access</li>
              <li>SOC2 Type II aligned scan environment</li>
              <li>No permanent source retention</li>
            </ul>
          </section>
        </aside>
      </div>
    </section>
  );
}

function formatScanStatus(status: string | null): string {
  if (!status) {
    return "No scan recorded";
  }

  return status.toLowerCase().replace(/_/g, " ");
}

function formatTimestamp(timestamp: string | null): string {
  if (!timestamp) {
    return "Awaiting first scan";
  }

  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(timestamp));
}

function getErrorMessage(error: unknown): string | null {
  if (!error) {
    return null;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "We could not synchronize repository access right now.";
}
