import type {
  ConnectedRepoItem,
  DashboardData,
  ScanSeveritySummary,
  ScanSummary,
  TrendItem,
} from "@aegisai/shared";

import { listConnectedRepos } from "./repos";
import { listRepoScans } from "./scans";

const RECENT_SCANS_PER_REPO = 4;
const DASHBOARD_RECENT_LIMIT = 8;
const TREND_DAY_LIMIT = 4;

const EMPTY_SUMMARY: ScanSeveritySummary = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
};

export interface DashboardWorkspaceData extends DashboardData {
  connectedRepos: ConnectedRepoItem[];
  completedScans: ScanSummary[];
  severitySummary: ScanSeveritySummary;
  degraded: boolean;
}

export async function getDashboardWorkspaceData(): Promise<DashboardWorkspaceData> {
  const connectedRepos = await listConnectedRepos();

  if (!connectedRepos.length) {
    return {
      connectedRepos: [],
      completedScans: [],
      degraded: false,
      openVulnerabilities: EMPTY_SUMMARY,
      recentScans: [],
      severitySummary: EMPTY_SUMMARY,
      totalRepos: 0,
      totalScans: 0,
      trend: [],
    };
  }

  const scanPages = await Promise.allSettled(
    connectedRepos.map((repo) => listRepoScans(repo.id, 1, RECENT_SCANS_PER_REPO))
  );

  const successfulPages = scanPages
    .filter(isFulfilled)
    .map((result) => result.value);

  if (!successfulPages.length) {
    const firstFailure = scanPages.find((result) => result.status === "rejected");
    throw firstFailure?.reason ?? new Error("Dashboard data unavailable.");
  }

  const recentScans = successfulPages
    .flatMap((page) => page.items)
    .sort((left, right) => toTimestamp(right) - toTimestamp(left))
    .slice(0, DASHBOARD_RECENT_LIMIT);

  const completedScans = recentScans.filter((scan) => scan.status === "DONE");
  const severitySummary = aggregateSeverity(recentScans);

  return {
    connectedRepos,
    completedScans,
    degraded: successfulPages.length !== scanPages.length,
    openVulnerabilities: severitySummary,
    recentScans,
    severitySummary,
    totalRepos: connectedRepos.length,
    totalScans: successfulPages.reduce((total, page) => total + page.totalCount, 0),
    trend: buildTrend(completedScans),
  };
}

function aggregateSeverity(scans: ScanSummary[]): ScanSeveritySummary {
  return scans.reduce<ScanSeveritySummary>(
    (summary, scan) => ({
      critical: summary.critical + scan.summary.critical,
      high: summary.high + scan.summary.high,
      medium: summary.medium + scan.summary.medium,
      low: summary.low + scan.summary.low,
      info: summary.info + scan.summary.info,
    }),
    { ...EMPTY_SUMMARY }
  );
}

function buildTrend(scans: ScanSummary[]): TrendItem[] {
  const grouped = new Map<string, TrendItem>();

  scans.forEach((scan) => {
    const key = toDateKey(scan);
    const existing = grouped.get(key);

    if (existing) {
      existing.critical += scan.summary.critical;
      existing.high += scan.summary.high;
      existing.medium += scan.summary.medium;
      return;
    }

    grouped.set(key, {
      date: formatTrendDate(key),
      critical: scan.summary.critical,
      high: scan.summary.high,
      medium: scan.summary.medium,
    });
  });

  return [...grouped.entries()]
    .sort((left, right) => right[0].localeCompare(left[0]))
    .slice(0, TREND_DAY_LIMIT)
    .reverse()
    .map(([, item]) => item);
}

function toTimestamp(scan: ScanSummary) {
  return new Date(scan.completedAt ?? scan.startedAt ?? scan.createdAt).getTime();
}

function toDateKey(scan: ScanSummary) {
  return (scan.completedAt ?? scan.startedAt ?? scan.createdAt).slice(0, 10);
}

function formatTrendDate(key: string) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  }).format(new Date(`${key}T00:00:00.000Z`));
}

function isFulfilled<T>(
  result: PromiseSettledResult<T>
): result is PromiseFulfilledResult<T> {
  return result.status === "fulfilled";
}
