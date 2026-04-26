import type { ConnectedRepoItem } from './repo';
import type { ScanSummary, ScanSeveritySummary } from './scan';

export interface TrendItem {
  date: string;
  critical: number;
  high: number;
  medium: number;
}

export interface DashboardData {
  totalRepos: number;
  totalScans: number;
  openVulnerabilities: ScanSeveritySummary;
  recentScans: ScanSummary[];
  trend: TrendItem[];
}

export interface DashboardWorkspaceData extends DashboardData {
  connectedRepos: ConnectedRepoItem[];
  completedScans: ScanSummary[];
  severitySummary: ScanSeveritySummary;
  degraded: boolean;
}
