import type {
  DashboardWorkspaceData,
  ScanSeveritySummary,
  ScanSummary,
  TrendItem
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { RepoProvider, ScanStatus } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';

const RECENT_SCAN_LIMIT = 8;
const TREND_SCAN_LIMIT = 32;
const TREND_DAY_LIMIT = 4;

const EMPTY_SUMMARY: ScanSeveritySummary = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0
};

@Injectable()
export class DashboardService {
  constructor(private readonly prisma: PrismaService) {}

  async getDashboardWorkspaceData(userId: string): Promise<DashboardWorkspaceData> {
    const connectedRepos = await this.prisma.connectedRepo.findMany({
      where: {
        userId
      },
      include: {
        scans: {
          orderBy: {
            createdAt: 'desc'
          },
          take: 1,
          select: {
            createdAt: true,
            status: true
          }
        }
      },
      orderBy: {
        connectedAt: 'desc'
      }
    });

    if (!connectedRepos.length) {
      return this.createEmptyDashboard();
    }

    const [totalScans, recentScanRows, trendScanRows] = await Promise.all([
      this.prisma.scan.count({
        where: {
          connectedRepo: {
            userId
          }
        }
      }),
      this.prisma.scan.findMany({
        where: {
          connectedRepo: {
            userId
          }
        },
        include: {
          connectedRepo: {
            select: {
              fullName: true
            }
          }
        },
        orderBy: {
          createdAt: 'desc'
        },
        take: RECENT_SCAN_LIMIT
      }),
      this.prisma.scan.findMany({
        where: {
          connectedRepo: {
            userId
          },
          status: ScanStatus.DONE
        },
        include: {
          connectedRepo: {
            select: {
              fullName: true
            }
          }
        },
        orderBy: [{ completedAt: 'desc' }, { createdAt: 'desc' }],
        take: TREND_SCAN_LIMIT
      })
    ]);

    const recentScans = recentScanRows.map((scan) => this.toScanSummary(scan));
    const completedScans = recentScans.filter((scan) => scan.status === 'DONE');
    const severitySummary = this.aggregateSeverity(recentScans);

    return {
      totalRepos: connectedRepos.length,
      totalScans,
      openVulnerabilities: severitySummary,
      recentScans,
      trend: this.buildTrend(trendScanRows.map((scan) => this.toScanSummary(scan))),
      connectedRepos: connectedRepos.map((connectedRepo) => {
        const [latestScan] = connectedRepo.scans;

        return {
          id: connectedRepo.id,
          provider: this.fromRepoProvider(connectedRepo.provider),
          fullName: connectedRepo.fullName,
          cloneUrl: connectedRepo.cloneUrl,
          defaultBranch: connectedRepo.defaultBranch,
          isPrivate: connectedRepo.isPrivate,
          lastScanAt: latestScan?.createdAt.toISOString() ?? null,
          lastScanStatus: latestScan?.status ?? null
        };
      }),
      completedScans,
      severitySummary,
      degraded: false
    };
  }

  private createEmptyDashboard(): DashboardWorkspaceData {
    return {
      totalRepos: 0,
      totalScans: 0,
      openVulnerabilities: { ...EMPTY_SUMMARY },
      recentScans: [],
      trend: [],
      connectedRepos: [],
      completedScans: [],
      severitySummary: { ...EMPTY_SUMMARY },
      degraded: false
    };
  }

  private aggregateSeverity(scans: ScanSummary[]): ScanSeveritySummary {
    return scans.reduce<ScanSeveritySummary>(
      (summary, scan) => ({
        critical: summary.critical + scan.summary.critical,
        high: summary.high + scan.summary.high,
        medium: summary.medium + scan.summary.medium,
        low: summary.low + scan.summary.low,
        info: summary.info + scan.summary.info
      }),
      { ...EMPTY_SUMMARY }
    );
  }

  private buildTrend(scans: ScanSummary[]): TrendItem[] {
    const grouped = new Map<string, TrendItem>();

    scans.forEach((scan) => {
      const key = this.toDateKey(scan);
      const existing = grouped.get(key);

      if (existing) {
        existing.critical += scan.summary.critical;
        existing.high += scan.summary.high;
        existing.medium += scan.summary.medium;
        return;
      }

      grouped.set(key, {
        date: this.formatTrendDate(key),
        critical: scan.summary.critical,
        high: scan.summary.high,
        medium: scan.summary.medium
      });
    });

    return [...grouped.entries()]
      .sort((left, right) => left[0].localeCompare(right[0]))
      .slice(-TREND_DAY_LIMIT)
      .map(([, item]) => item);
  }

  private toDateKey(scan: ScanSummary): string {
    return (scan.completedAt ?? scan.startedAt ?? scan.createdAt).slice(0, 10);
  }

  private formatTrendDate(key: string): string {
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      timeZone: 'UTC'
    }).format(new Date(`${key}T00:00:00.000Z`));
  }

  private fromRepoProvider(provider: RepoProvider): 'github' | 'gitlab' {
    return provider.toLowerCase() as 'github' | 'gitlab';
  }

  private toScanSummary(scan: {
    id: string;
    branch: string;
    commitSha: string | null;
    status: ScanStatus;
    language: string;
    totalFiles: number | null;
    totalLines: number | null;
    vulnCritical: number;
    vulnHigh: number;
    vulnMedium: number;
    vulnLow: number;
    vulnInfo: number;
    errorMessage: string | null;
    startedAt: Date | null;
    completedAt: Date | null;
    createdAt: Date;
    connectedRepo: {
      fullName: string;
    };
  }): ScanSummary {
    return {
      id: scan.id,
      repoFullName: scan.connectedRepo.fullName,
      branch: scan.branch,
      commitSha: scan.commitSha,
      status: scan.status,
      language: scan.language,
      totalFiles: scan.totalFiles,
      totalLines: scan.totalLines,
      summary: {
        critical: scan.vulnCritical,
        high: scan.vulnHigh,
        medium: scan.vulnMedium,
        low: scan.vulnLow,
        info: scan.vulnInfo
      },
      startedAt: scan.startedAt?.toISOString() ?? null,
      completedAt: scan.completedAt?.toISOString() ?? null,
      errorMessage: scan.errorMessage,
      createdAt: scan.createdAt.toISOString()
    };
  }
}
