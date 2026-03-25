import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Inject, Injectable } from '@nestjs/common';
import type { Provider } from '@aegisai/shared';
import { Prisma, ScanStatus } from '@prisma/client';
import type { Job } from 'bullmq';

import { ANALYSIS_API_CLIENT } from '../client/analysis/analysis-api-client.interface';
import type {
  IAnalysisApiClient,
  VulnerabilityItem
} from '../client/analysis/analysis-api-client.interface';
import { parseAnalysisResultDto } from '../client/analysis/analysis-api.dto';
import { PrismaService } from '../prisma/prisma.service';
import { TokenCryptoUtil } from '../auth/utils/token-crypto.util';
import { SCAN_QUEUE } from './scan.constants';
import { CodeCollectorService } from './services/code-collector.service';

interface ScanJobData {
  scanId: string;
}

@Injectable()
@Processor(SCAN_QUEUE)
export class ScanProcessor extends WorkerHost {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenCrypto: TokenCryptoUtil,
    private readonly codeCollector: CodeCollectorService,
    @Inject(ANALYSIS_API_CLIENT) private readonly analysisClient: IAnalysisApiClient
  ) {
    super();
  }

  async process(job: Job<ScanJobData>): Promise<void> {
    const scan = await this.prisma.scan.findUnique({
      where: { id: job.data.scanId },
      include: { connectedRepo: true }
    });

    if (!scan) {
      throw new Error(`Scan not found: ${job.data.scanId}`);
    }

    await this.prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: ScanStatus.RUNNING,
        startedAt: new Date(),
        errorMessage: null
      }
    });

    try {
      const persistedToken = await this.prisma.oAuthToken.findFirst({
        where: {
          userId: scan.connectedRepo.userId,
          provider: scan.connectedRepo.provider
        }
      });

      if (!persistedToken) {
        throw new Error('Provider access token not found for scan execution');
      }

      const accessToken = this.tokenCrypto.decrypt(persistedToken.accessToken);
      const collection = await this.codeCollector.collect({
        provider: scan.connectedRepo.provider.toLowerCase() as Provider,
        fullName: scan.connectedRepo.fullName,
        branch: scan.branch,
        commitSha: scan.commitSha,
        accessToken,
        language: scan.language,
        scanId: scan.id
      });
      const analysisResult = parseAnalysisResultDto(
        await this.analysisClient.analyze(collection.analysisRequest)
      );

      if (!analysisResult.success) {
        throw new Error(analysisResult.errorMessage ?? 'Analysis failed');
      }

      await this.prisma.vulnerability.deleteMany({
        where: { scanId: scan.id }
      });

      if (analysisResult.vulnerabilities.length > 0) {
        await this.prisma.vulnerability.createMany({
          data: analysisResult.vulnerabilities.map((vulnerability) =>
            this.mapVulnerability(scan.id, vulnerability)
          )
        });
      }

      const severityCounts = createSeverityCounts(analysisResult.vulnerabilities);

      await this.prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: ScanStatus.DONE,
          commitSha: collection.commitSha,
          totalFiles: analysisResult.totalFiles,
          totalLines: analysisResult.totalLines,
          vulnCritical: severityCounts.CRITICAL,
          vulnHigh: severityCounts.HIGH,
          vulnMedium: severityCounts.MEDIUM,
          vulnLow: severityCounts.LOW,
          vulnInfo: severityCounts.INFO,
          errorMessage: null,
          completedAt: new Date()
        }
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown scan processing error';

      await this.prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: ScanStatus.FAILED,
          errorMessage: message,
          completedAt: new Date()
        }
      });

      throw error;
    }
  }

  private mapVulnerability(scanId: string, vulnerability: VulnerabilityItem) {
    return {
      scanId,
      title: vulnerability.title,
      description: vulnerability.description,
      severity: vulnerability.severity,
      filePath: vulnerability.filePath,
      lineStart: vulnerability.lineStart,
      lineEnd: vulnerability.lineEnd ?? null,
      codeSnippet: vulnerability.codeSnippet ?? null,
      fixSuggestion: vulnerability.fixSuggestion ?? null,
      fixExplanation: vulnerability.fixExplanation ?? null,
      cweId: vulnerability.cweId ?? null,
      cveId: vulnerability.cveId ?? null,
      owaspCategory: vulnerability.owaspCategory ?? null,
      referenceLinks:
        vulnerability.referenceLinks === undefined
          ? Prisma.JsonNull
          : (vulnerability.referenceLinks as unknown as Prisma.InputJsonValue),
      consensusScore: vulnerability.consensusScore,
      modelResults: vulnerability.modelResults as unknown as Prisma.InputJsonValue
    };
  }
}

function createSeverityCounts(vulnerabilities: VulnerabilityItem[]) {
  return vulnerabilities.reduce(
    (counts, vulnerability) => {
      counts[vulnerability.severity] += 1;
      return counts;
    },
    {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    }
  );
}
