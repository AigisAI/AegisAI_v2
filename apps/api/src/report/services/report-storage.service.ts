import { Injectable } from '@nestjs/common';
import { access, mkdir, rm, writeFile } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';

import { ConfigService } from '../../config/config.service';

interface WriteReportPdfInput {
  reportId: string;
  scanId: string;
  pdf: Buffer;
}

@Injectable()
export class ReportStorageService {
  constructor(private readonly config: ConfigService) {}

  async write(input: WriteReportPdfInput): Promise<string> {
    const storageDir = this.getStorageDir();
    const absoluteStorageDir = path.resolve(process.cwd(), storageDir);
    const fileName = `aegisai-scan-report-${input.scanId}-${input.reportId}.pdf`;
    const absolutePath = path.join(absoluteStorageDir, fileName);

    await mkdir(absoluteStorageDir, { recursive: true });
    await writeFile(absolutePath, input.pdf);

    return path.join(storageDir, fileName);
  }

  async exists(filePath: string): Promise<boolean> {
    try {
      await access(this.resolve(filePath), fsConstants.F_OK);
      return true;
    } catch {
      return false;
    }
  }

  async delete(filePath: string): Promise<void> {
    await rm(this.resolve(filePath), {
      force: true
    });
  }

  private getStorageDir(): string {
    return this.config.get('REPORT_STORAGE_PATH');
  }

  private resolve(filePath: string): string {
    return path.resolve(process.cwd(), filePath);
  }
}
