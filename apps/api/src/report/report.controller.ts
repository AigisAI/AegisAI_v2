import type { AuthUser } from '@aegisai/shared';
import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Res,
  StreamableFile,
  UseGuards
} from '@nestjs/common';
import type { Response } from 'express';

import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { SkipTransform } from '../common/decorators/skip-transform.decorator';
import { ReportService } from './report.service';

@Controller('reports')
@UseGuards(SessionAuthGuard)
export class ReportController {
  constructor(private readonly reportService: ReportService) {}

  @Post('scans/:scanId/pdf')
  @HttpCode(HttpStatus.ACCEPTED)
  async requestReport(@CurrentUser() user: AuthUser, @Param('scanId') scanId: string) {
    return this.reportService.requestReport({
      userId: user.id,
      scanId
    });
  }

  @Get(':reportId')
  async getReportDetail(@CurrentUser() user: AuthUser, @Param('reportId') reportId: string) {
    return this.reportService.getReportDetail(user.id, reportId);
  }

  @Get(':reportId/download')
  @SkipTransform()
  async downloadReport(
    @CurrentUser() user: AuthUser,
    @Param('reportId') reportId: string,
    @Res({ passthrough: true }) response: Response
  ) {
    const download = await this.reportService.getReportDownload(user.id, reportId);

    response.setHeader('Content-Type', download.mimeType);
    response.setHeader('Content-Disposition', `attachment; filename="${download.fileName}"`);

    return new StreamableFile(download.buffer);
  }
}
