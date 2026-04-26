import type { AuthUser, ListRepoScansQuery, ScanRequestBody } from '@aegisai/shared';
import {
  BadRequestException,
  Body,
  Controller,
  DefaultValuePipe,
  Get,
  HttpCode,
  Param,
  ParseIntPipe,
  Post,
  Query,
  UseGuards
} from '@nestjs/common';

import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { ScanService } from './scan.service';

@Controller()
@UseGuards(SessionAuthGuard)
export class ScanController {
  constructor(private readonly scanService: ScanService) {}

  @Post('scans')
  @HttpCode(202)
  async requestScan(@CurrentUser() user: AuthUser, @Body() body: Partial<ScanRequestBody>) {
    const repoId = this.requireTrimmedString(body.repoId, 'repoId');
    const branch = this.requireTrimmedString(body.branch, 'branch');

    return this.scanService.createScan({
      userId: user.id,
      connectedRepoId: repoId,
      branch
    });
  }

  @Get('scans/:scanId')
  async getScanDetail(@CurrentUser() user: AuthUser, @Param('scanId') scanId: string) {
    return this.scanService.getScanDetail(user.id, scanId);
  }

  @Get('repos/:repoId/scans')
  async listRepoScans(
    @CurrentUser() user: AuthUser,
    @Param('repoId') repoId: string,
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
    @Query('size', new DefaultValuePipe(10), ParseIntPipe) size: number
  ) {
    return this.scanService.listRepoScans({
      userId: user.id,
      repoId,
      ...this.normalizePagination({ repoId, page, size })
    });
  }

  private normalizePagination(input: ListRepoScansQuery) {
    if (!input.page || input.page < 1) {
      throw new BadRequestException({
        message: 'page must be a positive integer.',
        errorCode: 'BAD_REQUEST'
      });
    }

    if (!input.size || input.size < 1) {
      throw new BadRequestException({
        message: 'size must be a positive integer.',
        errorCode: 'BAD_REQUEST'
      });
    }

    return {
      page: input.page,
      size: input.size
    };
  }

  private requireTrimmedString(value: unknown, fieldName: string): string {
    if (typeof value !== 'string' || !value.trim()) {
      throw new BadRequestException({
        message: `${fieldName} is required.`,
        errorCode: 'BAD_REQUEST'
      });
    }

    return value.trim();
  }
}
