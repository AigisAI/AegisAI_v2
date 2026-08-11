import type { AuthUser } from '@aegisai/shared';
import {
  Controller,
  Get,
  NotFoundException,
  Param,
  Query,
  UseGuards
} from '@nestjs/common';

import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { SastEvidenceAccessService } from '../scan-plane/sast-evidence-access.service';

@Controller('dashboard/evidence')
@UseGuards(SessionAuthGuard)
export class DashboardEvidenceController {
  constructor(
    private readonly evidenceAccess: SastEvidenceAccessService
  ) {}

  @Get(':evidencePackId')
  async getEvidence(
    @CurrentUser() user: AuthUser,
    @Param('evidencePackId') evidencePackId: string,
    @Query('repositoryBindingId') repositoryBindingId: string
  ) {
    const result = await this.evidenceAccess.readDashboard({
      tenantId: user.tenantId,
      repositoryBindingId,
      evidencePackId
    });
    if (result.outcome !== 'ALLOWED' || !result.dashboardEvidence) {
      throw new NotFoundException({
        message: 'Evidence is not available.',
        errorCode: 'EVIDENCE_NOT_AVAILABLE'
      });
    }
    return result.dashboardEvidence;
  }
}
