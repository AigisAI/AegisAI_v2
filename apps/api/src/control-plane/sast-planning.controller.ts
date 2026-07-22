import { Body, Controller, Param, Post, UseGuards } from '@nestjs/common';

import { InternalServiceGuard } from '../common/security/internal-service.guard';
import { PlanSastScanRequestDto } from './control-plane.dto';
import { SastScanPlannerService } from './sast-scan-planner.service';

@Controller('sast-planning')
@UseGuards(InternalServiceGuard)
export class SastPlanningController {
  constructor(private readonly planner: SastScanPlannerService) {}

  @Post(':scanRequestId')
  plan(
    @Param('scanRequestId') scanRequestId: string,
    @Body() body: PlanSastScanRequestDto
  ) {
    return this.planner.plan({
      ...body,
      scanRequestId
    });
  }
}
