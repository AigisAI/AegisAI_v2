import { Body, Controller, Post, UseGuards } from '@nestjs/common';

import { InternalServiceGuard } from '../common/security/internal-service.guard';
import { RunMockScanPlaneDto } from './scan-plane.dto';
import { ScanPlaneService } from './scan-plane.service';

@Controller('scan-plane')
export class ScanPlaneMockController {
  constructor(private readonly scanPlaneService: ScanPlaneService) {}

  @Post('mock-runs')
  @UseGuards(InternalServiceGuard)
  runMockPipeline(@Body() body: RunMockScanPlaneDto) {
    return this.scanPlaneService.runMockPipeline(body);
  }
}
