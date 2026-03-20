import { Module } from '@nestjs/common';

import { ANALYSIS_API_CLIENT } from './analysis-api-client.interface';
import { MockAnalysisApiClient } from './mock-analysis-api.client';

@Module({
  providers: [
    MockAnalysisApiClient,
    {
      provide: ANALYSIS_API_CLIENT,
      useExisting: MockAnalysisApiClient
    }
  ],
  exports: [ANALYSIS_API_CLIENT]
})
export class AnalysisApiModule {}
