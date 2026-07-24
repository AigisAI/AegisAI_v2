import { Module } from '@nestjs/common';

import { isMockAnalysisFixtureEnabled } from './analysis-fixture.policy';
import { ANALYSIS_API_CLIENT } from './analysis-api-client.interface';
import { DisabledAnalysisApiClient } from './disabled-analysis-api.client';
import { MockAnalysisApiClient } from './mock-analysis-api.client';

export { isMockAnalysisFixtureEnabled } from './analysis-fixture.policy';

const analysisProviders = isMockAnalysisFixtureEnabled()
  ? [
      MockAnalysisApiClient,
      {
        provide: ANALYSIS_API_CLIENT,
        useExisting: MockAnalysisApiClient
      }
    ]
  : [
      DisabledAnalysisApiClient,
      {
        provide: ANALYSIS_API_CLIENT,
        useExisting: DisabledAnalysisApiClient
      }
    ];

@Module({
  providers: analysisProviders,
  exports: [ANALYSIS_API_CLIENT]
})
export class AnalysisApiModule {}
