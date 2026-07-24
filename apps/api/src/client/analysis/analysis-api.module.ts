import { Module, type Provider } from '@nestjs/common';

import { isMockAnalysisFixtureEnabled } from './analysis-fixture.policy';
import {
  ANALYSIS_API_CLIENT,
  type IAnalysisApiClient
} from './analysis-api-client.interface';
import { DisabledAnalysisApiClient } from './disabled-analysis-api.client';
import { MockAnalysisApiClient } from './mock-analysis-api.client';

export { isMockAnalysisFixtureEnabled } from './analysis-fixture.policy';

const analysisApiClientProvider: Provider<IAnalysisApiClient> = {
  provide: ANALYSIS_API_CLIENT,
  useFactory: (): IAnalysisApiClient =>
    isMockAnalysisFixtureEnabled()
      ? new MockAnalysisApiClient()
      : new DisabledAnalysisApiClient()
};

@Module({
  providers: [analysisApiClientProvider],
  exports: [ANALYSIS_API_CLIENT]
})
export class AnalysisApiModule {}
