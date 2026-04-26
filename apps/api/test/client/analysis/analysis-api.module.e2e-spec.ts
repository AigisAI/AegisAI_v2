import { Test } from '@nestjs/testing';

import { AnalysisApiModule } from '../../../src/client/analysis/analysis-api.module';
import { ANALYSIS_API_CLIENT } from '../../../src/client/analysis/analysis-api-client.interface';
import { MockAnalysisApiClient } from '../../../src/client/analysis/mock-analysis-api.client';

describe('AnalysisApiModule', () => {
  it('binds the analysis client token to MockAnalysisApiClient by default', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AnalysisApiModule]
    }).compile();

    expect(moduleRef.get(ANALYSIS_API_CLIENT)).toBeInstanceOf(MockAnalysisApiClient);
  });
});
