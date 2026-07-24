import { Test } from '@nestjs/testing';

import {
  AnalysisApiModule,
  isMockAnalysisFixtureEnabled
} from '../../../src/client/analysis/analysis-api.module';
import { ANALYSIS_API_CLIENT } from '../../../src/client/analysis/analysis-api-client.interface';
import { MockAnalysisApiClient } from '../../../src/client/analysis/mock-analysis-api.client';

describe('AnalysisApiModule', () => {
  it('binds the analysis client token to MockAnalysisApiClient only in tests', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AnalysisApiModule]
    }).compile();

    expect(moduleRef.get(ANALYSIS_API_CLIENT)).toBeInstanceOf(MockAnalysisApiClient);
  });

  it('rejects mock routing outside the test environment', () => {
    expect(
      isMockAnalysisFixtureEnabled({
        NODE_ENV: 'production',
        ANALYSIS_CLIENT_MODE: 'mock'
      })
    ).toBe(false);
    expect(
      isMockAnalysisFixtureEnabled({
        NODE_ENV: 'development',
        ANALYSIS_CLIENT_MODE: 'mock'
      })
    ).toBe(false);
    expect(
      isMockAnalysisFixtureEnabled({
        NODE_ENV: 'test',
        ANALYSIS_CLIENT_MODE: 'mock'
      })
    ).toBe(true);
  });
});
