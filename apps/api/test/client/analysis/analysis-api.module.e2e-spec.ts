import { Test } from '@nestjs/testing';

import {
  AnalysisApiModule,
  isMockAnalysisFixtureEnabled
} from '../../../src/client/analysis/analysis-api.module';
import { ANALYSIS_API_CLIENT } from '../../../src/client/analysis/analysis-api-client.interface';
import { DisabledAnalysisApiClient } from '../../../src/client/analysis/disabled-analysis-api.client';
import { MockAnalysisApiClient } from '../../../src/client/analysis/mock-analysis-api.client';

describe('AnalysisApiModule', () => {
  const previousNodeEnv = process.env.NODE_ENV;
  const previousMode = process.env.ANALYSIS_CLIENT_MODE;

  afterAll(() => {
    setEnvironment(previousNodeEnv, previousMode);
  });

  it('binds mock only for the explicit test/mock fixture mode', async () => {
    setEnvironment('test', 'mock');
    const moduleRef = await Test.createTestingModule({
      imports: [AnalysisApiModule]
    }).compile();

    expect(moduleRef.get(ANALYSIS_API_CLIENT)).toBeInstanceOf(
      MockAnalysisApiClient
    );
  });

  it.each([
    { nodeEnv: 'test', mode: 'internal' },
    { nodeEnv: 'production', mode: 'mock' },
    { nodeEnv: 'development', mode: 'mock' }
  ])(
    'binds the disabled client for $nodeEnv/$mode',
    async ({ nodeEnv, mode }) => {
      setEnvironment(nodeEnv, mode);
      const moduleRef = await Test.createTestingModule({
        imports: [AnalysisApiModule]
      }).compile();

      expect(moduleRef.get(ANALYSIS_API_CLIENT)).toBeInstanceOf(
        DisabledAnalysisApiClient
      );
    }
  );

  it('evaluates the complete fixture routing matrix independently of inherited environment', () => {
    expect(
      isMockAnalysisFixtureEnabled({
        NODE_ENV: 'test',
        ANALYSIS_CLIENT_MODE: 'internal'
      })
    ).toBe(false);
    expect(
      isMockAnalysisFixtureEnabled({
        NODE_ENV: 'test',
        ANALYSIS_CLIENT_MODE: 'mock'
      })
    ).toBe(true);
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
  });
});

function setEnvironment(
  nodeEnv: string | undefined,
  mode: string | undefined
): void {
  if (nodeEnv === undefined) {
    delete process.env.NODE_ENV;
  } else {
    process.env.NODE_ENV = nodeEnv;
  }
  if (mode === undefined) {
    delete process.env.ANALYSIS_CLIENT_MODE;
  } else {
    process.env.ANALYSIS_CLIENT_MODE = mode;
  }
}
