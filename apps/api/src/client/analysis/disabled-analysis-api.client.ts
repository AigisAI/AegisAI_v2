import { Injectable, ServiceUnavailableException } from '@nestjs/common';

import type { AnalysisResult, IAnalysisApiClient } from './analysis-api-client.interface';

@Injectable()
export class DisabledAnalysisApiClient implements IAnalysisApiClient {
  analyze(): Promise<AnalysisResult> {
    throw new ServiceUnavailableException({
      message:
        'Legacy analysis execution is disabled; use the attested Scan Plane runtime.',
      errorCode: 'LEGACY_ANALYSIS_DISABLED'
    });
  }
}
