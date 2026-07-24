import { ServiceUnavailableException } from '@nestjs/common';
import type { TokenBrokerIssueRequest } from '@aegisai/shared';

import type { ConfigService } from '../../src/config/config.service';
import { TokenCredentialIssuerService } from '../../src/token-broker/token-credential-issuer.service';

describe('TokenCredentialIssuerService', () => {
  it('fails closed in production until a provider-backed minting adapter is active', () => {
    const issuer = new TokenCredentialIssuerService({
      isProduction: () => true
    } as ConfigService);

    expect(() =>
      issuer.issue({ ttlSeconds: 60 } as TokenBrokerIssueRequest)
    ).toThrow(ServiceUnavailableException);
  });
});
