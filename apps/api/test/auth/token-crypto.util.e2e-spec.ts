import { TokenCryptoUtil } from '../../src/auth/utils/token-crypto.util';

describe('TokenCryptoUtil', () => {
  const validKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  it('encrypts and decrypts provider tokens', () => {
    const service = new TokenCryptoUtil({
      get: (key: string) => {
        if (key === 'TOKEN_ENCRYPTION_KEY') {
          return validKey;
        }

        throw new Error(`Unexpected key: ${key}`);
      }
    } as never);

    const encrypted = service.encrypt('provider-access-token');

    expect(encrypted).not.toBe('provider-access-token');
    expect(service.decrypt(encrypted)).toBe('provider-access-token');
  });

  it('rejects invalid encryption keys', () => {
    expect(() => new TokenCryptoUtil({
      get: () => 'too-short'
    } as never)).toThrow('TOKEN_ENCRYPTION_KEY must be a 64-character hex string');
  });
});
