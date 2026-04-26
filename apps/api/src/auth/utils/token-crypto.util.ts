import { Injectable } from '@nestjs/common';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

import { ConfigService } from '../../config/config.service';

@Injectable()
export class TokenCryptoUtil {
  private readonly encryptionKey: Buffer;

  constructor(private readonly config: ConfigService) {
    const key = this.config.get('TOKEN_ENCRYPTION_KEY');

    if (!/^[a-f0-9]{64}$/i.test(key)) {
      throw new Error('TOKEN_ENCRYPTION_KEY must be a 64-character hex string');
    }

    this.encryptionKey = Buffer.from(key, 'hex');
  }

  encrypt(value: string): string {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  decrypt(payload: string): string {
    const [ivHex, authTagHex, encryptedHex] = payload.split(':');

    if (!ivHex || !authTagHex || !encryptedHex) {
      throw new Error('Encrypted token payload is malformed');
    }

    const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedHex, 'hex')),
      decipher.final()
    ]);

    return decrypted.toString('utf8');
  }
}
