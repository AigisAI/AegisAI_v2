import { Injectable, ServiceUnavailableException } from "@nestjs/common";
import { createHash, randomBytes } from "node:crypto";
import type { TokenBrokerIssueRequest } from '@aegisai/shared';

import { ConfigService } from '../config/config.service';

export interface IssuedTokenCredential {
  credentialType: "SCM_REPOSITORY_ACCESS";
  issuedAt: string;
  expiresAt: string;
  credential: EphemeralTokenCredential;
}

export class EphemeralTokenCredential {
  private readonly bytes: Buffer;
  private wiped = false;

  constructor(value: string) {
    this.bytes = Buffer.from(value, 'utf8');
  }

  fingerprint(): `sha256:${string}` {
    this.assertAvailable();
    return `sha256:${createHash('sha256').update(this.bytes).digest('hex')}`;
  }

  revealForTransport(): string {
    this.assertAvailable();
    return this.bytes.toString('utf8');
  }

  async use<T>(consumer: (credential: Uint8Array) => Promise<T>): Promise<T> {
    this.assertAvailable();
    try {
      return await consumer(this.bytes);
    } finally {
      this.wipe();
    }
  }

  wipe(): void {
    if (!this.wiped) {
      this.bytes.fill(0);
      this.wiped = true;
    }
  }

  isWiped(): boolean {
    return this.wiped && this.bytes.every((value) => value === 0);
  }

  toJSON(): never {
    throw new Error('Ephemeral credentials are not serializable.');
  }

  private assertAvailable(): void {
    if (this.wiped) {
      throw new Error('Ephemeral credential has already been wiped.');
    }
  }
}

@Injectable()
export class TokenCredentialIssuerService {
  constructor(private readonly config: ConfigService) {}

  issue(input: TokenBrokerIssueRequest, issuedAt = new Date()): IssuedTokenCredential {
    if (this.config.isProduction()) {
      throw new ServiceUnavailableException(
        'Provider-backed repository credential minting is not active for production.'
      );
    }
    const expiresAt = new Date(issuedAt.getTime() + input.ttlSeconds * 1000);

    return {
      credentialType: "SCM_REPOSITORY_ACCESS",
      credential: new EphemeralTokenCredential(this.buildCredentialValue()),
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString()
    };
  }

  private buildCredentialValue(): string {
    return `aegis_tb_${randomBytes(32).toString("base64url")}`;
  }
}
