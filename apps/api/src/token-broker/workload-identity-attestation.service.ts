import {
  createHmac,
  randomUUID,
  timingSafeEqual
} from 'node:crypto';

import {
  MAX_WORKLOAD_IDENTITY_ATTESTATION_TTL_SECONDS,
  WORKLOAD_IDENTITY_ATTESTATION_AUDIENCE,
  WORKLOAD_IDENTITY_ATTESTATION_VERSION,
  type WorkloadIdentityAttestation,
  type WorkloadIdentityAttestationClaims
} from '@aegisai/shared';
import { Injectable, UnauthorizedException } from '@nestjs/common';

import { ConfigService } from '../config/config.service';

const ATTESTATION_ISSUER = 'aegisai-sandbox-provisioner';
const MAX_CLOCK_SKEW_MS = 30_000;

export interface WorkloadIdentityScope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  workloadIdentityRef: string;
  commitSha: string;
}

@Injectable()
export class WorkloadIdentityAttestationService {
  constructor(private readonly config: ConfigService) {}

  issue(
    scope: WorkloadIdentityScope,
    options: { now?: Date; ttlSeconds?: number } = {}
  ): WorkloadIdentityAttestation {
    const now = options.now ?? new Date();
    const ttlSeconds = options.ttlSeconds ?? 120;
    if (
      !Number.isInteger(ttlSeconds) ||
      ttlSeconds < 1 ||
      ttlSeconds > MAX_WORKLOAD_IDENTITY_ATTESTATION_TTL_SECONDS
    ) {
      throw new Error('Workload identity attestation TTL is outside policy.');
    }

    const claims: WorkloadIdentityAttestationClaims = {
      version: WORKLOAD_IDENTITY_ATTESTATION_VERSION,
      issuer: ATTESTATION_ISSUER,
      audience: WORKLOAD_IDENTITY_ATTESTATION_AUDIENCE,
      ...scope,
      nonce: randomUUID(),
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlSeconds * 1000).toISOString()
    };

    return {
      claims,
      signature: this.sign(claims)
    };
  }

  verify(
    attestation: WorkloadIdentityAttestation,
    expected: WorkloadIdentityScope,
    now = new Date()
  ): void {
    const claims = attestation?.claims;
    if (!claims || !attestation.signature) {
      this.reject();
    }

    const issuedAt = this.parseCanonicalTimestamp(claims.issuedAt);
    const expiresAt = this.parseCanonicalTimestamp(claims.expiresAt);
    const lifetime = expiresAt - issuedAt;
    const expectedSignature = this.sign(claims);

    if (
      claims.version !== WORKLOAD_IDENTITY_ATTESTATION_VERSION ||
      claims.issuer !== ATTESTATION_ISSUER ||
      claims.audience !== WORKLOAD_IDENTITY_ATTESTATION_AUDIENCE ||
      !claims.nonce ||
      issuedAt > now.getTime() + MAX_CLOCK_SKEW_MS ||
      expiresAt <= now.getTime() ||
      lifetime < 1_000 ||
      lifetime > MAX_WORKLOAD_IDENTITY_ATTESTATION_TTL_SECONDS * 1000 ||
      claims.tenantId !== expected.tenantId ||
      claims.repositoryBindingId !== expected.repositoryBindingId ||
      claims.scanRequestId !== expected.scanRequestId ||
      claims.attemptId !== expected.attemptId ||
      claims.workloadIdentityRef !== expected.workloadIdentityRef ||
      claims.commitSha !== expected.commitSha ||
      !this.safeEqual(attestation.signature, expectedSignature)
    ) {
      this.reject();
    }
  }

  private sign(claims: WorkloadIdentityAttestationClaims): `sha256:${string}` {
    const key = Buffer.from(this.config.get('WORKLOAD_ATTESTATION_KEY'), 'hex');
    try {
      const digest = createHmac('sha256', key)
        .update(this.canonicalClaims(claims), 'utf8')
        .digest('hex');
      return `sha256:${digest}`;
    } finally {
      key.fill(0);
    }
  }

  private canonicalClaims(claims: WorkloadIdentityAttestationClaims): string {
    return JSON.stringify([
      claims.version,
      claims.issuer,
      claims.audience,
      claims.tenantId,
      claims.repositoryBindingId,
      claims.scanRequestId,
      claims.attemptId,
      claims.workloadIdentityRef,
      claims.commitSha,
      claims.nonce,
      claims.issuedAt,
      claims.expiresAt
    ]);
  }

  private parseCanonicalTimestamp(value: string): number {
    const timestamp = Date.parse(value);
    if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
      this.reject();
    }
    return timestamp;
  }

  private safeEqual(actual: string, expected: string): boolean {
    if (!/^sha256:[0-9a-f]{64}$/.test(actual)) {
      return false;
    }
    const actualBuffer = Buffer.from(actual);
    const expectedBuffer = Buffer.from(expected);
    return (
      actualBuffer.length === expectedBuffer.length &&
      timingSafeEqual(actualBuffer, expectedBuffer)
    );
  }

  private reject(): never {
    throw new UnauthorizedException(
      'Workload identity attestation is invalid, expired, or outside the requested attempt scope.'
    );
  }
}
