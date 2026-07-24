import { createHmac, timingSafeEqual } from 'node:crypto';

import { Injectable } from '@nestjs/common';
import type { SastPreflightDecision } from '@aegisai/shared';

import { ConfigService } from '../config/config.service';

export interface RepositoryPreflightAttestationClaims {
  attemptId: string;
  fixedCommitSha: string;
  pathPolicyVersion: string;
  inventoryDigest: `sha256:${string}`;
  decision: SastPreflightDecision;
  issuedAt: string;
}

@Injectable()
export class RepositoryPreflightAttestationService {
  constructor(private readonly config: ConfigService) {}

  issue(
    claims: Omit<RepositoryPreflightAttestationClaims, 'issuedAt'>,
    now = new Date()
  ): string {
    const complete: RepositoryPreflightAttestationClaims = {
      ...claims,
      issuedAt: now.toISOString()
    };
    const payload = Buffer.from(this.canonical(complete), 'utf8').toString('base64url');
    return `attestation://sast-preflight/v1/${payload}.${this.sign(payload)}`;
  }

  verify(
    attestationRef: string,
    expected: Omit<RepositoryPreflightAttestationClaims, 'issuedAt'>
  ): boolean {
    const prefix = 'attestation://sast-preflight/v1/';
    if (
      typeof attestationRef !== 'string' ||
      attestationRef.length > 8192 ||
      !attestationRef.startsWith(prefix)
    ) {
      return false;
    }
    const encoded = attestationRef.slice(prefix.length);
    const separator = encoded.lastIndexOf('.');
    if (separator < 1) {
      return false;
    }
    const payload = encoded.slice(0, separator);
    const signature = encoded.slice(separator + 1);
    if (
      !/^[A-Za-z0-9_-]{43}$/.test(signature) ||
      !this.safeEqual(signature, this.sign(payload))
    ) {
      return false;
    }
    try {
      const claims = JSON.parse(
        Buffer.from(payload, 'base64url').toString('utf8')
      ) as RepositoryPreflightAttestationClaims;
      return (
        this.canonical(claims) === Buffer.from(payload, 'base64url').toString('utf8') &&
        Number.isFinite(Date.parse(claims.issuedAt)) &&
        claims.attemptId === expected.attemptId &&
        claims.fixedCommitSha === expected.fixedCommitSha &&
        claims.pathPolicyVersion === expected.pathPolicyVersion &&
        claims.inventoryDigest === expected.inventoryDigest &&
        claims.decision === expected.decision
      );
    } catch {
      return false;
    }
  }

  private canonical(claims: RepositoryPreflightAttestationClaims): string {
    return JSON.stringify({
      version: '1',
      attemptId: claims.attemptId,
      fixedCommitSha: claims.fixedCommitSha,
      pathPolicyVersion: claims.pathPolicyVersion,
      inventoryDigest: claims.inventoryDigest,
      decision: claims.decision,
      issuedAt: claims.issuedAt
    });
  }

  private sign(payload: string): string {
    const key = Buffer.from(this.config.get('PREFLIGHT_ATTESTATION_KEY'), 'hex');
    try {
      return createHmac('sha256', key).update(payload, 'utf8').digest('base64url');
    } finally {
      key.fill(0);
    }
  }

  private safeEqual(actual: string, expected: string): boolean {
    const actualBuffer = Buffer.from(actual);
    const expectedBuffer = Buffer.from(expected);
    return (
      actualBuffer.length === expectedBuffer.length &&
      timingSafeEqual(actualBuffer, expectedBuffer)
    );
  }
}
