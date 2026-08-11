import { createHash } from 'node:crypto';

import {
  buildSastAiAdvisoryPolicyReference,
  isSastAiAdvisoryAuthorityProofIntentShapeValid,
  isSastAiAdvisoryPolicyReferenceShapeValid,
  type SastAiAdvisoryAuthorityProofIntent,
  type SastAiAdvisoryPolicyReference
} from '@aegisai/shared';
import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException
} from '@nestjs/common';

import { SastAiAdvisoryAuthorityStore } from './sast-ai-advisory-authority.store';

type AuthorityClock = () => string;

@Injectable()
export class AiAdvisoryAuthorityService {
  private readonly logger = new Logger(
    AiAdvisoryAuthorityService.name
  );

  constructor(private readonly store: SastAiAdvisoryAuthorityStore) {}

  async createProof(
    input: SastAiAdvisoryAuthorityProofIntent,
    clock: AuthorityClock = () => new Date().toISOString()
  ) {
    if (!isSastAiAdvisoryAuthorityProofIntentShapeValid(input)) {
      throw new BadRequestException(
        'AI authority proof intent must contain only tenant and advisory identifiers.'
      );
    }
    const verifiedAt = readClock(clock);
    if (!verifiedAt) throw unavailable();

    try {
      const persisted = await this.store.createProof({
        tenantId: input.tenantId,
        advisoryId: input.advisoryId,
        verifiedAt
      });
      const policyReference = buildSastAiAdvisoryPolicyReference(
        persisted.proof,
        digest
      );
      if (!policyReference) throw new Error('invalid proof reference');
      return { ...persisted, policyReference };
    } catch (error) {
      this.logger.error(
        `AI advisory authority proof failed (${safeErrorCategory(error)}).`
      );
      throw unavailable();
    }
  }

  async verifyPolicyReference(input: {
    tenantId: string;
    normalizedFindingId: string;
    reference: Readonly<SastAiAdvisoryPolicyReference>;
  }): Promise<boolean> {
    if (
      !isBoundedReference(input.tenantId) ||
      !isBoundedReference(input.normalizedFindingId) ||
      !isSastAiAdvisoryPolicyReferenceShapeValid(input.reference)
    ) {
      return false;
    }
    try {
      return await this.store.verifyPolicyReference(input);
    } catch {
      return false;
    }
  }
}

function readClock(clock: AuthorityClock): string | null {
  try {
    const value = clock();
    return typeof value === 'string' &&
      Number.isFinite(Date.parse(value)) &&
      new Date(value).toISOString() === value
      ? value
      : null;
  } catch {
    return null;
  }
}

function isBoundedReference(value: unknown): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.trim() === value &&
    new TextEncoder().encode(value).length <= 512;
}

function safeErrorCategory(error: unknown): string {
  if (!(error instanceof Error)) return 'UnknownError';
  return [
    'Error',
    'TypeError',
    'SastAiAdvisoryAuthorityPersistenceError',
    'PrismaClientKnownRequestError',
    'PrismaClientUnknownRequestError',
    'PrismaClientInitializationError'
  ].includes(error.name)
    ? error.name
    : 'UnknownError';
}

function unavailable(): NotFoundException {
  return new NotFoundException(
    'AI advisory authority proof source is unavailable.'
  );
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
