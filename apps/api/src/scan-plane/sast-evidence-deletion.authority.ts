import type {
  SastEvidenceAccessScope,
  SastEvidenceDeletionReceipt
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export interface DeleteSastEvidenceInput {
  operationId: string;
  deletionScheduleId: string;
  deletionScheduleDigest: `sha256:${string}`;
  scope: SastEvidenceAccessScope;
}

export abstract class SastEvidenceDeletionAuthority {
  /**
   * Implementations delete by operationId and must return the same receipt for
   * an exact replay. They must not expose a content read capability.
   */
  abstract delete(
    input: Readonly<DeleteSastEvidenceInput>
  ): Promise<SastEvidenceDeletionReceipt>;
}

export class SastEvidenceDeletionAuthorityUnavailableError extends Error {
  constructor() {
    super('No production evidence deletion authority is installed.');
    this.name = 'SastEvidenceDeletionAuthorityUnavailableError';
  }
}

@Injectable()
export class UnavailableSastEvidenceDeletionAuthority
  extends SastEvidenceDeletionAuthority {
  delete(): Promise<SastEvidenceDeletionReceipt> {
    return Promise.reject(
      new SastEvidenceDeletionAuthorityUnavailableError()
    );
  }
}
