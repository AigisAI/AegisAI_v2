import { Injectable } from '@nestjs/common';

export interface SastArtifactObjectWrite {
  ingestionId: string;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  scannerRunId: string;
  body: AsyncIterable<Uint8Array>;
}

export interface SastArtifactObjectWriteResult {
  objectKey: string;
}

export abstract class SastArtifactObjectStore {
  /**
   * Implementations must create an immutable object and consume the body once.
   * They must not expose a read method to the Scan Plane.
   */
  abstract put(
    input: Readonly<SastArtifactObjectWrite>
  ): Promise<SastArtifactObjectWriteResult>;

  abstract delete(objectKey: string): Promise<void>;
}

export class SastArtifactObjectStoreUnavailableError extends Error {
  constructor() {
    super('No production SAST artifact object-store adapter is installed.');
    this.name = 'SastArtifactObjectStoreUnavailableError';
  }
}

@Injectable()
export class UnavailableSastArtifactObjectStore
  extends SastArtifactObjectStore
{
  put(): Promise<SastArtifactObjectWriteResult> {
    return Promise.reject(new SastArtifactObjectStoreUnavailableError());
  }

  delete(): Promise<void> {
    return Promise.reject(new SastArtifactObjectStoreUnavailableError());
  }
}
