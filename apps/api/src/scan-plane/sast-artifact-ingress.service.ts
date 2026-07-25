import { createHash, randomUUID } from 'node:crypto';
import { TextDecoder } from 'node:util';

import {
  SAST_ARTIFACT_INGRESS_MEDIA_TYPE,
  SAST_MAX_ARTIFACT_ENVELOPE_BYTES,
  buildSastArtifactIngressIdempotencyKey,
  canonicalizeScannerArtifactEnvelope,
  isScannerArtifactEnvelopeBoundToPlan,
  isScannerArtifactEnvelopeShapeValid,
  type SastArtifactIngressReceipt,
  type ScannerArtifactEnvelope
} from '@aegisai/shared';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  PayloadTooLargeException,
  ServiceUnavailableException,
  UnsupportedMediaTypeException
} from '@nestjs/common';

import type { AuthenticatedSastWorkloadIdentity } from './sast-workload-identity.authenticator';
import {
  SastArtifactIngressReplayConflictError,
  SastArtifactIngressReservationRetryError,
  SastArtifactIngressStateConflictError,
  SastArtifactIngressStore,
  type SastArtifactIngressExpectedBinding
} from './sast-artifact-ingress.store';
import {
  SastArtifactObjectStore,
  SastArtifactObjectStoreUnavailableError
} from './sast-artifact-object-store';
import { SastArtifactValidationService } from './sast-artifact-validation.service';

const MAX_BASE64URL_ENVELOPE_BYTES =
  Math.ceil((SAST_MAX_ARTIFACT_ENVELOPE_BYTES * 4) / 3) + 4;

export interface IngestSastArtifactInput {
  scanRequestId: string;
  scannerRunId: string;
  envelopeHeader: string | undefined;
  idempotencyKey: string | undefined;
  contentType: string | undefined;
  contentLength: string | undefined;
  workloadIdentity: Readonly<AuthenticatedSastWorkloadIdentity>;
  body: AsyncIterable<Uint8Array>;
}

class SastArtifactTransportError extends Error {
  constructor(
    readonly reasonCode:
      | 'ARTIFACT_BODY_EXCEEDS_DECLARED_SIZE'
      | 'ARTIFACT_BODY_SIZE_MISMATCH'
  ) {
    super(reasonCode);
    this.name = 'SastArtifactTransportError';
  }
}

@Injectable()
export class SastArtifactIngressService {
  constructor(
    private readonly store: SastArtifactIngressStore,
    private readonly objectStore: SastArtifactObjectStore,
    private readonly validation: SastArtifactValidationService
  ) {}

  async ingest(
    input: Readonly<IngestSastArtifactInput>
  ): Promise<SastArtifactIngressReceipt> {
    this.assertMediaType(input.contentType);
    const envelope = this.decodeEnvelope(input.envelopeHeader);
    if (
      envelope.scanRequestId !== input.scanRequestId ||
      envelope.scannerRunId !== input.scannerRunId
    ) {
      throw this.badRequest(
        'ARTIFACT_INGRESS_PATH_MISMATCH',
        'Artifact envelope does not match the ingress path.'
      );
    }

    const expected = await this.store.loadExpectedBinding(
      input.scanRequestId,
      input.scannerRunId
    );
    if (!expected) {
      throw new NotFoundException({
        errorCode: 'ARTIFACT_INGRESS_NOT_FOUND',
        message: 'The artifact ingress binding does not exist.'
      });
    }

    await this.assertIdentity(input.workloadIdentity, envelope, expected);
    this.assertIngressOpen(expected);
    await this.assertEnvelopeBinding(
      envelope,
      expected,
      input.workloadIdentity
    );
    this.assertContentLength(
      input.contentLength,
      envelope.byteSize,
      expected.plan.profile.limits.maxArtifactBytes
    );

    const requiredIdempotencyKey =
      buildSastArtifactIngressIdempotencyKey(envelope);
    if (input.idempotencyKey !== requiredIdempotencyKey) {
      throw this.badRequest(
        'ARTIFACT_IDEMPOTENCY_KEY_INVALID',
        'Artifact idempotency key is missing or does not match the envelope.'
      );
    }

    const canonicalEnvelope = canonicalizeScannerArtifactEnvelope(envelope);
    const envelopeDigest = this.digest(canonicalEnvelope);
    const ingestionId = `sast_ingestion_${randomUUID()}`;
    const now = new Date().toISOString();

    let reservation;
    try {
      reservation = await this.store.reserve({
        ingestionId,
        envelope,
        envelopeDigest,
        idempotencyKey: requiredIdempotencyKey,
        expected,
        declaredContentDigest: envelope.contentDigest,
        declaredByteSize: envelope.byteSize,
        now
      });
    } catch (error) {
      if (error instanceof SastArtifactIngressReplayConflictError) {
        throw new ConflictException({
          errorCode: 'ARTIFACT_INGRESS_REPLAY_CONFLICT',
          message: 'A different artifact was already submitted for this scanner run.'
        });
      }
      if (error instanceof SastArtifactIngressStateConflictError) {
        throw new ConflictException({
          errorCode: 'ARTIFACT_INGRESS_CLOSED',
          message: 'The artifact ingress lifecycle is not open for this scanner run.'
        });
      }
      if (error instanceof SastArtifactIngressReservationRetryError) {
        throw this.unavailable(
          'ARTIFACT_INGRESS_RESERVATION_RETRY',
          'Artifact ingress reservation must be retried.'
        );
      }
      throw error;
    }

    if (reservation.kind === 'REPLAY') {
      await this.drainReplayBody(input.body, envelope.byteSize);
      return {
        ingestionId: reservation.ingestionId,
        scannerRunId: envelope.scannerRunId,
        state: 'PENDING_VALIDATION',
        replayed: true,
        receivedAt: reservation.receivedAt!
      };
    }

    const observation = {
      byteSize: 0,
      hash: createHash('sha256')
    };
    let objectKey: string | undefined;
    try {
      const validationSession = await this.validation.createSession({
        envelope,
        envelopeDigest,
        expected
      });
      const write = await this.objectStore.put({
        ingestionId,
        tenantId: envelope.tenantId,
        repositoryBindingId: envelope.repositoryBindingId,
        scanRequestId: envelope.scanRequestId,
        attemptId: envelope.attemptId,
        scannerRunId: envelope.scannerRunId,
        body: validationSession.observe(
          this.observeBody(input.body, envelope.byteSize, observation)
        )
      });
      objectKey = this.validateObjectKey(write.objectKey);
      if (observation.byteSize !== envelope.byteSize) {
        throw new SastArtifactTransportError(
          'ARTIFACT_BODY_SIZE_MISMATCH'
        );
      }

      const receivedAt = new Date().toISOString();
      const observedContentDigest =
        `sha256:${observation.hash.digest('hex')}` as const;
      const validationResult = validationSession.finish();
      if (
        validationResult.observedContentDigest !==
          observedContentDigest ||
        validationResult.statistics.observedByteSize !==
          observation.byteSize
      ) {
        throw new Error('Artifact validation observation mismatch.');
      }
      await this.store.complete({
        ingestionId,
        objectKey,
        observedContentDigest,
        observedByteSize: observation.byteSize,
        validation: validationResult,
        receivedAt
      });

      return {
        ingestionId,
        scannerRunId: envelope.scannerRunId,
        state: 'PENDING_VALIDATION',
        replayed: false,
        receivedAt
      };
    } catch (error) {
      if (error instanceof SastArtifactTransportError) {
        const observedContentDigest =
          error.reasonCode === 'ARTIFACT_BODY_SIZE_MISMATCH'
            ? (`sha256:${observation.hash.digest('hex')}` as const)
            : undefined;
        await this.store.reject({
          ingestionId,
          reasonCode: error.reasonCode,
          observedContentDigest,
          observedByteSize: observation.byteSize,
          rejectedAt: new Date().toISOString()
        });
        if (objectKey) {
          await this.deleteStoredObject(objectKey);
        }
        if (error.reasonCode === 'ARTIFACT_BODY_EXCEEDS_DECLARED_SIZE') {
          throw new PayloadTooLargeException({
            errorCode: error.reasonCode,
            message: 'Artifact body exceeds its declared bounded size.'
          });
        }
        throw this.badRequest(
          error.reasonCode,
          'Artifact body size does not match the envelope.'
        );
      }

      const reasonCode =
        error instanceof SastArtifactObjectStoreUnavailableError
          ? 'ARTIFACT_OBJECT_STORE_UNAVAILABLE'
          : 'ARTIFACT_OBJECT_WRITE_FAILED';
      await this.store.abort({
        ingestionId,
        reasonCode,
        occurredAt: new Date().toISOString()
      });
      if (objectKey) {
        await this.deleteStoredObject(objectKey);
      }
      throw this.unavailable(
        reasonCode,
        'Artifact object storage is temporarily unavailable.'
      );
    }
  }

  private decodeEnvelope(header: string | undefined): ScannerArtifactEnvelope {
    if (
      typeof header !== 'string' ||
      header.length === 0 ||
      Buffer.byteLength(header, 'ascii') > MAX_BASE64URL_ENVELOPE_BYTES ||
      !/^[A-Za-z0-9_-]+$/u.test(header)
    ) {
      throw this.badRequest(
        'ARTIFACT_ENVELOPE_HEADER_INVALID',
        'Artifact envelope header is missing or invalid.'
      );
    }

    try {
      const bytes = Buffer.from(header, 'base64url');
      if (
        bytes.length === 0 ||
        bytes.length > SAST_MAX_ARTIFACT_ENVELOPE_BYTES ||
        bytes.toString('base64url') !== header
      ) {
        throw new Error('non-canonical base64url');
      }
      const json = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      const parsed = JSON.parse(json) as unknown;
      if (
        !isScannerArtifactEnvelopeShapeValid(parsed) ||
        canonicalizeScannerArtifactEnvelope(parsed) !== json
      ) {
        throw new Error('non-canonical envelope');
      }
      return Object.freeze(parsed);
    } catch {
      throw this.badRequest(
        'ARTIFACT_ENVELOPE_HEADER_INVALID',
        'Artifact envelope header is missing or invalid.'
      );
    }
  }

  private async assertIdentity(
    identity: Readonly<AuthenticatedSastWorkloadIdentity>,
    envelope: Readonly<ScannerArtifactEnvelope>,
    expected: Readonly<SastArtifactIngressExpectedBinding>
  ): Promise<void> {
    if (
      identity.identityRef === expected.workloadIdentityRef &&
      envelope.workloadIdentityRef === expected.workloadIdentityRef
    ) {
      return;
    }

    await this.store.recordRejectedRequest({
      expected,
      certificateFingerprint: identity.certificateFingerprint,
      reasonCode: 'ARTIFACT_WORKLOAD_IDENTITY_MISMATCH',
      workloadIdentityValidated: false,
      occurredAt: new Date().toISOString()
    });
    throw new ForbiddenException({
      errorCode: 'ARTIFACT_WORKLOAD_IDENTITY_MISMATCH',
      message: 'Workload identity does not match the scanner attempt.'
    });
  }

  private assertIngressOpen(
    expected: Readonly<SastArtifactIngressExpectedBinding>
  ): void {
    if (
      expected.attemptStage !== 'SCANNING' ||
      expected.scannerRunStatus !== 'RUNNING' ||
      Date.parse(expected.attemptDeadlineAt) <= Date.now()
    ) {
      throw new ConflictException({
        errorCode: 'ARTIFACT_INGRESS_CLOSED',
        message: 'The artifact ingress lifecycle is not open for this scanner run.'
      });
    }
  }

  private async assertEnvelopeBinding(
    envelope: Readonly<ScannerArtifactEnvelope>,
    expected: Readonly<SastArtifactIngressExpectedBinding>,
    identity: Readonly<AuthenticatedSastWorkloadIdentity>
  ): Promise<void> {
    const bound =
      envelope.scanner === expected.scanner &&
      envelope.artifactRef === expected.artifactRef &&
      envelope.artifactRef ===
        `${expected.plan.resultIngressRef}/${expected.scanner.toLowerCase()}` &&
      isScannerArtifactEnvelopeBoundToPlan(envelope, expected.plan, {
        attemptId: expected.attemptId,
        scannerRunId: expected.scannerRunId,
        scanner: expected.scanner,
        artifactRef: expected.artifactRef,
        workloadIdentityRef: identity.identityRef,
        preflightAttestationRef: expected.preflightAttestationRef,
        preflightInventoryDigest: expected.preflightInventoryDigest
      });
    if (!bound) {
      await this.store.recordRejectedRequest({
        expected,
        certificateFingerprint: identity.certificateFingerprint,
        reasonCode: 'ARTIFACT_SCOPE_BINDING_MISMATCH',
        workloadIdentityValidated: true,
        occurredAt: new Date().toISOString()
      });
      throw new ForbiddenException({
        errorCode: 'ARTIFACT_SCOPE_BINDING_MISMATCH',
        message: 'Artifact envelope does not match the durable scanner binding.'
      });
    }
  }

  private assertMediaType(contentType: string | undefined): void {
    if (contentType?.toLowerCase() !== SAST_ARTIFACT_INGRESS_MEDIA_TYPE) {
      throw new UnsupportedMediaTypeException({
        errorCode: 'ARTIFACT_MEDIA_TYPE_INVALID',
        message: `Artifact bytes require ${SAST_ARTIFACT_INGRESS_MEDIA_TYPE}.`
      });
    }
  }

  private assertContentLength(
    contentLength: string | undefined,
    envelopeByteSize: number,
    maximumBytes: number
  ): void {
    if (
      typeof contentLength !== 'string' ||
      !/^[1-9][0-9]{0,9}$/u.test(contentLength)
    ) {
      throw this.badRequest(
        'ARTIFACT_CONTENT_LENGTH_REQUIRED',
        'A positive canonical Content-Length is required.'
      );
    }
    const declaredLength = Number(contentLength);
    if (
      !Number.isSafeInteger(declaredLength) ||
      declaredLength !== envelopeByteSize
    ) {
      throw this.badRequest(
        'ARTIFACT_CONTENT_LENGTH_MISMATCH',
        'Content-Length does not match the artifact envelope.'
      );
    }
    if (declaredLength > maximumBytes) {
      throw new PayloadTooLargeException({
        errorCode: 'ARTIFACT_SIZE_LIMIT_EXCEEDED',
        message: 'Artifact exceeds the immutable profile byte limit.'
      });
    }
  }

  private async *observeBody(
    body: AsyncIterable<Uint8Array>,
    maximumBytes: number,
    observation: { byteSize: number; hash: ReturnType<typeof createHash> }
  ): AsyncGenerator<Uint8Array> {
    for await (const chunk of body) {
      const bytes = Buffer.from(chunk);
      observation.byteSize += bytes.byteLength;
      if (observation.byteSize > maximumBytes) {
        observation.byteSize = maximumBytes + 1;
        throw new SastArtifactTransportError(
          'ARTIFACT_BODY_EXCEEDS_DECLARED_SIZE'
        );
      }
      observation.hash.update(bytes);
      yield bytes;
    }
  }

  private async drainReplayBody(
    body: AsyncIterable<Uint8Array>,
    expectedBytes: number
  ): Promise<void> {
    let observedBytes = 0;
    for await (const chunk of body) {
      observedBytes += chunk.byteLength;
      if (observedBytes > expectedBytes) {
        throw new PayloadTooLargeException({
          errorCode: 'ARTIFACT_BODY_EXCEEDS_DECLARED_SIZE',
          message: 'Artifact replay body exceeds its declared bounded size.'
        });
      }
    }
    if (observedBytes !== expectedBytes) {
      throw this.badRequest(
        'ARTIFACT_BODY_SIZE_MISMATCH',
        'Artifact replay body size does not match the envelope.'
      );
    }
  }

  private validateObjectKey(objectKey: string): string {
    if (
      typeof objectKey !== 'string' ||
      objectKey.length === 0 ||
      objectKey.length > 2048 ||
      [...objectKey].some((character) => {
        const codePoint = character.codePointAt(0)!;
        return codePoint <= 31 || codePoint === 127;
      })
    ) {
      throw new SastArtifactObjectStoreUnavailableError();
    }
    return objectKey;
  }

  private async deleteStoredObject(objectKey: string): Promise<void> {
    try {
      await this.objectStore.delete(objectKey);
    } catch {
      throw this.unavailable(
        'ARTIFACT_OBJECT_DELETE_FAILED',
        'Artifact object cleanup failed.'
      );
    }
  }

  private digest(value: string): `sha256:${string}` {
    return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
  }

  private badRequest(errorCode: string, message: string): BadRequestException {
    return new BadRequestException({ errorCode, message });
  }

  private unavailable(
    errorCode: string,
    message: string
  ): ServiceUnavailableException {
    return new ServiceUnavailableException({ errorCode, message });
  }
}
