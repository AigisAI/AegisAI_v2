import type {
  ExpectedScannerArtifactBinding,
  ScannerArtifactEnvelope
} from '@aegisai/shared';
import { Injectable, Logger } from '@nestjs/common';

import type { SastArtifactIngressExpectedBinding } from './sast-artifact-ingress.store';
import {
  SastArtifactStreamValidationSession,
  type SastArtifactStreamValidationInput
} from './sast-artifact-stream-validator';
import { SastFileCoordinateAttestationProvider } from './sast-file-coordinate-attestation.provider';

export interface CreateSastArtifactValidationSessionInput {
  envelope: Readonly<ScannerArtifactEnvelope>;
  envelopeDigest: `sha256:${string}`;
  expected: Readonly<SastArtifactIngressExpectedBinding>;
}

@Injectable()
export class SastArtifactValidationService {
  private readonly logger = new Logger(SastArtifactValidationService.name);

  constructor(
    private readonly coordinateAttestations:
      SastFileCoordinateAttestationProvider
  ) {}

  async createSession(
    input: Readonly<CreateSastArtifactValidationSessionInput>
  ): Promise<SastArtifactStreamValidationSession> {
    const expectedBinding: ExpectedScannerArtifactBinding = {
      attemptId: input.expected.attemptId,
      scannerRunId: input.expected.scannerRunId,
      scanner: input.expected.scanner,
      artifactRef: input.expected.artifactRef,
      workloadIdentityRef: input.expected.workloadIdentityRef,
      preflightAttestationRef:
        input.expected.preflightAttestationRef,
      preflightInventoryDigest:
        input.expected.preflightInventoryDigest
    };
    const coordinateAttestation =
      await this.loadCoordinateAttestation(input.expected);
    const validationInput: SastArtifactStreamValidationInput = {
      envelope: input.envelope,
      plan: input.expected.plan,
      expectedBinding,
      envelopeDigest: input.envelopeDigest,
      coordinateAttestation
    };
    return new SastArtifactStreamValidationSession(validationInput);
  }

  private async loadCoordinateAttestation(
    expected: Readonly<SastArtifactIngressExpectedBinding>
  ) {
    try {
      return await this.coordinateAttestations.load({
        tenantId: expected.plan.tenantId,
        repositoryBindingId:
          expected.plan.repositoryState.repositoryBindingId,
        scanRequestId: expected.plan.scanRequestId,
        attemptId: expected.attemptId,
        preflightAttestationRef: expected.preflightAttestationRef,
        preflightInventoryDigest:
          expected.preflightInventoryDigest
      });
    } catch {
      this.logger.warn(
        'Coordinate attestation provider call failed; validation remains fail closed.'
      );
      // A missing or unavailable attestation never relaxes coordinate checks.
      return null;
    }
  }
}
