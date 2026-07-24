import {
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Put,
  Req,
  UseGuards
} from '@nestjs/common';
import {
  SAST_ARTIFACT_ENVELOPE_HEADER,
  SAST_ARTIFACT_IDEMPOTENCY_HEADER
} from '@aegisai/shared';
import type { Request } from 'express';

import { CurrentSastWorkloadIdentity } from './current-sast-workload-identity.decorator';
import { SastArtifactIngressPathDto } from './scan-plane.dto';
import { SastArtifactIngressService } from './sast-artifact-ingress.service';
import type { AuthenticatedSastWorkloadIdentity } from './sast-workload-identity.authenticator';
import { SastWorkloadIdentityGuard } from './sast-workload-identity.guard';

@Controller('scan-plane/result-ingress')
@UseGuards(SastWorkloadIdentityGuard)
export class SastArtifactIngressController {
  constructor(private readonly ingress: SastArtifactIngressService) {}

  @Put(':scanRequestId/scanner-runs/:scannerRunId')
  @HttpCode(HttpStatus.ACCEPTED)
  ingestArtifact(
    @Param() params: SastArtifactIngressPathDto,
    @Headers(SAST_ARTIFACT_ENVELOPE_HEADER)
    envelopeHeader: string | undefined,
    @Headers(SAST_ARTIFACT_IDEMPOTENCY_HEADER)
    idempotencyKey: string | undefined,
    @Headers('content-type') contentType: string | undefined,
    @Headers('content-length') contentLength: string | undefined,
    @CurrentSastWorkloadIdentity()
    workloadIdentity: Readonly<AuthenticatedSastWorkloadIdentity>,
    @Req() request: Request
  ) {
    return this.ingress.ingest({
      scanRequestId: params.scanRequestId,
      scannerRunId: params.scannerRunId,
      envelopeHeader,
      idempotencyKey,
      contentType,
      contentLength,
      workloadIdentity,
      body: request
    });
  }
}
