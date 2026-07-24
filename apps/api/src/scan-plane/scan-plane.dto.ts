import type {
  SastSandboxRuntimeAttestation,
  SastScannerPreflightBinding,
  SastScanPlan
} from '@aegisai/shared';
import {
  IsBoolean,
  IsInt,
  IsObject,
  IsOptional,
  IsString,
  Matches,
  Max,
  Min
} from 'class-validator';

const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const ROUTE_RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/;
const VERSION_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export class RunMockScanPlaneDto {
  @IsString()
  @Matches(RESOURCE_ID)
  tenantId!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  scanRequestId!: string;

  @IsString()
  @Matches(VERSION_ID)
  scannerSetVersion!: string;
}

export class RunSandboxScannersDto {
  @IsObject()
  plan!: SastScanPlan;

  @IsString()
  @Matches(RESOURCE_ID)
  attemptId!: string;

  @IsInt()
  @Min(1)
  @Max(2)
  attemptNumber!: number;

  @IsString()
  @Matches(RESOURCE_ID)
  sandboxId!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  workloadIdentityRef!: string;

  @IsObject()
  preflight!: SastScannerPreflightBinding;

  @IsObject()
  sandboxAttestation!: SastSandboxRuntimeAttestation;
}

export class ScanArtifactsQueryDto {
  @IsString()
  @Matches(RESOURCE_ID)
  scanRequestId!: string;

  @IsOptional()
  @IsString()
  @Matches(RESOURCE_ID)
  tenantId?: string;
}

export class EvidenceAccessRequestDto extends ScanArtifactsQueryDto {
  @IsOptional()
  @IsBoolean()
  metadataOnly?: boolean;
}

export class SastArtifactIngressPathDto {
  @IsString()
  @Matches(ROUTE_RESOURCE_ID)
  scanRequestId!: string;

  @IsString()
  @Matches(ROUTE_RESOURCE_ID)
  scannerRunId!: string;
}
