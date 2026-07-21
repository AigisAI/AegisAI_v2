import { IsBoolean, IsIn, IsInt, IsOptional, IsString, Matches, Max, Min } from 'class-validator';

const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
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

export class RunSandboxScannersDto extends RunMockScanPlaneDto {
  @IsString()
  @Matches(RESOURCE_ID)
  workspaceRef!: string;

  @IsIn(['STANDARD', 'HARDENED', 'RESTRICTED'])
  isolationClass!: 'STANDARD' | 'HARDENED' | 'RESTRICTED';

  @IsInt()
  @Min(1)
  @Max(3600)
  timeoutSeconds!: number;
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
