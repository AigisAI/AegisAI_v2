import { Type } from "class-transformer";
import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Length,
  Matches,
  Max,
  Min,
  ValidateNested
} from "class-validator";
import { SCAN_LANES } from "@aegisai/shared";

const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const VERSION_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_TEXT = /^[^\p{Cc}]+$/u;
const UUID_V4 = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

export class InstallRepositoryDto {
  @IsString()
  @Matches(RESOURCE_ID)
  providerRepoId!: string;

  @IsString()
  @Length(3, 512)
  @Matches(/^[^\s/]+(?:\/[^\s/]+)+$/)
  fullName!: string;

  @IsString()
  @Length(1, 255)
  @Matches(SAFE_TEXT)
  defaultBranch!: string;

  @IsBoolean()
  isPrivate!: boolean;
}

export class InstallIntegrationDto {
  @IsString()
  @Matches(RESOURCE_ID)
  externalInstallationId!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  repoReadPrincipalId!: string;

  @IsOptional()
  @IsString()
  @Matches(RESOURCE_ID)
  commentWritePrincipalId?: string;

  @IsOptional()
  @IsString()
  @Matches(RESOURCE_ID)
  integrationAdminPrincipalId?: string;

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(100)
  @ValidateNested({ each: true })
  @Type(() => InstallRepositoryDto)
  repositories?: InstallRepositoryDto[];
}

export class IsolationSignalsDto {
  @IsInt()
  @Min(0)
  @Max(36_500)
  tenantAgeDays!: number;

  @IsInt()
  @Min(0)
  @Max(10_000_000)
  repositorySizeMb!: number;

  @IsBoolean()
  hasParserFaultHistory!: boolean;

  @IsBoolean()
  hasAbuseSignal!: boolean;

  @IsBoolean()
  hasSuspiciousPathLayout!: boolean;

  @IsBoolean()
  hasRepeatedTimeout!: boolean;

  @IsBoolean()
  manuallyEscalated!: boolean;
}

export class CreateScanRequestDto {
  @IsString()
  @Matches(RESOURCE_ID)
  repositoryBindingId!: string;

  @IsIn(SCAN_LANES)
  lane!: (typeof SCAN_LANES)[number];

  @IsString()
  @Length(1, 512)
  @Matches(SAFE_TEXT)
  targetRef!: string;

  @IsString()
  @Matches(/^[0-9a-fA-F]{7,64}$/)
  commitSha!: string;

  @IsString()
  @Matches(VERSION_ID)
  policyVersion!: string;

  @IsString()
  @Matches(VERSION_ID)
  scannerSetVersion!: string;

  @IsOptional()
  @ValidateNested()
  @Type(() => IsolationSignalsDto)
  isolationSignals?: IsolationSignalsDto;
}

export class ScanRequestIdParamDto {
  @IsString()
  @Matches(new RegExp(`^scan_request_${UUID_V4}$`, "i"))
  scanRequestId!: string;
}

export class IntegrationIdParamDto {
  @IsString()
  @Matches(new RegExp(`^integration_${UUID_V4}$`, "i"))
  integrationId!: string;
}
