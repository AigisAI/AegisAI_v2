import { Equals, IsInt, IsString, Matches, Max, Min } from 'class-validator';
import { MAX_SCAN_CREDENTIAL_TTL_SECONDS } from '@aegisai/shared';

const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;

export class TokenBrokerIssueDto {
  @IsString()
  @Matches(RESOURCE_ID)
  tenantId!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  repositoryBindingId!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  scanRequestId!: string;

  @Equals('REPO_READ')
  principal!: 'REPO_READ';

  @IsString()
  @Matches(/^[0-9a-fA-F]{7,64}$/)
  commitSha!: string;

  @IsInt()
  @Min(1)
  @Max(MAX_SCAN_CREDENTIAL_TTL_SECONDS)
  ttlSeconds!: number;

  @IsString()
  @Matches(RESOURCE_ID)
  auditReason!: string;
}
