import { Type } from 'class-transformer';
import {
  Equals,
  IsInt,
  IsString,
  Matches,
  Max,
  Min,
  ValidateNested
} from 'class-validator';
import {
  MAX_SCAN_CREDENTIAL_TTL_SECONDS,
  WORKLOAD_IDENTITY_ATTESTATION_AUDIENCE,
  WORKLOAD_IDENTITY_ATTESTATION_VERSION
} from '@aegisai/shared';

const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const FULL_COMMIT_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const ISO_TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

class WorkloadIdentityAttestationClaimsDto {
  @Equals(WORKLOAD_IDENTITY_ATTESTATION_VERSION)
  version!: typeof WORKLOAD_IDENTITY_ATTESTATION_VERSION;

  @Equals('aegisai-sandbox-provisioner')
  issuer!: 'aegisai-sandbox-provisioner';

  @Equals(WORKLOAD_IDENTITY_ATTESTATION_AUDIENCE)
  audience!: typeof WORKLOAD_IDENTITY_ATTESTATION_AUDIENCE;

  @IsString()
  @Matches(RESOURCE_ID)
  tenantId!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  repositoryBindingId!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  scanRequestId!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  attemptId!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  workloadIdentityRef!: string;

  @IsString()
  @Matches(FULL_COMMIT_SHA)
  commitSha!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  nonce!: string;

  @IsString()
  @Matches(ISO_TIMESTAMP)
  issuedAt!: string;

  @IsString()
  @Matches(ISO_TIMESTAMP)
  expiresAt!: string;
}

class WorkloadIdentityAttestationDto {
  @ValidateNested()
  @Type(() => WorkloadIdentityAttestationClaimsDto)
  claims!: WorkloadIdentityAttestationClaimsDto;

  @IsString()
  @Matches(/^sha256:[0-9a-f]{64}$/)
  signature!: `sha256:${string}`;
}

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

  @IsString()
  @Matches(RESOURCE_ID)
  attemptId!: string;

  @IsString()
  @Matches(RESOURCE_ID)
  workloadIdentityRef!: string;

  @ValidateNested()
  @Type(() => WorkloadIdentityAttestationDto)
  workloadIdentityAttestation!: WorkloadIdentityAttestationDto;

  @Equals('REPO_READ')
  principal!: 'REPO_READ';

  @IsString()
  @Matches(FULL_COMMIT_SHA)
  commitSha!: string;

  @IsInt()
  @Min(1)
  @Max(MAX_SCAN_CREDENTIAL_TTL_SECONDS)
  ttlSeconds!: number;

  @IsString()
  @Matches(RESOURCE_ID)
  auditReason!: string;
}
