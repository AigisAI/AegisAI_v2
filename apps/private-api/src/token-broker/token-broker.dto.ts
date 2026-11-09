import { Equals, IsInt, IsString, Matches, Max, Min } from "class-validator";
import { MAX_SCAN_CREDENTIAL_TTL_SECONDS } from "@aegisai/shared/private-runtime";

const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UUID_V4 = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

export class TokenBrokerIssueDto {
  @IsString()
  @Matches(RESOURCE_ID)
  tenantId!: string;

  @IsString()
  @Matches(new RegExp(`^repository_binding_${UUID_V4}$`, "i"))
  repositoryBindingId!: string;

  @IsString()
  @Matches(new RegExp(`^scan_request_${UUID_V4}$`, "i"))
  scanRequestId!: string;

  @Equals("REPO_READ")
  principal!: "REPO_READ";

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
