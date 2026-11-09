import { ArrayMaxSize, ArrayMinSize, ArrayUnique, IsArray, IsInt, Max, Min } from "class-validator";
import type { LinkGithubInstallationRequest } from "@aegisai/shared";

export class LinkGithubInstallationDto implements LinkGithubInstallationRequest {
  @IsInt()
  @Min(1)
  @Max(Number.MAX_SAFE_INTEGER)
  installationId!: number;

  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(100)
  @ArrayUnique()
  @IsInt({ each: true })
  @Min(1, { each: true })
  @Max(Number.MAX_SAFE_INTEGER, { each: true })
  repositoryIds!: number[];
}
