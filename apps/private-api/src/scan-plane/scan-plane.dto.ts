import { Type } from "class-transformer";
import {
  ArrayMaxSize, IsArray, IsDefined, IsObject, IsString, Matches,
  ValidateBy, ValidateIf, ValidateNested
} from "class-validator";
import { isRepositoryManifestPath, MAX_MANIFEST_FILES } from "@aegisai/shared/private-runtime";

export class RepositoryManifestFileDto {
  @IsString()
  @ValidateBy({ name: "repositoryManifestPath", validator: {
    validate: (value: unknown) => typeof value === "string" && isRepositoryManifestPath(value),
    defaultMessage: () => "path must be a bounded repository-relative path"
  } })
  path!: string;
}

export class RepositoryManifestDto {
  @IsDefined()
  @IsArray()
  @ArrayMaxSize(MAX_MANIFEST_FILES)
  @IsObject({ each: true })
  @ValidateNested({ each: true })
  @Type(() => RepositoryManifestFileDto)
  files!: RepositoryManifestFileDto[];
}

const UUID_V4 = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

export class RunMockScanPlaneDto {
  @IsString()
  @Matches(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
  tenantId!: string;

  @IsString()
  @Matches(new RegExp(`^scan_request_${UUID_V4}$`, "i"))
  scanRequestId!: string;

  @IsString()
  @Matches(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/)
  scannerSetVersion!: string;

  @ValidateIf((_object, value: unknown) => value !== undefined)
  @IsObject()
  @ValidateNested()
  @Type(() => RepositoryManifestDto)
  repositoryManifest?: RepositoryManifestDto;
}

export class ScanArtifactsQueryDto {
  @IsString()
  @Matches(new RegExp(`^scan_request_${UUID_V4}$`, "i"))
  scanRequestId!: string;
}
