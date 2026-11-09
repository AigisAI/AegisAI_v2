import { IsIn, IsOptional, IsString, Length, Matches } from "class-validator";

export class GithubCallbackQueryDto {
  @IsOptional()
  @IsString()
  @IsIn(["https://github.com/login/oauth"])
  iss?: string;

  @IsString()
  @Length(8, 512)
  @Matches(/^[A-Za-z0-9_-]+$/)
  code!: string;

  @IsString()
  @Length(32, 512)
  @Matches(/^[A-Za-z0-9_.-]+$/)
  state!: string;
}
