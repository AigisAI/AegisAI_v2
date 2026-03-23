import type {
  AuthUser,
  ConnectRepoRequest,
  ListAvailableReposQuery,
  ListRepoBranchesQuery,
  Provider
} from '@aegisai/shared';
import {
  BadRequestException,
  Body,
  Controller,
  DefaultValuePipe,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseIntPipe,
  Post,
  Query,
  UseGuards
} from '@nestjs/common';

import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { SkipTransform } from '../common/decorators/skip-transform.decorator';
import { RepoService } from './repo.service';

const VALID_PROVIDERS: Provider[] = ['github', 'gitlab'];

@Controller('repos')
@UseGuards(SessionAuthGuard)
export class RepoController {
  constructor(private readonly repoService: RepoService) {}

  @Get()
  async listConnectedRepos(@CurrentUser() user: AuthUser) {
    return this.repoService.listConnectedRepos(user.id);
  }

  @Get('available')
  async listAvailableRepos(
    @CurrentUser() user: AuthUser,
    @Query('provider') provider: string | undefined,
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
    @Query('size', new DefaultValuePipe(30), ParseIntPipe) size: number
  ) {
    return this.repoService.listAvailableRepos({
      userId: user.id,
      provider: this.parseProvider(provider),
      ...this.normalizePagination({ page, size })
    });
  }

  @Post()
  async connectRepo(
    @CurrentUser() user: AuthUser,
    @Body() body: Partial<ConnectRepoRequest>
  ) {
    const provider = this.parseProvider(body.provider);
    const providerRepoId = body.providerRepoId?.trim();

    if (!providerRepoId) {
      throw new BadRequestException({
        message: 'providerRepoId is required.',
        errorCode: 'BAD_REQUEST'
      });
    }

    return this.repoService.connectRepo({
      userId: user.id,
      provider,
      providerRepoId
    });
  }

  @Delete(':repoId')
  @HttpCode(204)
  @SkipTransform()
  async disconnectRepo(
    @CurrentUser() user: AuthUser,
    @Param('repoId') repoId: string
  ): Promise<void> {
    await this.repoService.disconnectRepo({
      userId: user.id,
      repoId
    });
  }

  @Get(':repoId/branches')
  async listBranches(
    @CurrentUser() user: AuthUser,
    @Param('repoId') repoId: string,
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
    @Query('size', new DefaultValuePipe(30), ParseIntPipe) size: number
  ) {
    return this.repoService.listBranches({
      userId: user.id,
      repoId,
      ...this.normalizePagination({ page, size })
    });
  }

  private parseProvider(provider: string | undefined): Provider {
    if (provider && VALID_PROVIDERS.includes(provider as Provider)) {
      return provider as Provider;
    }

    throw new BadRequestException({
      message: 'provider must be github or gitlab.',
      errorCode: 'BAD_REQUEST'
    });
  }

  private normalizePagination(input: ListAvailableReposQuery | ListRepoBranchesQuery) {
    if (!input.page || input.page < 1) {
      throw new BadRequestException({
        message: 'page must be a positive integer.',
        errorCode: 'BAD_REQUEST'
      });
    }

    if (!input.size || input.size < 1) {
      throw new BadRequestException({
        message: 'size must be a positive integer.',
        errorCode: 'BAD_REQUEST'
      });
    }

    return {
      page: input.page,
      size: input.size
    };
  }
}
