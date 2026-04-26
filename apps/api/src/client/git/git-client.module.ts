import { HttpModule } from '@nestjs/axios';
import { Module } from '@nestjs/common';

import { GitClientRegistry } from './git-client.registry';
import { GithubClient } from './github.client';
import { GitlabClient } from './gitlab.client';

@Module({
  imports: [HttpModule],
  providers: [GitClientRegistry, GithubClient, GitlabClient],
  exports: [GitClientRegistry]
})
export class GitClientModule {}
