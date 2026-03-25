import type { Provider } from '@aegisai/shared';

import { GitClientRegistry } from '../../../src/client/git/git-client.registry';
import type { IGitProviderClient } from '../../../src/client/git/git-provider-client.interface';

describe('GitClientRegistry', () => {
  it('returns the registered GitHub and GitLab clients by provider key', () => {
    const githubClient = { provider: 'github' } as unknown as IGitProviderClient;
    const gitlabClient = { provider: 'gitlab' } as unknown as IGitProviderClient;
    const registry = new GitClientRegistry(githubClient as never, gitlabClient as never);

    expect(registry.get('github')).toBe(githubClient);
    expect(registry.get('gitlab')).toBe(gitlabClient);
  });

  it('throws for unsupported providers', () => {
    const registry = new GitClientRegistry(
      {} as never,
      {} as never
    );

    expect(() => registry.get('bitbucket' as Provider)).toThrow(
      'Unsupported git provider: bitbucket'
    );
  });
});
