const gitlabStrategyCapture: { options?: Record<string, unknown> } = {};

jest.mock('passport-gitlab2', () => {
  return class MockGitlabPassportStrategy {
    name = 'gitlab';

    constructor(options: Record<string, unknown>) {
      gitlabStrategyCapture.options = options;
    }

    authenticate(): void {}
  };
});

import type { AuthUser } from '@aegisai/shared';

import { GitlabStrategy } from '../../src/auth/strategies/gitlab.strategy';

describe('GitlabStrategy', () => {
  const env = {
    APP_URL: 'http://localhost:3000',
    GITLAB_CLIENT_ID: 'gitlab-client-id',
    GITLAB_CLIENT_SECRET: 'gitlab-client-secret'
  } as const;

  beforeEach(() => {
    gitlabStrategyCapture.options = undefined;
  });

  it('builds the gitlab passport strategy from config', () => {
    const config = {
      get: jest.fn((key: keyof typeof env) => env[key])
    };
    const authService = {
      findOrCreateUser: jest.fn()
    };

    new GitlabStrategy(config as never, authService as never);

    expect(gitlabStrategyCapture.options).toEqual(
      expect.objectContaining({
        clientID: 'gitlab-client-id',
        clientSecret: 'gitlab-client-secret',
        callbackURL: 'http://localhost:3000/api/auth/gitlab/callback',
        scope: ['read_user', 'read_api'],
        state: true
      })
    );
  });

  it('delegates validated gitlab logins to AuthService', async () => {
    const expectedUser: AuthUser = {
      id: 'user-1',
      email: 'gitlab@example.com',
      name: 'GitLab User',
      avatarUrl: 'https://example.com/gitlab.png',
      connectedProviders: ['gitlab']
    };
    const config = {
      get: jest.fn((key: keyof typeof env) => env[key])
    };
    const authService = {
      findOrCreateUser: jest.fn().mockResolvedValue(expectedUser)
    };
    const strategy = new GitlabStrategy(config as never, authService as never);
    const profile = {
      id: 'gitlab-456',
      username: 'gitlab-user',
      displayName: 'GitLab User',
      emails: [{ value: 'gitlab@example.com' }],
      avatarUrl: 'https://example.com/gitlab.png'
    };

    await expect(strategy.validate('gitlab-access-token', undefined, profile)).resolves.toEqual(
      expectedUser
    );

    expect(authService.findOrCreateUser).toHaveBeenCalledWith(
      'gitlab',
      profile,
      'gitlab-access-token',
      undefined
    );
  });
});
