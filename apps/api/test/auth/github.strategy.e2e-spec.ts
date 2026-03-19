const githubStrategyCapture: { options?: Record<string, unknown> } = {};

jest.mock('passport-github2', () => {
  class MockGithubPassportStrategy {
    name = 'github';

    constructor(options: Record<string, unknown>) {
      githubStrategyCapture.options = options;
    }

    authenticate(): void {}
  }

  return { Strategy: MockGithubPassportStrategy };
});

import type { AuthUser } from '@aegisai/shared';

import { GithubStrategy } from '../../src/auth/strategies/github.strategy';

describe('GithubStrategy', () => {
  const env = {
    APP_URL: 'http://localhost:3000',
    GITHUB_CLIENT_ID: 'github-client-id',
    GITHUB_CLIENT_SECRET: 'github-client-secret'
  } as const;

  beforeEach(() => {
    githubStrategyCapture.options = undefined;
  });

  it('builds the github passport strategy from config', () => {
    const config = {
      get: jest.fn((key: keyof typeof env) => env[key])
    };
    const authService = {
      findOrCreateUser: jest.fn()
    };

    new GithubStrategy(config as never, authService as never);

    expect(githubStrategyCapture.options).toEqual(
      expect.objectContaining({
        clientID: 'github-client-id',
        clientSecret: 'github-client-secret',
        callbackURL: 'http://localhost:3000/api/auth/github/callback',
        scope: ['read:user', 'user:email', 'repo'],
        state: true
      })
    );
  });

  it('delegates validated github logins to AuthService', async () => {
    const expectedUser: AuthUser = {
      id: 'user-1',
      email: 'octo@example.com',
      name: 'Octo Cat',
      avatarUrl: 'https://example.com/octo.png',
      connectedProviders: ['github']
    };
    const config = {
      get: jest.fn((key: keyof typeof env) => env[key])
    };
    const authService = {
      findOrCreateUser: jest.fn().mockResolvedValue(expectedUser)
    };
    const strategy = new GithubStrategy(config as never, authService as never);
    const profile = {
      id: 'github-123',
      username: 'octocat',
      displayName: 'Octo Cat',
      emails: [{ value: 'octo@example.com' }],
      photos: [{ value: 'https://example.com/octo.png' }]
    };

    await expect(
      strategy.validate('github-access-token', 'github-refresh-token', profile)
    ).resolves.toEqual(expectedUser);

    expect(authService.findOrCreateUser).toHaveBeenCalledWith(
      'github',
      profile,
      'github-access-token',
      'github-refresh-token'
    );
  });
});
