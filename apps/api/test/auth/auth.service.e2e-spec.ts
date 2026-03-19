import { AuthService } from '../../src/auth/auth.service';

describe('AuthService', () => {
  it('creates a github-backed user and stores encrypted provider tokens', async () => {
    const prisma = {
      user: {
        findUnique: jest
          .fn()
          .mockResolvedValueOnce(null)
          .mockResolvedValueOnce({
            id: 'user-1',
            email: 'octo@example.com',
            name: 'Octo Cat',
            avatarUrl: 'https://example.com/octo.png',
            oauthTokens: [{ provider: 'GITHUB' }]
          }),
        create: jest.fn().mockResolvedValue({ id: 'user-1' })
      },
      oAuthToken: {
        findUnique: jest.fn().mockResolvedValue(null),
        upsert: jest.fn().mockResolvedValue({ id: 'token-1' })
      }
    };
    const tokenCrypto = {
      encrypt: jest.fn((value: string) => `enc(${value})`)
    };

    const service = new AuthService(prisma as never, tokenCrypto as never);

    await expect(
      service.findOrCreateUser(
        'github',
        {
          id: 'github-123',
          username: 'octocat',
          displayName: 'Octo Cat',
          emails: [{ value: 'octo@example.com' }],
          photos: [{ value: 'https://example.com/octo.png' }]
        },
        'github-access-token',
        'github-refresh-token'
      )
    ).resolves.toEqual({
      id: 'user-1',
      email: 'octo@example.com',
      name: 'Octo Cat',
      avatarUrl: 'https://example.com/octo.png',
      connectedProviders: ['github']
    });

    expect(prisma.oAuthToken.findUnique).toHaveBeenCalledWith({
      where: {
        provider_providerUserId: {
          provider: 'GITHUB',
          providerUserId: 'github-123'
        }
      }
    });
    expect(prisma.user.create).toHaveBeenCalledWith({
      data: {
        email: 'octo@example.com',
        name: 'Octo Cat',
        avatarUrl: 'https://example.com/octo.png'
      }
    });
    expect(tokenCrypto.encrypt).toHaveBeenNthCalledWith(1, 'github-access-token');
    expect(tokenCrypto.encrypt).toHaveBeenNthCalledWith(2, 'github-refresh-token');
    expect(prisma.oAuthToken.upsert).toHaveBeenCalledWith({
      where: {
        provider_providerUserId: {
          provider: 'GITHUB',
          providerUserId: 'github-123'
        }
      },
      update: {
        accessToken: 'enc(github-access-token)',
        refreshToken: 'enc(github-refresh-token)',
        expiresAt: null
      },
      create: {
        userId: 'user-1',
        provider: 'GITHUB',
        providerUserId: 'github-123',
        accessToken: 'enc(github-access-token)',
        refreshToken: 'enc(github-refresh-token)',
        expiresAt: null
      }
    });
  });

  it('reuses an existing email-matched user for a gitlab login', async () => {
    const prisma = {
      user: {
        findUnique: jest
          .fn()
          .mockResolvedValueOnce({
            id: 'user-1',
            email: 'gitlab@example.com',
            name: 'Existing User',
            avatarUrl: null,
            oauthTokens: [{ provider: 'GITHUB' }]
          })
          .mockResolvedValueOnce({
            id: 'user-1',
            email: 'gitlab@example.com',
            name: 'GitLab User',
            avatarUrl: 'https://example.com/gitlab.png',
            oauthTokens: [{ provider: 'GITHUB' }, { provider: 'GITLAB' }]
          }),
        create: jest.fn(),
        update: jest.fn().mockResolvedValue({ id: 'user-1' })
      },
      oAuthToken: {
        findUnique: jest.fn().mockResolvedValue(null),
        upsert: jest.fn().mockResolvedValue({ id: 'token-2' })
      }
    };
    const tokenCrypto = {
      encrypt: jest.fn((value: string) => `enc(${value})`)
    };

    const service = new AuthService(prisma as never, tokenCrypto as never);

    await expect(
      service.findOrCreateUser(
        'gitlab',
        {
          id: 'gitlab-456',
          username: 'gitlab-user',
          displayName: 'GitLab User',
          emails: [{ value: 'gitlab@example.com' }],
          avatarUrl: 'https://example.com/gitlab.png'
        },
        'gitlab-access-token'
      )
    ).resolves.toEqual({
      id: 'user-1',
      email: 'gitlab@example.com',
      name: 'GitLab User',
      avatarUrl: 'https://example.com/gitlab.png',
      connectedProviders: ['github', 'gitlab']
    });

    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(prisma.user.update).toHaveBeenCalledWith({
      where: { id: 'user-1' },
      data: {
        email: 'gitlab@example.com',
        name: 'GitLab User',
        avatarUrl: 'https://example.com/gitlab.png'
      }
    });
    expect(tokenCrypto.encrypt).toHaveBeenCalledTimes(1);
    expect(tokenCrypto.encrypt).toHaveBeenCalledWith('gitlab-access-token');
    expect(prisma.oAuthToken.upsert).toHaveBeenCalledWith({
      where: {
        provider_providerUserId: {
          provider: 'GITLAB',
          providerUserId: 'gitlab-456'
        }
      },
      update: {
        accessToken: 'enc(gitlab-access-token)',
        refreshToken: null,
        expiresAt: null
      },
      create: {
        userId: 'user-1',
        provider: 'GITLAB',
        providerUserId: 'gitlab-456',
        accessToken: 'enc(gitlab-access-token)',
        refreshToken: null,
        expiresAt: null
      }
    });
  });

  it('maps a persisted user into the shared session shape', async () => {
    const prisma = {
      user: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'user-1',
          email: 'user@example.com',
          name: 'Aegis User',
          avatarUrl: 'https://example.com/avatar.png',
          oauthTokens: [{ provider: 'GITHUB' }, { provider: 'GITLAB' }]
        })
      }
    };

    const service = new AuthService(prisma as never, {} as never);

    await expect(service.getSessionUserById('user-1')).resolves.toEqual({
      id: 'user-1',
      email: 'user@example.com',
      name: 'Aegis User',
      avatarUrl: 'https://example.com/avatar.png',
      connectedProviders: ['github', 'gitlab']
    });

    expect(prisma.user.findUnique).toHaveBeenCalledWith({
      where: { id: 'user-1' },
      include: { oauthTokens: { select: { provider: true } } }
    });
  });

  it('returns null when the user no longer exists', async () => {
    const service = new AuthService({
      user: {
        findUnique: jest.fn().mockResolvedValue(null)
      }
    } as never, {} as never);

    await expect(service.getSessionUserById('missing-user')).resolves.toBeNull();
  });

  it('creates distinct csrf token values', () => {
    const service = new AuthService({} as never, {} as never);

    const first = service.createCsrfToken();
    const second = service.createCsrfToken();

    expect(first).toMatch(/^[a-f0-9]{64}$/);
    expect(second).toMatch(/^[a-f0-9]{64}$/);
    expect(first).not.toBe(second);
  });
});
