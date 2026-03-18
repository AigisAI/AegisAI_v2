import { AuthService } from '../../src/auth/auth.service';

describe('AuthService', () => {
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

    const service = new AuthService(prisma as never);

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
    } as never);

    await expect(service.getSessionUserById('missing-user')).resolves.toBeNull();
  });

  it('creates distinct csrf token values', () => {
    const service = new AuthService({} as never);

    const first = service.createCsrfToken();
    const second = service.createCsrfToken();

    expect(first).toMatch(/^[a-f0-9]{64}$/);
    expect(second).toMatch(/^[a-f0-9]{64}$/);
    expect(first).not.toBe(second);
  });
});
