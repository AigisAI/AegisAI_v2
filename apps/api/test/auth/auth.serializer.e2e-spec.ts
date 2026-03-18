import type { AuthUser } from '@aegisai/shared';
import { UnauthorizedException } from '@nestjs/common';

import { AuthSerializer } from '../../src/auth/auth.serializer';

describe('AuthSerializer', () => {
  const authUser: AuthUser = {
    id: 'user-1',
    email: 'user@example.com',
    name: 'Aegis User',
    avatarUrl: null,
    connectedProviders: ['github']
  };

  it('serializes the authenticated user id into the session', () => {
    const serializer = new AuthSerializer({
      getSessionUserById: jest.fn()
    } as never);

    const done = jest.fn();

    serializer.serializeUser(authUser, done);

    expect(done).toHaveBeenCalledWith(null, 'user-1');
  });

  it('deserializes the user from the auth service', async () => {
    const serializer = new AuthSerializer({
      getSessionUserById: jest.fn().mockResolvedValue(authUser)
    } as never);

    const done = jest.fn();

    await serializer.deserializeUser('user-1', done);

    expect(done).toHaveBeenCalledWith(null, authUser);
  });

  it('fails deserialization when the user is missing', async () => {
    const serializer = new AuthSerializer({
      getSessionUserById: jest.fn().mockResolvedValue(null)
    } as never);

    const done = jest.fn();

    await serializer.deserializeUser('missing-user', done);

    expect(done).toHaveBeenCalled();
    expect(done.mock.calls[0][0]).toBeInstanceOf(UnauthorizedException);
  });
});
