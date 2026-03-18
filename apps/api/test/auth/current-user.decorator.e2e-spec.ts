import type { AuthUser } from '@aegisai/shared';

import { getCurrentUserFromRequest } from '../../src/auth/decorators/current-user.decorator';

describe('CurrentUser helper', () => {
  it('returns the authenticated user from the request object', () => {
    const user: AuthUser = {
      id: 'user-1',
      email: 'user@example.com',
      name: 'Aegis User',
      avatarUrl: null,
      connectedProviders: ['github']
    };

    expect(getCurrentUserFromRequest({ user })).toEqual(user);
  });
});
