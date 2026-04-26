import { Injectable } from '@nestjs/common';
import { PassportSerializer } from '@nestjs/passport';
import type { AuthUser } from '@aegisai/shared';

import { AuthService } from './auth.service';

@Injectable()
export class AuthSerializer extends PassportSerializer {
  constructor(private readonly authService: AuthService) {
    super();
  }

  serializeUser(user: AuthUser, done: (err: Error | null, payload?: string) => void): void {
    done(null, user.id);
  }

  async deserializeUser(payload: string, done: (err: Error | null, user?: AuthUser | false) => void): Promise<void> {
    try {
      const user = await this.authService.getSessionUserById(payload);

      if (!user) {
        done(null, false);
        return;
      }

      done(null, user);
    } catch (error) {
      done(error as Error);
    }
  }
}
