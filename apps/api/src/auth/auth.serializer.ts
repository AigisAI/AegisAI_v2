import { Injectable, UnauthorizedException } from '@nestjs/common';
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

  async deserializeUser(payload: string, done: (err: Error | null, user?: AuthUser) => void): Promise<void> {
    try {
      const user = await this.authService.getSessionUserById(payload);

      if (!user) {
        done(new UnauthorizedException({ message: '인증된 사용자를 찾을 수 없습니다.', errorCode: 'UNAUTHORIZED' }));
        return;
      }

      done(null, user);
    } catch (error) {
      done(error as Error);
    }
  }
}
