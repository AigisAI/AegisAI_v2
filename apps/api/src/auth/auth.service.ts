import type { AuthUser, Provider } from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';

import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}

  async getSessionUserById(userId: string): Promise<AuthUser | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { oauthTokens: { select: { provider: true } } }
    });

    if (!user) {
      return null;
    }

    return {
      id: user.id,
      email: user.email,
      name: user.name,
      avatarUrl: user.avatarUrl,
      connectedProviders: user.oauthTokens.map((token) => token.provider.toLowerCase() as Provider)
    };
  }

  createCsrfToken(): string {
    return randomBytes(32).toString('hex');
  }
}
