import type { AuthUser, Provider } from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { RepoProvider } from '@prisma/client';
import { randomBytes } from 'node:crypto';

import { PrismaService } from '../prisma/prisma.service';
import { TokenCryptoUtil } from './utils/token-crypto.util';
import type { OAuthProviderProfile } from './oauth-profile.types';

interface NormalizedProviderProfile {
  provider: RepoProvider;
  providerUserId: string;
  email: string | null;
  name: string;
  avatarUrl: string | null;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenCrypto: TokenCryptoUtil
  ) {}

  async findOrCreateUser(
    provider: Provider,
    profile: OAuthProviderProfile,
    accessToken: string,
    refreshToken?: string
  ): Promise<AuthUser> {
    const normalizedProfile = this.normalizeProviderProfile(provider, profile);
    const existingToken = await this.prisma.oAuthToken.findUnique({
      where: {
        provider_providerUserId: {
          provider: normalizedProfile.provider,
          providerUserId: normalizedProfile.providerUserId
        }
      }
    });

    let userId: string;

    if (existingToken) {
      const user = await this.prisma.user.update({
        where: { id: existingToken.userId },
        data: {
          email: normalizedProfile.email,
          name: normalizedProfile.name,
          avatarUrl: normalizedProfile.avatarUrl
        }
      });

      userId = user.id;
    } else {
      const existingUser = normalizedProfile.email
        ? await this.prisma.user.findUnique({
            where: { email: normalizedProfile.email },
            include: { oauthTokens: { select: { provider: true } } }
          })
        : null;

      if (existingUser) {
        const user = await this.prisma.user.update({
          where: { id: existingUser.id },
          data: {
            email: normalizedProfile.email,
            name: normalizedProfile.name,
            avatarUrl: normalizedProfile.avatarUrl
          }
        });

        userId = user.id;
      } else {
        const user = await this.prisma.user.create({
          data: {
            email: normalizedProfile.email,
            name: normalizedProfile.name,
            avatarUrl: normalizedProfile.avatarUrl
          }
        });

        userId = user.id;
      }
    }

    const encryptedAccessToken = this.tokenCrypto.encrypt(accessToken);
    const encryptedRefreshToken = refreshToken ? this.tokenCrypto.encrypt(refreshToken) : null;

    await this.prisma.oAuthToken.upsert({
      where: {
        provider_providerUserId: {
          provider: normalizedProfile.provider,
          providerUserId: normalizedProfile.providerUserId
        }
      },
      update: {
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
        expiresAt: null
      },
      create: {
        userId,
        provider: normalizedProfile.provider,
        providerUserId: normalizedProfile.providerUserId,
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
        expiresAt: null
      }
    });

    const sessionUser = await this.getSessionUserById(userId);

    if (!sessionUser) {
      throw new Error('Authenticated user could not be loaded after provider login');
    }

    return sessionUser;
  }

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

  private normalizeProviderProfile(
    provider: Provider,
    profile: OAuthProviderProfile
  ): NormalizedProviderProfile {
    if (provider === 'github') {
      return {
        provider: RepoProvider.GITHUB,
        providerUserId: String(profile.id),
        email: profile.emails?.[0]?.value ?? null,
        name: profile.displayName ?? profile.username ?? `github-${String(profile.id)}`,
        avatarUrl: 'photos' in profile ? profile.photos?.[0]?.value ?? null : null
      };
    }

    return {
      provider: RepoProvider.GITLAB,
      providerUserId: String(profile.id),
      email: profile.emails?.[0]?.value ?? null,
      name: profile.displayName ?? profile.username ?? `gitlab-${String(profile.id)}`,
      avatarUrl: 'avatarUrl' in profile ? profile.avatarUrl ?? null : null
    };
  }
}
