import { ForbiddenException, Injectable } from "@nestjs/common";

import { PrismaService } from "../prisma/prisma.service";
import { serializable } from "../prisma/transaction";
import type { AuthenticatedPrincipal } from "./auth.types";

@Injectable()
export class IdentityStoreService {
  constructor(private readonly prisma: PrismaService) {}

  async persist(principal: AuthenticatedPrincipal): Promise<void> {
    await serializable(this.prisma, async (tx) => {
      const tenant = await tx.tenant.upsert({
        where: { id: principal.tenantId }, update: {},
        create: { id: principal.tenantId, slug: principal.tenantId, name: principal.name }
      });
      if (tenant.status !== "ACTIVE") throw new ForbiddenException("Tenant is suspended");
      await tx.user.upsert({
        where: { id: principal.userId },
        create: {
          id: principal.userId, email: principal.email, name: principal.name,
          avatarUrl: principal.avatarUrl
        },
        update: { email: principal.email, name: principal.name, avatarUrl: principal.avatarUrl ?? null }
      });
      await tx.userOAuthIdentity.upsert({
        where: { provider_providerUserId: {
          provider: principal.provider, providerUserId: principal.providerUserId
        } },
        create: {
          userId: principal.userId, provider: principal.provider,
          providerUserId: principal.providerUserId
        }, update: {}
      });
    });
  }
}
