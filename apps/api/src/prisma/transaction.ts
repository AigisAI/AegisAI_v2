import { Prisma } from "@prisma/client";

import { PrismaService } from "./prisma.service";

export async function serializable<T>(
  prisma: PrismaService,
  operation: (transaction: Prisma.TransactionClient) => Promise<T>
): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await prisma.$transaction(operation, {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable
      });
    } catch (error) {
      const retryable = error instanceof Prisma.PrismaClientKnownRequestError
        && (error.code === "P2034" || error.code === "P2002");
      if (!retryable || attempt >= 4) throw error;
      await new Promise((resolve) => setTimeout(resolve, 10 * 2 ** attempt));
    }
  }
}
