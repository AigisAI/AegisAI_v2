import { createHash } from 'node:crypto';

import { Prisma } from '@prisma/client';

export const SAST_KILL_SWITCH_SERIALIZABLE_RETRIES = 3;
export const SAST_KILL_SWITCH_SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000;
export const SAST_KILL_SWITCH_SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000;

interface SerializableTransactionClient {
  $transaction<T>(
    operation: (tx: Prisma.TransactionClient) => Promise<T>,
    options: {
      isolationLevel: Prisma.TransactionIsolationLevel;
      maxWait: number;
      timeout: number;
    }
  ): Promise<T>;
}

export async function runSastKillSwitchSerializable<T>(
  client: SerializableTransactionClient,
  operation: (tx: Prisma.TransactionClient) => Promise<T>
): Promise<T> {
  for (
    let attempt = 1;
    attempt <= SAST_KILL_SWITCH_SERIALIZABLE_RETRIES;
    attempt += 1
  ) {
    try {
      return await client.$transaction(operation, {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
        maxWait: SAST_KILL_SWITCH_SERIALIZABLE_MAX_WAIT_MILLISECONDS,
        timeout: SAST_KILL_SWITCH_SERIALIZABLE_TIMEOUT_MILLISECONDS
      });
    } catch (error) {
      if (
        !isSastKillSwitchSerializableConflict(error) ||
        attempt === SAST_KILL_SWITCH_SERIALIZABLE_RETRIES
      ) {
        throw error;
      }
      await new Promise((resolve) =>
        setTimeout(resolve, 20 * attempt + Math.floor(Math.random() * 20))
      );
    }
  }
  throw new Error('SAST kill-switch serializable retry budget was exhausted.');
}

export function isSastKillSwitchSerializableConflict(
  error: unknown
): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2034'
  );
}

export function digestSastKillSwitchValue(
  value: string
): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

export function asSastKillSwitchDigest(
  value: string,
  invalid: () => Error
): `sha256:${string}` {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value)) throw invalid();
  return value as `sha256:${string}`;
}
