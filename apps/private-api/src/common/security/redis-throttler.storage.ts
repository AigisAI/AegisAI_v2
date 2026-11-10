import { ServiceUnavailableException } from '@nestjs/common';
import type { ThrottlerStorage } from '@nestjs/throttler';
import { createHash } from 'node:crypto';
import { createClient } from 'redis';

import type { ConfigService } from '../../config/config.service';
import type { RuntimeResourcesService } from '../../runtime/runtime-resources.service';

interface Client {
  readonly isReady: boolean;
  sendCommand(args: ReadonlyArray<string>, options: { timeout: number }): Promise<unknown>;
}
type Record = Awaited<ReturnType<ThrottlerStorage['increment']>>;

// Server time and a single atomic script preserve sliding hit expiry/blocking
// across replicas. Blocked retries neither extend the block nor grow the log.
const INCREMENT = `
local t=redis.call('TIME')
local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
local ttl,limit,duration=tonumber(ARGV[1]),tonumber(ARGV[2]),tonumber(ARGV[3])
local blocked=tonumber(redis.call('HGET',KEYS[2],'blocked') or '0')
redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',now-ttl)
local hits=redis.call('ZCARD',KEYS[1])
local first=redis.call('ZRANGE',KEYS[1],0,0,'WITHSCORES')
local expires=0
if first[2] then expires=math.max(0,math.ceil((tonumber(first[2])+ttl-now)/1000)) end
if blocked>now then return {hits,expires,1,math.ceil((blocked-now)/1000)} end
if blocked>0 then redis.call('DEL',KEYS[1],KEYS[2]) end
local seq=redis.call('HINCRBY',KEYS[2],'seq',1)
redis.call('ZADD',KEYS[1],now,tostring(seq))
hits=redis.call('ZCARD',KEYS[1])
first=redis.call('ZRANGE',KEYS[1],0,0,'WITHSCORES')
expires=math.max(0,math.ceil((tonumber(first[2])+ttl-now)/1000))
blocked=0
if hits>limit then blocked=now+duration;redis.call('HSET',KEYS[2],'blocked',blocked) end
redis.call('PEXPIRE',KEYS[1],ttl)
redis.call('PEXPIRE',KEYS[2],math.max(ttl,duration))
if blocked>now then return {hits,expires,1,math.ceil((blocked-now)/1000)} end
return {hits,expires,0,0}
`;

function unavailable(): ServiceUnavailableException {
  return new ServiceUnavailableException({ errorCode: 'THROTTLE_STORE_UNAVAILABLE', message: 'Request limits are temporarily unavailable.' });
}

export class RedisThrottlerStorage implements ThrottlerStorage {
  constructor(private readonly client: Client) {}

  async increment(key: string, ttl: number, limit: number, blockDuration: number, throttlerName: string): Promise<Record> {
    try {
      if (!this.client.isReady || key.length > 4096 || throttlerName.length > 128 ||
          ![ttl, limit, blockDuration].every(Number.isSafeInteger) || ttl < 1 || ttl > 3_600_000 ||
          limit < 1 || limit > 10_000 || blockDuration < 1 || blockDuration > 3_600_000) throw unavailable();
      const hash = createHash('sha256').update(throttlerName + ':' + key).digest('hex');
      const base = 'aegisai:throttle:v1:{' + hash + '}';
      const reply = await this.client.sendCommand(['EVAL', INCREMENT, '2', base + ':hits', base + ':state',
        String(ttl), String(limit), String(blockDuration)], { timeout: 1500 });
      if (!Array.isArray(reply) || reply.length !== 4) throw unavailable();
      const values = reply.map(Number);
      if (!values.every(value => Number.isSafeInteger(value) && value >= 0) ||
          values[0] > limit + 1 || ![0, 1].includes(values[2])) throw unavailable();
      return { totalHits: values[0], timeToExpire: values[1], isBlocked: values[2] === 1, timeToBlockExpire: values[3] };
    } catch { throw unavailable(); }
  }
}

export async function createRuntimeThrottleStorage(config: ConfigService, resources: RuntimeResourcesService): Promise<ThrottlerStorage | undefined> {
  if (config.isTest()) return undefined;
  const client = createClient({ url: config.get('REDIS_URL'), disableOfflineQueue: true, commandsQueueMaxLength: 128,
    socket: { connectTimeout: 3000, reconnectStrategy: retries => Math.min(1000, 100 * (retries + 1)) } });
  client.on('error', () => undefined); // Never log Redis URLs or authentication details.
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([client.connect(), new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(unavailable()), 5000);
    })]);
  } catch {
    if (client.isOpen) client.destroy();
    throw unavailable();
  } finally { if (timer) clearTimeout(timer); }
  resources.registerShutdownCallback(async () => { if (client.isOpen) await client.quit(); });
  return new RedisThrottlerStorage(client);
}
