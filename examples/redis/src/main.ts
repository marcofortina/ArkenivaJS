// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { setTimeout } from 'node:timers/promises';
import { createApplication, KitError } from '@arkenivajs/core';
import type { RedisProvider } from '@arkenivajs/core';
import { redisPlugin } from '@arkenivajs/database-redis';

/** Store a short-lived JSON cache entry only when absent; preserve the native NX outcome. */
export async function cacheOrder(redis: Pick<RedisProvider, 'set' | 'get'>, key: string) {
  const accepted = await redis.set(key, JSON.stringify({ id: '42', total: '5.25' }), {
    ttlMs: 5000,
    onlyIfAbsent: true,
  });
  const value = await redis.get(key);
  return Object.freeze({ accepted, value });
}

/** Exercise only randomly owned keys on an explicitly disposable Redis endpoint. */
export async function runRedisCacheExample() {
  if (process.env.ARKENIVA_REDIS_DISPOSABLE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The Redis example requires an explicitly disposable server',
    });
  if (!process.env.ARKENIVA_REDIS_URL)
    throw new KitError({ code: 'EK_CONFIG_MISSING', message: 'ARKENIVA_REDIS_URL is required' });
  const app = await createApplication({
    service: { name: 'redis-cache-example', version: '1.0.0', environment: 'development' },
    plugins: [redisPlugin()],
    databases: { cache: { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_URL' } },
  });
  const base = 'example:' + randomBytes(12).toString('hex') + ':',
    keys = [base + 'order', base + 'counter', base + 'expiry'];
  let ready = false;
  try {
    await app.start();
    ready = true;
    const redis = app.redis!;
    assert.equal(await redis.get(keys[0]!), null);
    const first = await cacheOrder(redis, keys[0]!);
    const second = await cacheOrder(redis, keys[0]!);
    assert.equal(first.accepted, true);
    assert.equal(second.accepted, false);
    assert.equal(second.value, first.value);
    assert.deepEqual(JSON.parse(first.value!), { id: '42', total: '5.25' });
    assert.equal(await redis.increment(keys[1]!), 1);
    assert.equal(await redis.increment(keys[1]!, 2), 3);
    assert.equal(await redis.set(keys[2]!, 'temporary', { ttlMs: 200 }), true);
    const deadline = performance.now() + 3000;
    while (await redis.get(keys[2]!)) {
      if (performance.now() >= deadline)
        throw new Error('Redis TTL did not expire within the example budget');
      await setTimeout(25);
    }
    const deleted = await redis.del(keys);
    assert.equal(deleted, 2);
    assert.equal(await redis.del([]), 0);
    return {
      firstAccepted: first.accepted,
      secondAccepted: second.accepted,
      order: JSON.parse(first.value!) as { id: string; total: string },
      counter: 3,
      expired: true,
      deleted,
    };
  } finally {
    try {
      if (ready) await app.redis!.del(keys);
    } finally {
      await app.stop();
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(await runRedisCacheExample()));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The Redis example failed' },
      ),
    );
    process.exitCode = 1;
  }
}
