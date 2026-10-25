// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication, KitError } from '@arkenivajs/core';
import { copyData } from '@arkenivajs/core/support';
import { redisPlugin } from '@arkenivajs/database-redis';
import { cachePlugin } from '@arkenivajs/cache';

/** The application validates its business shape and explicitly projects public JSON fields. */
export function customerDTO(input: unknown) {
  const value = copyData(input);
  if (
    !value ||
    typeof value !== 'object' ||
    !('id' in value) ||
    !('name' in value) ||
    typeof value.id !== 'string' ||
    typeof value.name !== 'string'
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Cached customer requires string identity and name',
    });
  return Object.freeze({ id: value.id, name: value.name });
}

/** Use randomly owned keys on an explicitly disposable authenticated Redis endpoint. */
export async function runCacheExample() {
  if (process.env.ARKENIVA_REDIS_DISPOSABLE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The cache example requires an explicitly disposable Redis server',
    });
  if (!process.env.ARKENIVA_REDIS_URL)
    throw new KitError({ code: 'EK_CONFIG_MISSING', message: 'ARKENIVA_REDIS_URL is required' });
  const namespace = 'cache-example:' + randomBytes(12).toString('hex') + ':',
    app = await createApplication({
      service: { name: 'cache-customer-example', version: '1.0.0', environment: 'development' },
      plugins: [redisPlugin(), cachePlugin({ namespace })],
      databases: { values: { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_URL' } },
    });
  let ready = false,
    result:
      | (ReturnType<typeof customerDTO> & {
          removed: boolean;
          removedAgain: boolean;
          expired: boolean;
        })
      | undefined;
  const failures: unknown[] = [];
  try {
    await app.start();
    ready = true;
    const cache = app.cache!;
    await cache.set(
      'customer',
      { id: 'customer-42', name: 'Ada', internal: 'private' },
      { ttlMs: 30000 },
    );
    const customer = customerDTO(await cache.get('customer')),
      removed = await cache.delete('customer'),
      removedAgain = await cache.delete('customer');
    assert.equal(removed, true);
    assert.equal(removedAgain, false);
    await cache.set('presence', { state: 'active' }, { ttlMs: 30 });
    const deadline = performance.now() + 3000;
    while ((await cache.get('presence')) !== null) {
      assert.ok(performance.now() < deadline, 'The server did not expire the example value');
      await delay(5);
    }
    result = { ...customer, removed, removedAgain, expired: true };
  } catch (cause) {
    failures.push(cause);
  } finally {
    try {
      if (ready) await app.redis!.del([namespace + 'customer', namespace + 'presence']);
    } catch (cause) {
      failures.push(cause);
    } finally {
      try {
        await app.stop();
      } catch (cause) {
        failures.push(cause);
      }
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(failures, 'The cache example and cleanup failed');
  assert.ok(result);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(await runCacheExample()));
  } catch (cause) {
    console.error(
      JSON.stringify(
        cause instanceof KitError
          ? cause.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The cache example failed' },
      ),
    );
    process.exitCode = 1;
  }
}
