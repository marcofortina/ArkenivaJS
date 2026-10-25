// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { RedisClientType } from 'redis';
import { createApplication } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { redisPlugin } from '@arkenivajs/database-redis';
import { cachePlugin } from '@arkenivajs/cache';

async function fixture(context: TestContext, selected?: { namespace: string; plugin: Plugin }) {
  assert.equal(
    process.env.ARKENIVA_REDIS_DISPOSABLE,
    '1',
    'Only a dedicated disposable Redis fixture is permitted',
  );
  assert.ok(process.env.ARKENIVA_REDIS_URL);
  const namespace = selected?.namespace ?? 'cache-test:' + randomBytes(12).toString('hex') + ':',
    app = await createApplication({
      service: { name: 'cache-native-contract', version: '1.0.0', environment: 'test' },
      plugins: [redisPlugin(), selected?.plugin ?? cachePlugin({ namespace })],
      databases: { values: { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_URL' } },
    });
  await app.start();
  const native = app.redis!.native() as RedisClientType,
    cleanup = native.duplicate(),
    keys = new Set<string>(),
    prefix = new URL(process.env.ARKENIVA_REDIS_URL).searchParams.get('prefix') ?? '';
  context.after(async () => {
    try {
      if (keys.size) {
        await cleanup.connect();
        await cleanup.del([...keys].map((key) => prefix + namespace + key));
      }
    } finally {
      try {
        if (cleanup.isOpen) await cleanup.close();
      } finally {
        await app.stop();
      }
    }
  });
  return {
    app,
    cache: app.cache!,
    native,
    namespace,
    physical: (key: string) => prefix + namespace + key,
    key(value = 'entry') {
      keys.add(value);
      return value;
    },
  };
}

test('Real Redis cache verifies finite default TTL, checked JSON storage, mutation isolation and actual deletion counts', async (context) => {
  const f = await fixture(context),
    key = f.key();
  assert.equal(await f.cache.get(key), null);
  const value = { name: 'Ada', nested: { enabled: true } },
    writing = f.cache.set(key, value);
  value.nested.enabled = false;
  await writing;
  const ttl = await f.native.pTTL(f.physical(key));
  assert.ok(ttl > 20000 && ttl <= 30000);
  assert.deepEqual(JSON.parse((await f.native.get(f.physical(key)))!), {
    schemaVersion: 1,
    value: { name: 'Ada', nested: { enabled: true } },
  });
  const read = await f.cache.get<typeof value>(key);
  assert.deepEqual(read, { name: 'Ada', nested: { enabled: true } });
  read!.name = 'Changed';
  assert.equal((await f.cache.get<typeof value>(key))!.name, 'Ada');
  assert.equal(await f.cache.delete(key), true);
  assert.equal(await f.cache.delete(key), false);
  assert.equal(await f.cache.get(key), null);
});

test('Real Redis cache expiration uses positive millisecond TTL and never returns an expired value', async (context) => {
  const f = await fixture(context),
    key = f.key();
  await f.cache.set(key, { state: 'active' }, { ttlMs: 3000 });
  assert.ok((await f.native.pTTL(f.physical(key))) > 0);
  assert.ok((await f.native.pTTL(f.physical(key))) <= 3000);
  await f.cache.set(key, { state: 'short' }, { ttlMs: 50 });
  const deadline = performance.now() + 3000;
  while ((await f.cache.get(key)) !== null) {
    assert.ok(performance.now() < deadline, 'The server did not expire the cache value');
    await delay(5);
  }
  assert.equal(await f.native.get(f.physical(key)), null);
});

test('Real Redis cache surfaces stored schema corruption without evicting data or silently falling back', async (context) => {
  const f = await fixture(context),
    key = f.key();
  const corrupt = '{"schemaVersion":2,"value":"private-corrupt-data"}';
  await f.app.redis!.set(f.namespace + key, corrupt, { ttlMs: 30000 });
  await assert.rejects(f.cache.get(key), { code: 'EK_BACKEND_UNAVAILABLE' });
  assert.equal(await f.app.redis!.get(f.namespace + key), corrupt);
  await assert.rejects(f.cache.set(key, { unsupported: 1n }), { code: 'EK_CONFIG_INVALID' });
  assert.equal(await f.app.redis!.get(f.namespace + key), corrupt);
});

test('Reusable Redis cache plugin factories keep application clients and draining facades isolated', async (context) => {
  const namespace = 'cache-reuse:' + randomBytes(12).toString('hex') + ':',
    plugin = cachePlugin({ namespace }),
    a = await fixture(context, { namespace, plugin }),
    b = await fixture(context, { namespace, plugin }),
    key = a.key();
  b.key(key);
  assert.notEqual(a.native, b.native);
  assert.notEqual(a.cache, b.cache);
  await a.cache.set(key, { name: 'shared-backend' });
  await a.app.stop();
  await assert.rejects(a.cache.get(key), { code: 'EK_RESOURCE_CLOSED' });
  assert.deepEqual(await b.cache.get(key), { name: 'shared-backend' });
});
