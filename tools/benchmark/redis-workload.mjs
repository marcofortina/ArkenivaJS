// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { checkServerIdentity } from 'node:tls';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { createClient } from 'redis';

export const redisKeys = ['entry', 'counter', 'expiring', 'roundtrip'];
export function redisConnection(fixture) {
  const url = new URL(fixture.url);
  assert.equal(url.protocol, 'rediss:');
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
  assert.ok(
    url.port && url.username && url.password && url.searchParams.get('sslca')?.startsWith('/'),
  );
  assert.match(fixture.namespace, /^redis-comparison:[a-f0-9]{32}:$/);
  const prefix = url.searchParams.get('prefix') ?? '';
  assert.match(prefix, /^[A-Za-z0-9:_-]*$/);
  return { url, prefix };
}

export async function cleanupRedis(service, fixture) {
  await service.inspect().del(redisKeys.map((name) => service.physical(fixture.namespace + name)));
}

/** Direct native commands on small valid UTF8 values and safely bounded counter operands. */
export async function nativeRedis(fixture) {
  const { url, prefix } = redisConnection(fixture);
  const client = createClient({
    username: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: Number(url.pathname.slice(1) || '0'),
    socket: {
      host: url.hostname,
      port: Number(url.port),
      tls: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
      ...(url.hostname === 'localhost' ? { servername: url.hostname } : {}),
      ca: await readFile(url.searchParams.get('sslca')),
      checkServerIdentity: (_name, certificate) => checkServerIdentity(url.hostname, certificate),
      connectTimeout: 5000,
      reconnectStrategy: false,
    },
    disableOfflineQueue: true,
    commandsQueueMaxLength: 128,
    maintNotifications: 'disabled',
    disableClientInfo: true,
  });
  client.on('error', () => undefined);
  try {
    await client.connect();
  } catch {
    if (client.isOpen) client.destroy();
    throw new Error('The owned native Redis comparison connection failed');
  }
  const service = {
    inspect: () => client,
    physical: (key) => prefix + key,
    workloadCalls: 0,
    redis: {
      get: (key) => client.get(prefix + key),
      set: async (key, value, options = {}) =>
        (await client.set(prefix + key, value, {
          ...(options.ttlMs ? { expiration: { type: 'PX', value: options.ttlMs } } : {}),
          ...(options.onlyIfAbsent ? { condition: 'NX' } : {}),
        })) === 'OK',
      increment: (key, amount = 1) => client.incrBy(prefix + key, amount),
      del: (keys) =>
        keys.length ? client.del(keys.map((key) => prefix + key)) : Promise.resolve(0),
      publish: (channel, message) => client.publish(prefix + channel, message),
    },
    async close() {
      try {
        await cleanupRedis(service, fixture);
      } finally {
        await client.close();
      }
    },
  };
  return service;
}

export async function verifyRedis(service, fixture) {
  const key = (name) => fixture.namespace + name,
    redis = service.redis,
    inspector = service.inspect();
  assert.equal(await redis.get(key('entry')), null);
  assert.equal(
    await redis.set(key('entry'), '\ufeff' + fixture.marker, { ttlMs: 30000, onlyIfAbsent: true }),
    true,
  );
  assert.equal(await redis.set(key('entry'), 'replacement', { onlyIfAbsent: true }), false);
  assert.equal(await redis.get(key('entry')), '\ufeff' + fixture.marker);
  assert.equal(await inspector.get(service.physical(key('entry'))), '\ufeff' + fixture.marker);
  const ttl = await inspector.pTTL(service.physical(key('entry')));
  assert.ok(ttl > 0 && ttl <= 30000);
  assert.equal(await redis.increment(key('counter'), 2), 2);
  assert.equal(await redis.increment(key('counter'), -1), 1);
  assert.equal(await inspector.get(service.physical(key('counter'))), '1');
  const subscriber = inspector.duplicate();
  let timer;
  subscriber.on('error', () => undefined);
  try {
    await subscriber.connect();
    let done;
    const message = new Promise((resolve, reject) => {
      done = resolve;
      timer = setTimeout(
        () => reject(new Error('The actual Redis message was not observed')),
        3000,
      );
    });
    void message.catch(() => undefined);
    await subscriber.subscribe(service.physical(key('events')), (value) => done(value));
    assert.equal(await redis.publish(key('events'), fixture.marker), 1);
    assert.equal(await message, fixture.marker);
    await subscriber.unsubscribe(service.physical(key('events')));
  } finally {
    clearTimeout(timer);
    if (subscriber.isOpen) await subscriber.close();
  }
  assert.equal(await redis.del([key('entry'), key('counter')]), 2);
  assert.equal(await redis.del([key('entry'), key('counter')]), 0);
  assert.equal(await redis.del([]), 0);
  assert.equal(await redis.set(key('expiring'), fixture.marker, { ttlMs: 25 }), true);
  const deadline = performance.now() + 3000;
  while ((await redis.get(key('expiring'))) !== null) {
    assert.ok(performance.now() < deadline, 'The actual Redis entry did not expire');
    await delay(5);
  }
  assert.equal(await inspector.get(service.physical(key('expiring'))), null);
  assert.equal(await redis.set(key('counter'), '0', { ttlMs: 30000 }), true);
  return {
    utf8AndBomPreserved: true,
    nxOutcomes: [true, false],
    nativeTtlAndExpiryVerified: true,
    counterStateVerified: true,
    deleteCounts: [2, 0],
    actualSubscriberObserved: true,
  };
}

export function redisWorkload(service, fixture) {
  return {
    roundtrip: async () => {
      const key = fixture.namespace + 'roundtrip';
      assert.equal(await service.redis.set(key, fixture.marker, { ttlMs: 30000 }), true);
      assert.equal(await service.redis.get(key), fixture.marker);
      assert.equal(
        await service.redis.increment(fixture.namespace + 'counter', 1),
        service.workloadCalls + 1,
      );
      assert.equal(await service.redis.del([key]), 1);
      service.workloadCalls++;
    },
  };
}

export async function completeRedis(service, { fixture, measure }) {
  const value = await service.inspect().get(service.physical(fixture.namespace + 'counter'));
  assert.equal(value, String(service.workloadCalls));
  assert.ok(measure ? service.workloadCalls >= 100 : service.workloadCalls === 0);
  return { acknowledgedRoundtrips: service.workloadCalls, nativeCounterVerified: true };
}
