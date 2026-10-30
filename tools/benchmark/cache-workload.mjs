// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { checkServerIdentity } from 'node:tls';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { createClient } from 'redis';
import { Ajv } from 'ajv';

export const cacheKeys = Object.freeze(['entry', 'expiring', 'corrupt', 'roundtrip']);
export function cacheConnection(fixture) {
  const url = new URL(fixture.url);
  assert.equal(url.protocol, 'rediss:');
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
  assert.ok(url.port && url.username && url.password);
  assert.ok(url.searchParams.get('sslca')?.startsWith('/'));
  assert.match(fixture.namespace, /^cache-comparison:[a-f0-9]{32}:$/);
  const prefix = url.searchParams.get('prefix') ?? '';
  assert.match(prefix, /^[A-Za-z0-9:_-]*$/);
  return { url, prefix: prefix + fixture.namespace };
}

/** The valid-corpus baseline checks the native versioned JSON envelope, without wrapper traversal policy. */
export async function nativeCache(fixture) {
  const { url, prefix } = cacheConnection(fixture);
  const client = createClient({
    username: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: Number(url.pathname.slice(1) || '0'),
    socket: {
      host: url.hostname,
      port: Number(url.port),
      tls: true,
      rejectUnauthorized: true,
      ...(url.hostname === 'localhost' ? { servername: url.hostname } : {}),
      minVersion: 'TLSv1.2',
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
  const validate = new Ajv({ strict: true }).compile({
    type: 'object',
    required: ['schemaVersion', 'value'],
    additionalProperties: false,
    properties: { schemaVersion: { const: 1 }, value: {} },
  });
  try {
    await client.connect();
  } catch {
    client.destroy();
    throw new Error('The owned Redis comparison connection failed');
  }
  const cache = {
    async get(key) {
      const raw = await client.get(prefix + key);
      if (raw === null) return null;
      const envelope = JSON.parse(raw);
      assert.equal(validate(envelope), true);
      return envelope.value;
    },
    async set(key, value, options = {}) {
      const envelope = { schemaVersion: 1, value };
      assert.equal(validate(envelope), true);
      await client.set(prefix + key, JSON.stringify(envelope), {
        expiration: { type: 'PX', value: options.ttlMs ?? 30000 },
      });
    },
    delete: async (key) => (await client.del(prefix + key)) > 0,
  };
  return {
    cache,
    inspect: () => client,
    physical: (key) => prefix + key,
    async close() {
      try {
        await client.del(cacheKeys.map((key) => prefix + key));
      } finally {
        await client.close();
      }
    },
  };
}

export async function verifyCache(service, fixture) {
  const { cache, physical } = service;
  const inspector = service.inspect();
  const value = { marker: fixture.marker, data: [1, true, null] };
  assert.equal(await cache.get('entry'), null);
  await cache.set('entry', value);
  assert.deepEqual(JSON.parse(await inspector.get(physical('entry'))), { schemaVersion: 1, value });
  const ttl = await inspector.pTTL(physical('entry'));
  assert.ok(ttl > 0 && ttl <= 30000);
  const first = await cache.get('entry');
  assert.deepEqual(first, value);
  first.data[0] = 9;
  assert.deepEqual(await cache.get('entry'), value);
  assert.equal(await cache.delete('entry'), true);
  assert.equal(await cache.delete('entry'), false);
  assert.equal(await cache.get('entry'), null);
  const corrupt = JSON.stringify({ schemaVersion: 2, value });
  await inspector.set(physical('corrupt'), corrupt, { expiration: { type: 'PX', value: 30000 } });
  await assert.rejects(cache.get('corrupt'));
  assert.equal(await inspector.get(physical('corrupt')), corrupt);
  await inspector.del(physical('corrupt'));
  await cache.set('expiring', value, { ttlMs: 25 });
  const deadline = performance.now() + 3000;
  while ((await cache.get('expiring')) !== null) {
    assert.ok(performance.now() < deadline, 'The actual Redis cache entry did not expire');
    await delay(5);
  }
  assert.equal(await inspector.get(physical('expiring')), null);
  return {
    actualEnvelopeVerified: true,
    actualTtlVerified: true,
    expiredEntryAbsent: true,
    corruptEntryRejectedAndPreserved: true,
    deletionOutcomes: [true, false],
  };
}

export function cacheWorkload(service, fixture) {
  const value = { marker: fixture.marker, data: [1, true, null] };
  return {
    roundtrip: async () => {
      await service.cache.set('roundtrip', value);
      assert.deepEqual(await service.cache.get('roundtrip'), value);
      assert.equal(await service.cache.delete('roundtrip'), true);
    },
  };
}
