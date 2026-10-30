// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { AsyncLocalStorage } from 'node:async_hooks';
import { KitError } from '@arkenivajs/core';
import type { Telemetry, Logger, TenantId, VerifiedTenantContext } from '@arkenivajs/core';
import { createRedisCache, tenantCache, cachePlugin } from '@arkenivajs/cache';
import { cacheSerializer } from '../../dist/json.js';
import { redisPortDouble } from '../fixtures/redis-port-double.js';

test('Redis cache snapshots versioned JSON, applies a finite default TTL and reports actual hit/miss/deletion semantics', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis),
    value = { name: 'Ada' };
  try {
    const writing = cache.set('customer', value);
    value.name = 'Changed';
    await writing;
    assert.equal(f.state.calls[0]!.key, 'cache:v1:customer');
    assert.equal(f.state.calls[0]!.options?.ttlMs, 30000);
    assert.deepEqual(JSON.parse(f.state.calls[0]!.value!), {
      schemaVersion: 1,
      value: { name: 'Ada' },
    });
    assert.equal(await cache.get('customer'), null);
    f.state.value = f.state.calls[0]!.value!;
    assert.deepEqual(await cache.get('customer'), { name: 'Ada' });
    assert.equal(await cache.delete('customer'), true);
    f.state.removed = 0;
    assert.equal(await cache.delete('customer'), false);
    assert.equal(cache.stats().operations, 5);
  } finally {
    await cache.close();
  }
});

test('Redis cache validates budgets, keys, TTL and policy before any backend call and captures mutable caller options', async () => {
  const f = redisPortDouble();
  for (const options of [
    { namespace: '' },
    { namespace: 'bad\n' },
    { defaultTtlMs: 0 },
    { defaultTtlMs: NaN },
  ])
    assert.throws(() => createRedisCache(f.redis, options), { code: 'EK_CONFIG_INVALID' });
  assert.throws(() => createRedisCache({} as never), { code: 'EK_CONFIG_INVALID' });
  assert.throws(() => cachePlugin({ unknown: true } as never), { code: 'EK_CONFIG_INVALID' });
  const cache = createRedisCache(f.redis);
  try {
    for (const key of ['', 'x\0', 'x\r', 'x\n', '\ud800', 'x'.repeat(2049), 42 as never])
      await assert.rejects(cache.get(key), { code: 'EK_CONFIG_INVALID' });
    for (const ttlMs of [0, -1, 1.5, Infinity, null as never])
      await assert.rejects(cache.set('key', {}, { ttlMs }), { code: 'EK_CONFIG_INVALID' });
    for (const timeoutMs of [0, -1, 1.5, NaN])
      await assert.rejects(cache.get('key', { timeoutMs }), { code: 'EK_CONFIG_INVALID' });
    await assert.rejects(cache.get('key', { signal: {} as never }), { code: 'EK_CONFIG_INVALID' });
    assert.equal(f.state.calls.length, 0);
    const options = { ttlMs: 42, timeoutMs: 1000 },
      writing = cache.set('key', { name: 'Ada' }, options);
    options.ttlMs = 0;
    options.timeoutMs = 0;
    await writing;
    assert.equal(f.state.calls[0]!.options?.ttlMs, 42);
    assert.ok(f.state.calls[0]!.options!.timeoutMs! > 0);
    assert.ok(f.state.calls[0]!.options!.timeoutMs! <= 1000);
  } finally {
    await cache.close();
  }
});

test('Redis cache requires explicit factory opt-in for non-expiring entries and supports positive per-call overrides', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis, { namespace: 'shared:', defaultTtlMs: null });
  try {
    await cache.set('one', null);
    await cache.set('two', false, { ttlMs: 1 });
    assert.equal(f.state.calls[0]!.options?.ttlMs, undefined);
    assert.equal(f.state.calls[1]!.options?.ttlMs, 1);
    assert.equal(f.state.calls[0]!.key, 'shared:one');
  } finally {
    await cache.close();
  }
});

test('Redis cache rejects unknown, non-data and accessor options without invoking them or a backend', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis);
  let invoked = 0;
  const getters = Object.defineProperty({}, 'ttlMs', {
    enumerable: true,
    get() {
      invoked++;
      return 0;
    },
  });
  try {
    for (const options of [
      null,
      [],
      new Date(),
      { unexpected: true },
      { timeoutMs: null },
      { [Symbol('private')]: 1 },
      getters,
    ]) {
      await assert.rejects(cache.get('key', options as never), { code: 'EK_CONFIG_INVALID' });
      await assert.rejects(cache.set('key', {}, options as never), { code: 'EK_CONFIG_INVALID' });
    }
    assert.equal(invoked, 0);
    assert.equal(f.state.calls.length, 0);
  } finally {
    await cache.close();
  }
});

test('Redis cache prevents a delayed tracing callback from submitting work after public cancellation', async () => {
  const f = redisPortDouble(),
    controller = new AbortController();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
      release = resolve;
    }),
    telemetry = {
      async withSpan(_name: string, work: () => Promise<unknown>) {
        await gate;
        return work();
      },
      recordHistogram() {},
    } as unknown as Telemetry,
    cache = createRedisCache(f.redis, { telemetry });
  try {
    const operation = cache.get('key', { signal: controller.signal }),
      rejected = assert.rejects(operation, { code: 'EK_ABORTED' });
    controller.abort();
    await rejected;
    release();
    await delay(0);
    assert.equal(f.state.calls.length, 0);
    assert.equal(cache.stats().pending, 0);
  } finally {
    release();
    await cache.close();
  }
});

test('Redis cache does not disguise corrupt data or invalid acknowledgments as misses or success', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis);
  try {
    f.state.value = '{private-corrupt';
    await assert.rejects(cache.get('key'), { code: 'EK_BACKEND_UNAVAILABLE' });
    f.state.accepted = false;
    await assert.rejects(cache.set('key', {}), { code: 'EK_BACKEND_UNAVAILABLE' });
    f.state.removed = 2;
    await assert.rejects(cache.delete('key'), { code: 'EK_BACKEND_UNAVAILABLE' });
    const failure = new KitError({
      code: 'EK_DATABASE_UNAVAILABLE',
      message: 'Native failure',
      details: { outcome: 'unknown' },
    });
    f.state.failure = failure;
    await assert.rejects(cache.set('key', {}), (cause: unknown) => cause === failure);
    f.state.failure = new Error('private-native-text');
    await assert.rejects(
      cache.get('key'),
      (cause: unknown) =>
        cause instanceof KitError &&
        cause.code === 'EK_BACKEND_UNAVAILABLE' &&
        cause.cause === f.state.failure,
    );
    assert.equal(f.state.calls.length, 5);
  } finally {
    await cache.close();
  }
});

test('Redis cache keeps admission reserved after logical write cancellation until the backend promise settles', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis),
    controller = new AbortController();
  let release!: () => void;
  f.state.gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const work = Array.from({ length: 128 }, () =>
      cache.set('key', {}, { signal: controller.signal }),
    ),
    settled = Promise.allSettled(work);
  try {
    await delay(0);
    assert.equal(f.state.calls.length, 128);
    controller.abort();
    const outcomes = await settled;
    assert.ok(
      outcomes.every(
        (outcome) =>
          outcome.status === 'rejected' &&
          outcome.reason instanceof KitError &&
          outcome.reason.details.outcome === 'unknown',
      ),
    );
    assert.equal(cache.stats().pending, 128);
    await assert.rejects(cache.get('another'), { code: 'EK_BACKEND_UNAVAILABLE' });
    release();
    await delay(0);
    assert.equal(cache.stats().pending, 0);
    assert.equal(f.state.calls.length, 128);
  } finally {
    release();
    await cache.close();
  }
});

test('Redis cache performs no backend submission after an early abort and coalesces close without owning Redis', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis),
    controller = new AbortController();
  controller.abort();
  await assert.rejects(cache.get('key', { signal: controller.signal }), { code: 'EK_ABORTED' });
  assert.equal(f.state.calls.length, 0);
  const closing = cache.close();
  assert.equal(closing, cache.close());
  await closing;
  await assert.rejects(cache.get('key'), { code: 'EK_RESOURCE_CLOSED' });
  await assert.rejects(cache.set('key', {}), { code: 'EK_RESOURCE_CLOSED' });
  await assert.rejects(cache.delete('key'), { code: 'EK_RESOURCE_CLOSED' });
  await f.redis.get('still-owned-by-application');
  assert.equal(f.state.calls.length, 1);
});

test('Redis cache timing and native work run under the cache span and failed diagnostics cannot replay or replace an acknowledgment', async () => {
  const f = redisPortDouble(),
    scope = new AsyncLocalStorage<boolean>(),
    histograms: number[] = [];
  const original = f.redis.set.bind(f.redis);
  f.redis.set = async (...args) => {
    assert.equal(scope.getStore(), true);
    return original(...args);
  };
  const telemetry = {
    async withSpan(_name: string, work: () => Promise<unknown>) {
      return scope.run(true, async () => {
        await work();
        throw new Error('Trace export failed');
      });
    },
    recordHistogram(_name: string, value: number) {
      histograms.push(value);
      throw new Error('Metric export failed');
    },
  } as unknown as Telemetry;
  const logger = {
    warn() {
      throw new Error('Log sink failed');
    },
  } as unknown as Logger;
  const cache = createRedisCache(f.redis, { telemetry, logger });
  try {
    await cache.set('private-key', { private: 'document' });
    assert.equal(f.state.calls.length, 1);
    assert.ok(histograms[0]! >= 0 && histograms[0]! < 1);
    assert.ok(cache.stats().observerFailures >= 2);
  } finally {
    await cache.close();
  }
});

test('Redis cache retains established native acceptance when an outer observation wrapper exceeds its deadline', async () => {
  const f = redisPortDouble(),
    telemetry = {
      async withSpan(_name: string, work: () => Promise<unknown>) {
        await work();
        await delay(30);
      },
      recordHistogram() {},
    } as unknown as Telemetry,
    cache = createRedisCache(f.redis, { telemetry });
  try {
    await cache.set('key', {}, { timeoutMs: 10 });
    assert.equal(f.state.calls.length, 1);
  } finally {
    await cache.close();
  }
});

test('Tenant cache binds verified authority, rejects qualified foreign keys and checks revocation before backend access', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis),
    verified = new WeakSet<object>();
  const context = (id: string) =>
    Object.freeze({
      tenantId: id as TenantId,
      identity: Object.freeze({
        subject: 'subject',
        issuer: 'https://issuer.invalid',
        audience: ['test'],
        scopes: [],
        claims: {},
      }),
      verifiedAt: new Date().toISOString(),
      source: 'oidc' as const,
    });
  const a = context('tenant-A'),
    b = context('tenant-B');
  verified.add(a);
  verified.add(b);
  const auth = {
    isVerifiedTenant(value: unknown): value is VerifiedTenantContext {
      return !!value && typeof value === 'object' && verified.has(value);
    },
  };
  try {
    assert.throws(() => tenantCache(cache, auth, { ...a }), { code: 'EK_TENANT_UNVERIFIED' });
    assert.throws(() => tenantCache(cache, {} as never, a), { code: 'EK_TENANT_UNVERIFIED' });
    const cacheA = tenantCache(cache, auth, a),
      cacheB = tenantCache(cache, auth, b);
    await cacheA.set('customer', { name: 'A' });
    await cacheB.set('customer', { name: 'B' });
    assert.notEqual(f.state.calls[0]!.key, f.state.calls[1]!.key);
    const count = f.state.calls.length;
    await assert.rejects(
      cacheA.get('tenant:' + Buffer.from('tenant-B').toString('base64url') + ':customer'),
      { code: 'EK_AUTH_FORBIDDEN' },
    );
    verified.delete(a);
    await assert.rejects(cacheA.get('customer'), { code: 'EK_TENANT_UNVERIFIED' });
    await assert.rejects(cacheA.delete('customer'), { code: 'EK_TENANT_UNVERIFIED' });
    assert.equal(f.state.calls.length, count);
    f.state.value = cacheSerializer().encode({ name: 'B' });
    assert.deepEqual(await cacheB.get('customer'), { name: 'B' });
    assert.equal(await cacheB.delete('customer'), true);
  } finally {
    await cache.close();
  }
});

test('Tenant cache ignores custom binding metadata and never treats malformed evidence as verification', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis),
    tenant = Object.freeze({ tenantId: 'tenant-A' }) as VerifiedTenantContext;
  let binds = 0,
    verified = 0;
  const authority = {
    isVerifiedTenant(value: unknown): value is VerifiedTenantContext {
      assert.equal(this, authority);
      assert.equal(value, tenant);
      verified++;
      return false;
    },
  };
  Object.defineProperty(authority.isVerifiedTenant, 'bind', {
    value: () => {
      binds++;
      return () => true;
    },
  });
  try {
    assert.throws(() => tenantCache(cache, authority, tenant), { code: 'EK_TENANT_UNVERIFIED' });
    assert.equal(verified, 1);
    assert.equal(binds, 0);
    for (const result of [1, 'verified', {}, Promise.resolve(false)]) {
      assert.throws(
        () => tenantCache(cache, { isVerifiedTenant: (() => result) as never }, tenant),
        { code: 'EK_TENANT_UNVERIFIED' },
      );
    }
    assert.equal(f.state.calls.length, 0);
  } finally {
    await cache.close();
  }
});

test('Tenant cache retains inherited authority methods and rejects executable metadata before backend work', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis),
    tenant = Object.freeze({ tenantId: 'tenant-A' }) as VerifiedTenantContext;
  let effects = 0;
  class Authority {
    allowed = true;
    isVerifiedTenant(value: unknown): value is VerifiedTenantContext {
      assert.ok(this instanceof Authority);
      return this.allowed && value === tenant;
    }
  }
  const authority = new Authority(),
    scoped = tenantCache(cache, authority, tenant);
  authority.isVerifiedTenant = (_value: unknown): _value is VerifiedTenantContext => {
    void _value;
    return true;
  };
  authority.allowed = false;
  try {
    await assert.rejects(scoped.get('private'), { code: 'EK_TENANT_UNVERIFIED' });
    const trap = () => {
      effects++;
      throw new Error('Authority metadata must not execute');
    };
    const bad = [
      new Proxy(authority, { get: trap, getOwnPropertyDescriptor: trap, getPrototypeOf: trap }),
      Object.defineProperty({}, 'isVerifiedTenant', { get: trap }),
      { isVerifiedTenant: new Proxy(() => true, { apply: trap }) },
      Object.create(new Proxy(authority, { getOwnPropertyDescriptor: trap })),
      Array.from({ length: 33 }).reduce<object>(
        (previous) => Object.create(previous) as object,
        authority,
      ),
    ];
    for (const value of bad)
      assert.throws(() => tenantCache(cache, value as never, tenant), {
        code: 'EK_TENANT_UNVERIFIED',
      });
    assert.equal(effects, 0);
    assert.equal(f.state.calls.length, 0);
  } finally {
    await cache.close();
  }
});

test('Tenant cache never consults callable metadata and a verifier failure cannot reach Redis', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis),
    tenant = Object.freeze({ tenantId: 'tenant-A' }) as VerifiedTenantContext;
  let failed = false,
    metadataReads = 0;
  const failure = new Error('private-verifier-diagnostic');
  const authority = {
    isVerifiedTenant(value: unknown): value is VerifiedTenantContext {
      if (failed) throw failure;
      return value === tenant;
    },
  };
  for (const name of ['bind', 'call', 'apply'])
    Object.defineProperty(authority.isVerifiedTenant, name, {
      get() {
        metadataReads++;
        throw new Error('Callable metadata must not execute');
      },
    });
  const scoped = tenantCache(cache, authority, tenant);
  try {
    failed = true;
    for (const operation of [
      () => scoped.get('private'),
      () => scoped.set('private', {}),
      () => scoped.delete('private'),
    ])
      await assert.rejects(operation(), (error: unknown) => error === failure);
    assert.equal(metadataReads, 0);
    assert.equal(f.state.calls.length, 0);
  } finally {
    await cache.close();
  }
});

test('Tenant cache observes invalid asynchronous verifier rejection without trusting thenable metadata', async () => {
  const f = redisPortDouble(),
    cache = createRedisCache(f.redis),
    tenant = Object.freeze({ tenantId: 'tenant-A' }) as VerifiedTenantContext;
  let reads = 0;
  const asynchronous = () => {
    const result = Promise.reject(new Error('private-async-verifier-diagnostic'));
    for (const name of ['then', 'catch'])
      Object.defineProperty(result, name, {
        get() {
          reads++;
          throw new Error('Promise metadata must not execute');
        },
      });
    return result;
  };
  try {
    assert.throws(() => tenantCache(cache, { isVerifiedTenant: asynchronous as never }, tenant), {
      code: 'EK_TENANT_UNVERIFIED',
    });
    const thenable = Object.defineProperty({}, 'then', {
      get() {
        reads++;
        throw new Error('Thenable metadata must not execute');
      },
    });
    assert.throws(
      () => tenantCache(cache, { isVerifiedTenant: (() => thenable) as never }, tenant),
      { code: 'EK_TENANT_UNVERIFIED' },
    );
    await delay(0);
    assert.equal(reads, 0);
    assert.equal(f.state.calls.length, 0);
  } finally {
    await cache.close();
  }
});
