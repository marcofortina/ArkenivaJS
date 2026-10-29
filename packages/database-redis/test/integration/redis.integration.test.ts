// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import redis from 'redis';
import type { RedisClientType } from 'redis';
import { createApplication, KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { redisPlugin } from '@arkenivajs/database-redis';
import { REDIS_PUBSUB_CAPABILITY } from '@arkenivajs/database-redis/pubsub';
import type { RedisPubsubProvider } from '@arkenivajs/database-redis/pubsub';
import { redisConfiguration } from '../../dist/config.js';

const service = { name: 'redis-live-contract', version: '1.0.0', environment: 'test' as const };
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
async function eventually(check: () => boolean | Promise<boolean>, budget = 5000) {
  const expires = performance.now() + budget;
  while (!(await check())) {
    if (performance.now() >= expires)
      assert.fail('Redis condition did not become true within its budget');
    await delay(10);
  }
}
async function fixture(context: TestContext) {
  assert.equal(
    process.env.ARKENIVA_REDIS_DISPOSABLE,
    '1',
    'Only an explicitly disposable Redis fixture is permitted',
  );
  for (const name of [
    'ARKENIVA_REDIS_URL',
    'ARKENIVA_REDIS_WRONG_SAN_URL',
    'ARKENIVA_REDIS_CONTROL_URL',
  ])
    assert.ok(process.env[name], 'Every TLS/ACL fixture endpoint is required');
  const configuration = redisConfiguration(
    { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_URL' },
    'test',
  );
  const app = await createApplication({
    service,
    plugins: [redisPlugin()],
    databases: { main: { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_URL' } },
  });
  const provider = app.redis!;
  const keys = new Set<string>(),
    base = 'case:' + randomUUID() + ':';
  context.after(async () => {
    try {
      if (keys.size) {
        if (app.state === 'READY' && (provider.native() as RedisClientType).isReady)
          await provider.del([...keys]);
        else {
          const cleanup = redis.createClient(configuration.native);
          cleanup.on('error', () => undefined);
          try {
            await within(() => cleanup.connect(), { timeoutMs: 5000 });
            await cleanup
              .withAbortSignal(AbortSignal.timeout(5000))
              .del([...keys].map((key) => configuration.prefix + key));
          } finally {
            if (cleanup.isOpen) cleanup.destroy();
          }
        }
      }
    } finally {
      await app.stop();
    }
  });
  await app.start();
  return {
    app,
    provider,
    native: provider.native() as RedisClientType,
    configuration,
    key(name: string) {
      const key = base + name;
      keys.add(key);
      return key;
    },
  };
}
async function control(context: TestContext) {
  const configuration = redisConfiguration(
    { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_CONTROL_URL' },
    'test',
  );
  const client = redis.createClient(configuration.native);
  client.on('error', () => undefined);
  context.after(() => {
    if (client.isOpen) client.destroy();
  });
  await within(() => client.connect(), { timeoutMs: 5000 });
  return client;
}

test(
  'Live Redis PubSub uses independent authenticated connections across applications and releases them at shutdown',
  { timeout: 30_000 },
  async (context) => {
    const first = await fixture(context),
      second = await fixture(context);
    const a = first.app.resolve<RedisPubsubProvider>(REDIS_PUBSUB_CAPABILITY);
    const b = second.app.resolve<RedisPubsubProvider>(REDIS_PUBSUB_CAPABILITY);
    assert.equal(a.connectionName, 'main');
    const topic = 'events:' + randomUUID(),
      receivedA: string[] = [],
      receivedB: string[] = [],
      failures: unknown[] = [];
    const onFailure = (error: unknown) => {
      failures.push(error);
    };
    const one = await a.subscribe(
      topic,
      async (message) => {
        receivedA.push(message);
      },
      { onFailure },
    );
    const two = await b.subscribe(
      topic,
      async (message) => {
        receivedB.push(message);
      },
      { onFailure },
    );
    assert.equal(await first.provider.publish(topic, 'first'), 2);
    await eventually(() => receivedA.length === 1 && receivedB.length === 1);
    assert.deepEqual(receivedA, ['first']);
    assert.deepEqual(receivedB, ['first']);
    await assert.rejects(first.native.publish('unapproved:' + topic, 'denied'));
    await one.close();
    assert.equal(await second.provider.publish(topic, 'second'), 1);
    await eventually(() => receivedB.length === 2);
    assert.deepEqual(receivedA, ['first']);
    assert.deepEqual(receivedB, ['first', 'second']);
    await second.app.stop();
    assert.equal(await first.provider.publish(topic, 'after-shutdown'), 0);
    assert.throws(
      () => b.subscribe(topic, async () => {}, { onFailure }),
      code('EK_RESOURCE_CLOSED'),
    );
    await two.close();
    assert.deepEqual(failures, []);
  },
);

test(
  'EK-DB-002 live Redis authenticates scoped TLS and preserves missing, empty, Unicode, BOM and literal values',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      key = f.key('value');
    assert.equal(f.app.state, 'READY');
    assert.equal(f.native.isReady, true);
    assert.equal(await f.provider.get(key), null);
    for (const value of ['', '\uFEFFexact', '日本語 😀', 'quotes\'"\n\0 are data']) {
      assert.equal(await f.provider.set(key, value), true);
      assert.equal(await f.provider.get(key), value);
    }
    assert.throws(() => f.app.sql, code('EK_UNSUPPORTED_CAPABILITY'));
    const operator = await control(context);
    const info = await operator.info('server');
    assert.match(info, /redis_version:8\.10\.2/);
    await assert.rejects(f.native.set('outside_the_scoped_namespace', 'denied'));
    await assert.rejects(f.native.sendCommand(['FLUSHALL']));
  },
);

test(
  'EK-DB-002 live Redis implements NX as true/false and positive millisecond TTL with eventual expiration',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      key = f.key('ttl');
    assert.equal(await f.provider.set(key, 'first', { ttlMs: 500, onlyIfAbsent: true }), true);
    assert.equal(await f.provider.set(key, 'second', { onlyIfAbsent: true }), false);
    assert.equal(await f.provider.get(key), 'first');
    const remaining = await f.native.pTTL(f.configuration.prefix + key);
    assert.ok(remaining > 0 && remaining <= 500);
    await eventually(async () => (await f.provider.get(key)) === null, 3000);
    assert.equal(await f.provider.set(key, 'after-expiry', { onlyIfAbsent: true }), true);
  },
);

test(
  'EK-DB-002 live Redis increment is atomic, integer-safe before mutation and preserves an existing TTL',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      key = f.key('counter');
    assert.equal(await f.provider.increment(key), 1);
    assert.equal(await f.provider.increment(key, -2), -1);
    assert.equal(await f.provider.increment(key, 0), -1);
    for (const value of [
      String(Number.MAX_SAFE_INTEGER),
      String(Number.MIN_SAFE_INTEGER),
      '9223372036854775807',
      '-9223372036854775808',
      'not-an-integer',
      '001',
      '-0',
      '1.25',
    ]) {
      await f.provider.set(key, value);
      await assert.rejects(
        f.provider.increment(key, value.startsWith('-') ? -1 : 1),
        code('EK_KV_CONFLICT'),
      );
      assert.equal(await f.provider.get(key), value);
    }
    await f.provider.set(key, '7', { ttlMs: 5000 });
    assert.equal(await f.provider.increment(key, 2), 9);
    const remaining = await f.native.pTTL(f.configuration.prefix + key);
    assert.ok(remaining > 0 && remaining <= 5000);
  },
);

test(
  'EK-DB-002 live Redis concurrent clients cannot lose increments or cross the safe-integer boundary',
  { timeout: 30_000 },
  async (context) => {
    const first = await fixture(context),
      second = await fixture(context),
      key = first.key('race');
    await first.provider.set(key, '0');
    await Promise.all(
      Array.from({ length: 100 }, (_, index) =>
        (index % 2 ? first.provider : second.provider).increment(key),
      ),
    );
    assert.equal(await first.provider.get(key), '100');
    await first.provider.set(key, String(Number.MAX_SAFE_INTEGER - 1));
    const race = await Promise.allSettled([
      first.provider.increment(key),
      second.provider.increment(key),
    ]);
    assert.equal(race.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(
      race.filter((result) => result.status === 'rejected' && code('EK_KV_CONFLICT')(result.reason))
        .length,
      1,
    );
    assert.equal(await first.provider.get(key), String(Number.MAX_SAFE_INTEGER));
  },
);

test(
  'EK-DB-002 live Redis deletes actual keys and implements the empty delete without a native request',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      one = f.key('one'),
      two = f.key('two');
    const command = context.mock.method(f.native, 'withAbortSignal');
    assert.equal(await f.provider.del([]), 0);
    assert.equal(command.mock.callCount(), 0);
    await f.provider.set(one, '1');
    await f.provider.set(two, '2');
    assert.equal(await f.provider.del([one, one, two, f.key('missing')]), 2);
    assert.equal(await f.provider.del([one]), 0);
  },
);

test(
  'EK-DB-002 live Redis bounds returned bytes before transfer and rejects invalid native UTF-8',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      key = f.key('large'),
      raw = f.configuration.prefix + key;
    await f.native.set(raw, Buffer.alloc(1_048_577, 65));
    await assert.rejects(
      f.provider.get(key),
      (error) =>
        error instanceof KitError &&
        error.code === 'EK_KV_CONFLICT' &&
        error.details.limitExceeded === true,
    );
    await f.native.set(raw, Buffer.from([0xff, 0xfe]));
    await assert.rejects(f.provider.get(key), code('EK_KV_CONFLICT'));
    const hash = f.key('hash');
    await f.native.hSet(f.configuration.prefix + hash, { field: 'native' });
    await assert.rejects(f.provider.get(hash), code('EK_KV_CONFLICT'));
  },
);

test(
  'EK-DB-002 live Redis exposes actual native structures and MULTI without SQL or hidden callback retries',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      key = f.key('native');
    assert.equal(typeof f.native.duplicate, 'function');
    assert.equal(typeof f.native.hSet, 'function');
    await f.native.hSet(f.configuration.prefix + key, { field: 'value' });
    assert.deepEqual(
      { ...(await f.native.hGetAll(f.configuration.prefix + key)) },
      { field: 'value' },
    );
    const count = f.key('multi');
    assert.deepEqual(
      await f.native
        .multi()
        .set(f.configuration.prefix + count, '1')
        .incrBy(f.configuration.prefix + count, 2)
        .exec(),
      ['OK', 3],
    );
    assert.equal(await f.provider.get(count), '3');
  },
);

test(
  'EK-DB-002 live Redis publish reports subscriber counts and native unsubscribe releases ownership',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      channel = f.key('channel'),
      subscriber = f.native.duplicate();
    subscriber.on('error', () => undefined);
    context.after(() => {
      if (subscriber.isOpen) subscriber.destroy();
    });
    await within(() => subscriber.connect(), { timeoutMs: 5000 });
    const received = deferred();
    let value: string | undefined;
    await subscriber.subscribe(f.configuration.prefix + channel, (message) => {
      value = message;
      received.resolve();
    });
    assert.equal(await f.provider.publish(channel, 'payload'), 1);
    await within(() => received.promise, { timeoutMs: 5000 });
    assert.equal(value, 'payload');
    await subscriber.unsubscribe(f.configuration.prefix + channel);
    subscriber.destroy();
    assert.equal(subscriber.isOpen, false);
    assert.equal(await f.provider.publish(channel, 'after-unsubscribe'), 0);
  },
);

test(
  'EK-SEC-001 live Redis verifies DNS/IP trust and rejects wrong SAN, missing CA and bad credentials',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      variable = 'ARKENIVA_REDIS_NEGATIVE_TEST',
      original = process.env[variable];
    try {
      const ip = new URL(process.env.ARKENIVA_REDIS_URL!);
      ip.hostname = '127.0.0.1';
      process.env[variable] = ip.href;
      const good = await createApplication({
        service,
        plugins: [redisPlugin()],
        databases: { main: { driver: 'redis', connectionStringEnv: variable } },
      });
      try {
        await good.start();
        assert.equal(await good.redis!.get(f.key('ip')), null);
      } finally {
        await good.stop();
      }
      const untrusted = new URL(process.env.ARKENIVA_REDIS_URL!);
      untrusted.searchParams.delete('sslca');
      const password = new URL(process.env.ARKENIVA_REDIS_URL!);
      password.password = 'intentionally-wrong';
      for (const url of [
        process.env.ARKENIVA_REDIS_WRONG_SAN_URL!,
        untrusted.href,
        password.href,
      ]) {
        process.env[variable] = url;
        const bad = await createApplication({
          service,
          plugins: [redisPlugin()],
          databases: { main: { driver: 'redis', connectionStringEnv: variable } },
        });
        await assert.rejects(
          bad.start(),
          (error) =>
            error instanceof KitError &&
            error.cause instanceof KitError &&
            error.cause.code === 'EK_BACKEND_UNAVAILABLE',
        );
        assert.equal(bad.state, 'CLOSED');
        await bad.stop();
      }
    } finally {
      if (original === undefined) delete process.env[variable];
      else process.env[variable] = original;
    }
  },
);

test(
  'EK-DB-002 a real Redis write remains exactly once after an injected lost acknowledgment at its public native boundary',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      key = f.key('ack');
    await f.provider.set(key, '0');
    const owner = Object.getPrototypeOf(f.native) as RedisClientType;
    const execute = owner.eval;
    let executions = 0;
    const mock = context.mock.method(
      owner,
      'eval',
      async function (this: RedisClientType, ...arguments_: Parameters<typeof owner.eval>) {
        await Reflect.apply(execute, this, arguments_);
        executions++;
        throw new redis.SocketClosedUnexpectedlyError();
      },
    );
    await assert.rejects(
      f.provider.increment(key),
      (error) =>
        error instanceof KitError &&
        error.details.outcome === 'unknown' &&
        error.retryable === false,
    );
    mock.mock.restore();
    assert.equal(executions, 1);
    assert.equal(await f.provider.get(key), '1');
  },
);

test(
  'EK-CORE-001 live Redis reconnects transport after a targeted disconnect and refuses offline writes',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      operator = await control(context),
      key = f.key('offline');
    const id = await f.native.sendCommand(['CLIENT', 'ID']);
    assert.ok(typeof id === 'number' && Number.isSafeInteger(id));
    const reconnecting = deferred();
    f.native.once('reconnecting', reconnecting.resolve);
    const calls = context.mock.method(f.native, 'withAbortSignal');
    await operator.sendCommand(['CLIENT', 'KILL', 'ID', String(id)]);
    await within(() => reconnecting.promise, { timeoutMs: 5000 });
    const before = calls.mock.callCount();
    await assert.rejects(f.provider.set(key, 'must-not-queue'), code('EK_BACKEND_UNAVAILABLE'));
    assert.equal(calls.mock.callCount(), before);
    await eventually(() => f.native.isReady);
    assert.equal(await f.provider.get(key), null);
    assert.notEqual(await f.native.sendCommand(['CLIENT', 'ID']), id);
  },
);

test(
  'EK-CORE-001 live Redis timeout and cancellation consume late replies without corrupting subsequent commands',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      operator = await control(context),
      key = f.key('cancel');
    await f.provider.set(key, 'before');
    await operator.sendCommand(['CLIENT', 'PAUSE', '200', 'ALL']);
    await assert.rejects(f.provider.get(key, { timeoutMs: 20 }), code('EK_TIMEOUT'));
    assert.equal(await f.provider.get(key), 'before');
    await operator.sendCommand(['CLIENT', 'PAUSE', '200', 'WRITE']);
    const submitted = deferred(),
      abort = new AbortController(),
      bind = f.native.withAbortSignal.bind(f.native);
    const mock = context.mock.method(f.native, 'withAbortSignal', (signal: AbortSignal) => {
      submitted.resolve();
      return bind(signal);
    });
    const pending = f.provider.set(key, 'after', { signal: abort.signal });
    await within(() => submitted.promise, { timeoutMs: 5000 });
    abort.abort('Caller cancelled');
    await assert.rejects(
      pending,
      (error) =>
        error instanceof KitError &&
        error.code === 'EK_ABORTED' &&
        error.details.outcome === 'unknown',
    );
    mock.mock.restore();
    assert.ok(['before', 'after'].includes((await f.provider.get(key))!));
  },
);

test(
  'EK-CORE-001 live Redis shutdown rejects new work and observes an in-flight write with an uncertain outcome',
  { timeout: 30_000 },
  async (context) => {
    const f = await fixture(context),
      operator = await control(context),
      key = f.key('drain');
    await operator.sendCommand(['CLIENT', 'PAUSE', '200', 'WRITE']);
    const submitted = deferred(),
      bind = f.native.withAbortSignal.bind(f.native);
    context.mock.method(f.native, 'withAbortSignal', (signal: AbortSignal) => {
      submitted.resolve();
      return bind(signal);
    });
    const pending = f.provider.set(key, 'bounded', { ttlMs: 1000 });
    void pending.catch(() => undefined);
    await within(() => submitted.promise, { timeoutMs: 5000 });
    await f.app.stop();
    await assert.rejects(
      pending,
      (error) => error instanceof KitError && error.details.outcome === 'unknown',
    );
    assert.equal(f.native.isOpen, false);
    await assert.rejects(f.provider.get(key), code('EK_RESOURCE_CLOSED'));
    await f.app.stop();
  },
);
