import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import redis from 'redis';
import { KitError } from '@arkenivajs/core';
import type { Logger, Telemetry, UsageMeter, MeterSession } from '@arkenivajs/core';
import { sdkDouble } from '../fixtures/native-double.js';
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

test('EK-DB-002 Redis captures scoped commands, Buffer conversion and validated modern NX/TTL options', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection();
  await connection.start();
  sdk.plan('get', { value: null });
  assert.equal(await connection.get('missing'), null);
  sdk.plan('get', { value: Buffer.from('\uFEFFexact') });
  assert.equal(await connection.get('value'), '\uFEFFexact');
  assert.equal(await connection.set('value', 'payload', { ttlMs: 5000, onlyIfAbsent: true }), true);
  sdk.plan('set', { value: null });
  assert.equal(await connection.set('value', 'next', { onlyIfAbsent: true }), false);
  assert.deepEqual(sdk.calls.find((call) => call.method === 'set')!.arguments, [
    'scope:value',
    'payload',
    { expiration: { type: 'PX', value: 5000 }, condition: 'NX' },
  ]);
  assert.equal(await connection.increment('counter', -2), 1);
  assert.equal(await connection.publish('topic', 'message'), 0);
  const keys = ['one', 'two'];
  const pending = connection.del(keys);
  keys[0] = 'changed';
  await pending;
  assert.deepEqual(sdk.calls.find((call) => call.method === 'del')!.arguments, [
    ['scope:one', 'scope:two'],
  ]);
  const before = sdk.calls.length;
  assert.equal(await connection.del([]), 0);
  assert.equal(sdk.calls.length, before);
  assert.ok(sdk.mappings.length > 0);
  assert.equal(connection.native(), sdk.client);
  assert.ok(connection.stats().operations! > 0);
  await connection.close();
  assert.equal(sdk.counts.destroys, 1);
});

test('EK-CONF-001 Redis rejects invalid keys, values, limits, TTL and signal options before command submission', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection();
  await connection.start();
  const before = sdk.calls.length;
  for (const key of ['', '\0key', 'line\nkey', 'x'.repeat(1025), '\ud800', null])
    await assert.rejects(connection.get(key as string), code('EK_CONFIG_INVALID'));
  for (const value of ['x'.repeat(1_048_577), '\ud800', null])
    await assert.rejects(connection.set('key', value as string), code('EK_CONFIG_INVALID'));
  for (const ttlMs of [0, -1, 1.5, Infinity])
    await assert.rejects(connection.set('key', 'value', { ttlMs }), code('EK_CONFIG_INVALID'));
  await assert.rejects(
    connection.set('key', 'value', { onlyIfAbsent: 1 as never }),
    code('EK_CONFIG_INVALID'),
  );
  for (const input of [null, [], { timeoutMs: 0 }, { timeoutMs: 1.5 }, { signal: {} }])
    await assert.rejects(connection.get('key', input as never), code('EK_CONFIG_INVALID'));
  await assert.rejects(
    connection.get('key', { signal: AbortSignal.abort('Stopped') }),
    code('EK_ABORTED'),
  );
  await assert.rejects(connection.del('key' as never), code('EK_CONFIG_INVALID'));
  await assert.rejects(connection.del(Array(1001).fill('key')), code('EK_CONFIG_INVALID'));
  for (const amount of [NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1])
    await assert.rejects(connection.increment('key', amount), code('EK_CONFIG_INVALID'));
  await assert.rejects(connection.publish('topic', '\ud800'), code('EK_CONFIG_INVALID'));
  assert.equal(sdk.calls.length, before);
  await connection.close();
});

test('EK-DB-002 Redis rejects malformed native replies and invalid stored UTF-8 without inventing success', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection();
  await connection.start();
  for (const value of ['unexpected-string', Buffer.from([0xff])]) {
    sdk.plan('get', { value });
    await assert.rejects(connection.get('key'));
  }
  sdk.plan('set', { value: null });
  await assert.rejects(connection.set('key', 'value'), code('EK_BACKEND_UNAVAILABLE'));
  sdk.plan('set', { value: 'unexpected' });
  await assert.rejects(connection.set('key', 'value'), code('EK_BACKEND_UNAVAILABLE'));
  for (const value of [-1, 1.5, '1']) {
    sdk.plan('del', { value });
    await assert.rejects(connection.del(['key']), code('EK_BACKEND_UNAVAILABLE'));
    sdk.plan('publish', { value });
    await assert.rejects(connection.publish('topic', 'message'), code('EK_BACKEND_UNAVAILABLE'));
  }
  for (const value of [
    Number.MAX_SAFE_INTEGER + 1,
    '9007199254740992',
    '-9007199254740992',
    '1.25',
    'not-an-integer',
    '123456789012345678',
  ]) {
    sdk.plan('increment', { value });
    await assert.rejects(connection.increment('key'), code('EK_KV_CONFLICT'));
  }
  await connection.close();
});

test('EK-CORE-001 Redis bounds pending attempts and never submits commands while transport is offline', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection();
  await connection.start();
  sdk.ready(false);
  await assert.rejects(connection.set('key', 'value'), code('EK_BACKEND_UNAVAILABLE'));
  sdk.ready(true);
  const gate = deferred();
  for (let index = 0; index < 128; index++) sdk.plan('get', { gate: gate.promise });
  const pending = Array.from({ length: 128 }, () => connection.get('key'));
  await assert.rejects(connection.get('key'), code('EK_BACKEND_UNAVAILABLE'));
  assert.equal(connection.stats().pending, 128);
  gate.resolve();
  await Promise.all(pending);
  assert.equal(connection.stats().pending, 0);
  await connection.close();
});

test('EK-CORE-001 Redis cancels SDK work and preserves unknown write outcomes without replay', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection();
  await connection.start();
  const gate = deferred();
  sdk.plan('get', { gate: gate.promise });
  await assert.rejects(connection.get('key', { timeoutMs: 10 }), code('EK_TIMEOUT'));
  const abort = new AbortController();
  sdk.plan('set', { gate: gate.promise });
  const pending = connection.set('key', 'value', { signal: abort.signal });
  await setImmediate();
  abort.abort('Stopped');
  await assert.rejects(
    pending,
    (error) =>
      error instanceof KitError &&
      error.code === 'EK_ABORTED' &&
      error.details.outcome === 'unknown' &&
      error.retryable === false,
  );
  assert.equal(sdk.calls.filter((call) => call.method === 'set').length, 1);
  gate.resolve();
  await connection.close();
});

test('EK-DB-002 Redis keeps acknowledged server failures distinct from uncertain transport failures', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection();
  await connection.start();
  sdk.plan('increment', {
    fail: true,
    error: new redis.SimpleError('ARKENIVA_INTEGER_RANGE Unsafe integer'),
  });
  await assert.rejects(
    connection.increment('key'),
    (error) =>
      error instanceof KitError &&
      error.code === 'EK_KV_CONFLICT' &&
      error.details.outcome === undefined,
  );
  sdk.plan('set', { fail: true, error: new redis.SocketClosedUnexpectedlyError() });
  await assert.rejects(
    connection.set('key', 'value'),
    (error) =>
      error instanceof KitError && error.details.outcome === 'unknown' && error.retryable === false,
  );
  await connection.close();
});

test('EK-CORE-001 Redis closes pending work once and stale operations cannot reopen a socket', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection();
  await connection.start();
  const gate = deferred();
  sdk.plan('get', { gate: gate.promise });
  const pending = connection.get('key');
  await setImmediate();
  const closing = connection.close();
  assert.equal(connection.close(), closing);
  await assert.rejects(pending);
  await closing;
  gate.resolve();
  assert.equal(sdk.counts.destroys, 1);
  await assert.rejects(connection.get('key'), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => connection.native(), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => connection.start(), code('EK_RESOURCE_CLOSED'));
});

test('EK-CORE-001 Redis startup is single-flight, validates PING and cleans failed native acquisition', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection();
  const starting = connection.start();
  assert.equal(connection.start(), starting);
  await starting;
  await connection.close();
  assert.equal(sdk.counts.connects, 1);
  const next = sdk.connection();
  sdk.plan('ping', { value: 'not-ready' });
  await assert.rejects(next.start(), code('EK_BACKEND_UNAVAILABLE'));
  await next.close();
  const failed = sdk.connection();
  sdk.failConnect(new redis.SimpleError('WRONGPASS Invalid credentials'));
  await assert.rejects(failed.start(), code('EK_BACKEND_UNAVAILABLE'));
  await failed.close();
});

test('EK-CORE-001 Redis startup cancellation observes and closes a late native connection', async (context) => {
  const sdk = sdkDouble(context),
    gate = deferred();
  sdk.gateConnect(gate.promise);
  const connection = sdk.connection();
  await assert.rejects(connection.start({ timeoutMs: 10 }), code('EK_TIMEOUT'));
  gate.resolve();
  await setImmediate();
  await connection.close();
  assert.equal(sdk.client.isOpen, false);
  assert.ok(sdk.counts.destroys >= 1);
});

test('EK-CORE-001 Redis startup and shutdown cleanup failures remain visible', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection();
  sdk.plan('ping', { value: 'bad' });
  sdk.failDestroy('Cleanup failed');
  await assert.rejects(
    connection.start(),
    (error) => error instanceof KitError && error.cause instanceof AggregateError,
  );
  await connection.close();
  const next = sdk.connection();
  await next.start();
  await assert.rejects(
    next.close(),
    (error) => error instanceof KitError && error.code === 'EK_BACKEND_UNAVAILABLE',
  );
});

test('EK-DB-004 Redis ports observe seconds versus milliseconds, one attempt, quality gaps and safe logs', async (context) => {
  const records: string[] = [],
    usage: { value: number; unit: string }[] = [],
    histograms: { name: string; value: number }[] = [],
    missing: string[] = [],
    logs: unknown[] = [];
  const session = {
    recordOperation(name: string) {
      records.push(name);
    },
    recordUsage(_name: string, value: { value: number; unit: string }) {
      usage.push(value);
    },
  } as unknown as MeterSession;
  const meter = {
    current: () => session,
    markMissing(_session: MeterSession, reason: string) {
      missing.push(reason);
    },
  } as unknown as UsageMeter;
  const telemetry = {
    withSpan: async (_name: string, work: () => Promise<unknown>) => work(),
    recordHistogram(name: string, value: number) {
      histograms.push({ name, value });
    },
  } as unknown as Telemetry;
  const logger = {
    debug(_message: string, fields: unknown) {
      logs.push(fields);
    },
    warn(_message: string, fields: unknown) {
      logs.push(fields);
    },
  } as unknown as Logger;
  const sdk = sdkDouble(context),
    connection = sdk.connection({ meter, telemetry, logger });
  await connection.start();
  await connection.get('sensitive-key');
  assert.deepEqual(records, ['db.query']);
  assert.equal(usage[0]!.unit, 'milliseconds');
  assert.equal(histograms[0]!.value, usage[0]!.value / 1000);
  connection.native();
  assert.ok(missing.includes('driver_bytes_unavailable'));
  assert.ok(missing.includes('not_instrumented'));
  sdk.client.emit('error', new Error('sensitive-value'));
  sdk.client.emit('reconnecting');
  assert.equal(connection.stats().reconnects, 1);
  assert.ok(!JSON.stringify(logs).includes('sensitive'));
  await connection.close();
});

test('EK-DB-004 Redis diagnostic failures cannot replay or replace a business result', async (context) => {
  const telemetry = {
    withSpan() {
      throw new Error('Tracing failed');
    },
    recordHistogram() {
      throw new Error('Histogram failed');
    },
  } as unknown as Telemetry;
  const logger = {
    debug() {
      throw new Error('Logger failed');
    },
    warn() {
      throw new Error('Logger failed');
    },
  } as unknown as Logger;
  const session = {
    recordOperation() {
      throw new Error('Counter failed');
    },
    recordUsage() {
      throw new Error('Usage failed');
    },
  } as unknown as MeterSession;
  const sdk = sdkDouble(context),
    connection = sdk.connection({
      telemetry,
      logger,
      meter: { current: () => session } as unknown as UsageMeter,
    });
  await connection.start();
  assert.equal(await connection.set('key', 'value'), true);
  assert.equal(sdk.calls.filter((call) => call.method === 'set').length, 1);
  sdk.plan('set', { fail: true, error: new redis.SimpleError('WRONGTYPE Wrong type') });
  await assert.rejects(connection.set('key', 'value'), code('EK_KV_CONFLICT'));
  assert.ok(connection.stats().observerFailures! > 0);
  await connection.close();
});

test('EK-DB-004 Redis bounds delayed diagnostics and preserves an already acknowledged native outcome', async (context) => {
  const gate = deferred();
  const telemetry = {
    async withSpan(_name: string, work: () => Promise<unknown>) {
      await work();
      await gate.promise;
    },
    recordHistogram() {},
  } as unknown as Telemetry;
  const sdk = sdkDouble(context),
    connection = sdk.connection({ telemetry });
  await connection.start();
  assert.equal(await connection.set('key', 'value', { timeoutMs: 10 }), true);
  assert.equal(sdk.calls.filter((call) => call.method === 'set').length, 1);
  gate.resolve();
  await connection.close();
});
