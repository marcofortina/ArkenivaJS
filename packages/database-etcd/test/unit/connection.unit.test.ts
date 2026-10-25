// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { GRPCUnavailableError, EtcdPermissionDeniedError } from 'etcd3';
import { KitError } from '@arkenivajs/core';
import type { Logger, Telemetry, UsageMeter, MeterSession } from '@arkenivajs/core';
import { nativeDouble, deferred, header } from '../fixtures/native-double.js';

const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('EK-DB-002 etcd passes exact bytes, prefixes and revision strings to the actual SDK callable boundary', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  f.plan('range', { value: f.row() });
  const row = await c.get('key');
  assert.deepEqual(row, {
    key: 'key',
    value: Uint8Array.from([0, 255]),
    revision: 9007199254740993n,
    version: 9007199254740995n,
  });
  assert.ok(Object.isFrozen(row));
  const bytes = Uint8Array.from([0, 255, 1]);
  const writing = c.put('key', bytes);
  bytes.fill(42);
  await writing;
  const write = f.calls.find((call) => call.method === 'put')!.payload as {
    key: Buffer;
    value: Buffer;
  };
  assert.deepEqual(write, { key: Buffer.from('/scope/key'), value: Buffer.from([0, 255, 1]) });
  assert.equal(
    await c.compareAndSwap({
      key: 'key',
      expectedRevision: 9007199254740993n,
      value: Uint8Array.from([2]),
    }),
    true,
  );
  const transaction = f.calls.find((call) => call.method === 'txn')!.payload as {
    compare: { mod_revision: string }[];
  };
  assert.equal(transaction.compare[0]!.mod_revision, '9007199254740993');
  f.plan('txn', { value: { header, succeeded: false, responses: [] } });
  assert.equal(
    await c.compareAndSwap({ key: 'key', expectedRevision: 0n, value: new Uint8Array() }),
    false,
  );
  f.plan('deleteRange', { value: { header, deleted: '0' } });
  assert.equal(await c.delete('key'), false);
  assert.equal(await c.delete('key'), true);
  assert.equal(await c.get('key'), null);
});

test('EK-CONF-001 etcd rejects invalid public inputs before the native callable or resource creation', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  const before = f.calls.length;
  for (const key of ['', '\0key', '\ud800', 'x'.repeat(4097), null]) {
    await assert.rejects(c.get(key as string), code('EK_CONFIG_INVALID'));
    await assert.rejects(c.delete(key as string), code('EK_CONFIG_INVALID'));
  }
  for (const value of ['text', null, new Uint8Array(1_048_577)])
    await assert.rejects(c.put('key', value as never), code('EK_CONFIG_INVALID'));
  for (const input of [null, [], { timeoutMs: 0 }, { timeoutMs: 1.5 }, { signal: {} }])
    await assert.rejects(c.get('key', input as never), code('EK_CONFIG_INVALID'));
  await assert.rejects(c.get('key', { signal: AbortSignal.abort('Stopped') }), code('EK_ABORTED'));
  for (const ttl of [0, -1, 1.5, NaN, Infinity])
    await assert.rejects(c.grantLease(ttl), code('EK_CONFIG_INVALID'));
  for (const leaseId of [1, '', '01', '-1', '9223372036854775808'])
    await assert.rejects(
      c.put('key', new Uint8Array(), { leaseId: leaseId as string }),
      code('EK_CONFIG_INVALID'),
    );
  await assert.rejects(c.put('key', new Uint8Array(), { leaseId: '1' }), code('EK_KV_CONFLICT'));
  for (const input of [
    null,
    [],
    { key: 'key', expectedRevision: 1, value: new Uint8Array() },
    { key: 'key', expectedRevision: -1n, value: new Uint8Array() },
    { key: 'key', expectedRevision: 9_223_372_036_854_775_808n, value: new Uint8Array() },
  ])
    await assert.rejects(c.compareAndSwap(input as never), code('EK_CONFIG_INVALID'));
  await assert.rejects(c.watch('\0prefix'), code('EK_CONFIG_INVALID'));
  assert.equal(f.calls.length, before);
});

test('EK-DB-002 etcd rejects malformed acknowledgments, ambiguous rows and oversized stored values', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  for (const value of [
    { header, count: '2', kvs: [], more: false },
    { ...f.row(), more: true },
    { ...f.row(), kvs: [...f.row().kvs, ...f.row().kvs], count: '2' },
    { ...f.row(), kvs: [{ ...f.row().kvs[0], key: Buffer.from('/scope/other') }] },
    { ...f.row(), kvs: [{ ...f.row().kvs[0], value: 'text' }] },
    { ...f.row(), kvs: [{ ...f.row().kvs[0], version: '0' }] },
  ]) {
    f.plan('range', { value });
    await assert.rejects(c.get('key'), code('EK_BACKEND_UNAVAILABLE'));
  }
  f.plan('range', { value: f.row(Buffer.alloc(1_048_577)) });
  await assert.rejects(
    c.get('key'),
    (error) =>
      error instanceof KitError &&
      error.code === 'EK_KV_CONFLICT' &&
      error.details.limitExceeded === true,
  );
  f.plan('put', { value: { header: {} } });
  await assert.rejects(c.put('key', new Uint8Array()), code('EK_BACKEND_UNAVAILABLE'));
  for (const deleted of ['-1', '2', '1.5']) {
    f.plan('deleteRange', { value: { header, deleted } });
    await assert.rejects(c.delete('key'), code('EK_BACKEND_UNAVAILABLE'));
  }
  f.plan('txn', { value: { header, succeeded: 'yes' } });
  await assert.rejects(
    c.compareAndSwap({ key: 'key', expectedRevision: 0n, value: new Uint8Array() }),
    code('EK_BACKEND_UNAVAILABLE'),
  );
});

test('EK-CORE-001 etcd bounds pending work, cancels one waiter and retains late native settlements', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  const gate = deferred();
  for (let index = 0; index < 128; index++) f.plan('range', { gate: gate.promise });
  const pending = Array.from({ length: 128 }, () => c.get('key'));
  await assert.rejects(c.get('key'), code('EK_BACKEND_UNAVAILABLE'));
  assert.equal(c.stats().pending, 128);
  gate.resolve();
  await Promise.all(pending);
  assert.equal(c.stats().pending, 0);
  const slow = deferred();
  f.plan('range', { gate: slow.promise });
  await assert.rejects(c.get('key', { timeoutMs: 10 }), code('EK_TIMEOUT'));
  slow.resolve();
  await setImmediate();
  assert.equal(await c.get('key'), null);
});

test('EK-CORE-001 etcd shutdown observes cancelled work without treating a normal request abort as failed cleanup', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  const gate = deferred();
  f.plan('range', { gate: gate.promise });
  const pending = c.get('key');
  void pending.catch(() => undefined);
  const closing = c.close();
  assert.equal(c.close(), closing);
  await assert.rejects(pending, code('EK_ABORTED'));
  await closing;
  gate.resolve();
  await setImmediate();
  await assert.rejects(c.get('key'), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => c.native(), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => c.start(), code('EK_RESOURCE_CLOSED'));
  assert.equal(c.stats().ready, 0);
});

test('EK-CORE-001 etcd startup is single-flight, schedules a five-second default and rejects stale or unready access', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await assert.rejects(c.get('key'), code('EK_LIFECYCLE_STATE'));
  await assert.rejects(c.watch('prefix'), code('EK_LIFECYCLE_STATE'));
  await assert.rejects(c.grantLease(1), code('EK_LIFECYCLE_STATE'));
  const original = globalThis.setTimeout,
    delays: number[] = [];
  context.mock.method(globalThis, 'setTimeout', ((...args: Parameters<typeof setTimeout>) => {
    delays.push(args[1] ?? 0);
    return Reflect.apply(original, globalThis, args);
  }) as typeof setTimeout);
  const starting = c.start();
  assert.equal(c.start(), starting);
  await starting;
  assert.equal(delays[0], 5000);
  assert.equal(c.stats().operations, 0);
});

test('EK-CORE-001 etcd readiness and native close failures retain both causes and report incomplete cleanup', async (context) => {
  const f = nativeDouble(context),
    native = f.connection.native();
  f.plan('range', { fail: true, error: new EtcdPermissionDeniedError('Private failure') });
  const failure = new Error('Native close failed');
  context.mock.method(native, 'close', () => {
    throw failure;
  });
  f.allowCloseFailure();
  await assert.rejects(
    f.connection.start(),
    (error) =>
      error instanceof KitError &&
      error.cause instanceof AggregateError &&
      error.cause.errors.length === 2,
  );
  await assert.rejects(f.connection.close(), code('EK_BACKEND_UNAVAILABLE'));
});

test('EK-DB-004 etcd observes seconds versus milliseconds once and keeps sensitive native text out of default logs', async (context) => {
  const usage: { value: number; unit: string }[] = [],
    histograms: number[] = [],
    missing: string[] = [],
    records: string[] = [],
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
    async withSpan(_name: string, work: () => Promise<unknown>) {
      return work();
    },
    recordHistogram(_name: string, value: number) {
      histograms.push(value);
    },
  } as unknown as Telemetry;
  const logger = {
    warn(_message: string, fields: unknown) {
      logs.push(fields);
    },
  } as unknown as Logger;
  const f = nativeDouble(context, { meter, telemetry, logger });
  await f.connection.start();
  await f.connection.get('key');
  assert.deepEqual(records, ['db.query']);
  assert.equal(usage[0]!.unit, 'milliseconds');
  assert.equal(histograms[0], usage[0]!.value / 1000);
  assert.ok(missing.includes('driver_bytes_unavailable') && missing.includes('not_instrumented'));
  f.plan('put', { fail: true, error: new GRPCUnavailableError('private-key private-value') });
  await assert.rejects(f.connection.put('key', new Uint8Array()), code('EK_BACKEND_UNAVAILABLE'));
  assert.ok(!JSON.stringify(logs).includes('private'));
});

test('EK-DB-004 etcd diagnostic failures cannot replay writes or replace an acknowledged native result', async (context) => {
  const telemetry = {
    async withSpan(_name: string, work: () => Promise<unknown>) {
      await work();
      throw new Error('Diagnostic failed');
    },
    recordHistogram() {
      throw new Error('Histogram failed');
    },
  } as unknown as Telemetry;
  const logger = {
    warn() {
      throw new Error('Logger failed');
    },
  } as unknown as Logger;
  const meter = {
    current() {
      throw new Error('Meter failed');
    },
  } as unknown as UsageMeter;
  const f = nativeDouble(context, { telemetry, logger, meter });
  await f.connection.start();
  await f.connection.put('key', Uint8Array.from([1]));
  assert.equal(f.calls.filter((call) => call.method === 'put').length, 1);
  f.plan('put', { fail: true, error: new EtcdPermissionDeniedError('Denied') });
  await assert.rejects(f.connection.put('key', new Uint8Array()), code('EK_BACKEND_UNAVAILABLE'));
  assert.equal(f.calls.filter((call) => call.method === 'put').length, 2);
  assert.ok(f.connection.stats().observerFailures! > 0);
});

test('EK-DB-004 etcd bounds a delayed diagnostic wrapper while preserving its established native acknowledgment', async (context) => {
  const gate = deferred();
  const telemetry = {
    async withSpan(_name: string, work: () => Promise<unknown>) {
      await work();
      await gate.promise;
    },
    recordHistogram() {},
  } as unknown as Telemetry;
  const f = nativeDouble(context, { telemetry });
  await f.connection.start();
  await f.connection.put('key', new Uint8Array(), { timeoutMs: 10 });
  assert.equal(f.calls.filter((call) => call.method === 'put').length, 1);
  gate.resolve();
});
