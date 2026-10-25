// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { MongoClient, AbstractCursor, ClientSession, BSON, MongoNetworkError } from 'mongodb';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { Logger, Telemetry, UsageMeter, MeterSession } from '@arkenivajs/core';
import { nativeDouble, deferred } from '../fixtures/native-double.js';

test('MongoDB enters the actual SDK with captured BSON, exact opaque IDs and actual modified/deleted counts', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  const bytes = Buffer.from([0, 255]),
    document = { _id: 'caller', bytes, amount: BSON.Decimal128.fromString('1.25') };
  const writing = c.insertOne('records', document);
  bytes[0] = 99;
  assert.equal(await writing, '"caller"');
  const inserted = f.calls.find((call) => call.method === 'insertOne')!.payload as Record<
    string,
    unknown
  >;
  assert.ok(inserted.bytes instanceof BSON.Binary);
  assert.equal(inserted.bytes.buffer[0], 0);
  assert.ok(inserted.amount instanceof BSON.Decimal128);
  f.plan('next', { value: { _id: 'caller', amount: BSON.Decimal128.fromString('1.25') } });
  const row = await c.findOne<{ amount: BSON.Decimal128 }>('records', { _id: 'caller' });
  assert.equal(row?.amount.toString(), '1.25');
  f.plan('updateOne', { value: { acknowledged: true, modifiedCount: 0 } });
  assert.equal(await c.updateOne('records', {}, { $set: { value: 1 } }), 0);
  assert.equal(await c.deleteOne('records', {}), 1);
  f.plan('deleteOne', { value: { acknowledged: true, deletedCount: 0 } });
  assert.equal(await c.deleteOne('records', {}), 0);
});

test('MongoDB rejects stale/unready access and invalid options and documents before native submission', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  assert.throws(() => c.native(), { code: 'EK_LIFECYCLE_STATE' });
  await assert.rejects(c.findOne('records', {}), { code: 'EK_LIFECYCLE_STATE' });
  await c.start();
  const before = f.calls.length;
  for (const call of [
    () => c.findOne('', {}),
    () => c.findOne('records', null as never),
    () => c.findMany('records', {}, { limit: 0 }),
    () => c.findMany('records', {}, { limit: 1001 }),
    () => c.insertOne('records', []),
    () => c.updateOne('records', {}, null as never),
    () => c.aggregate('records', [{ $match: {} }]),
    () => c.deleteOne('records', {}, { timeoutMs: 0 }),
    () => c.withTransaction(null as never),
  ])
    await assert.rejects(call, { code: 'EK_CONFIG_INVALID' });
  assert.equal(f.calls.length, before);
  await c.close();
  assert.throws(() => c.native(), { code: 'EK_RESOURCE_CLOSED' });
  await assert.rejects(c.findOne('records', {}), { code: 'EK_RESOURCE_CLOSED' });
  assert.throws(() => c.start(), { code: 'EK_RESOURCE_CLOSED' });
});

test('MongoDB native admission remains held after a caller aborts non-abortable writes', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  const gate = deferred(),
    controller = new AbortController();
  for (let index = 0; index < 128; index++) f.plan('insertOne', { gate: gate.promise });
  const calls = Array.from({ length: 128 }, () =>
    c.insertOne('records', {}, { signal: controller.signal }),
  );
  const handled = Promise.allSettled(calls);
  await delay(0);
  assert.equal(c.stats().nativePending, 128);
  controller.abort();
  const results = await handled;
  assert.ok(results.every((result) => result.status === 'rejected'));
  assert.equal(c.stats().pending, 128);
  await assert.rejects(c.insertOne('records', {}), { code: 'EK_DATABASE_UNAVAILABLE' });
  gate.resolve();
  const deadline = performance.now() + 3000;
  while (c.stats().nativePending) {
    assert.ok(performance.now() < deadline);
    await delay(5);
  }
  assert.equal(c.stats().pending, 0);
  assert.equal(await c.findOne('records', {}), null);
});

test('MongoDB normal shutdown observes pending native settlements without treating cancellation as cleanup failure', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  const gate = deferred();
  f.plan('insertOne', { gate: gate.promise });
  const work = c.insertOne('records', {});
  const rejected = assert.rejects(work);
  await delay(0);
  const closing = c.close();
  gate.resolve();
  await rejected;
  await closing;
  assert.equal(c.stats().nativePending, 0);
});

test('MongoDB rejects malformed native acknowledgments and never truncates an oversized or unproved result', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  for (const [method, value, work] of [
    ['insertOne', { acknowledged: false }, () => c.insertOne('records', {})],
    ['insertOne', { acknowledged: true }, () => c.insertOne('records', {})],
    [
      'updateOne',
      { acknowledged: true, modifiedCount: 2 },
      () => c.updateOne('records', {}, { $set: { value: 1 } }),
    ],
    [
      'updateOne',
      { acknowledged: false },
      () => c.updateOne('records', {}, { $set: { value: 1 } }),
    ],
    ['deleteOne', { acknowledged: true, deletedCount: -1 }, () => c.deleteOne('records', {})],
    ['deleteOne', { acknowledged: false }, () => c.deleteOne('records', {})],
  ] as const) {
    f.plan(method, { value });
    await assert.rejects(work, { code: 'EK_DOCUMENT_OPERATION' });
  }
  f.plan('next', { value: [] });
  await assert.rejects(c.findOne('records', {}), { code: 'EK_DOCUMENT_OPERATION' });
  f.plan('next', { value: { bytes: Buffer.alloc(1_048_576) } });
  await assert.rejects(c.findOne('records', {}), { code: 'EK_DOCUMENT_OPERATION' });
  f.plan('next', { value: { row: 1 } });
  f.plan('next', { value: { row: 2 } });
  await assert.rejects(c.aggregate('records', [{ $limit: 1 }]), { code: 'EK_DOCUMENT_OPERATION' });
});

test('MongoDB cursor and native pool cleanup failures retain their causes and terminal lifecycle', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  f.allowCloseFailure();
  const original = AbstractCursor.prototype.close;
  context.mock.method(AbstractCursor.prototype, 'close', async function (this: AbstractCursor) {
    await original.call(this);
    throw new Error('Native cursor close failed');
  });
  await assert.rejects(c.findOne('records', {}));
  await assert.rejects(c.close(), { code: 'EK_DATABASE_UNAVAILABLE' });
  assert.ok(c.stats().cleanupFailures! > 0);
});

test('MongoDB readiness and close errors remain visible and startup stays single-flight', async (context) => {
  const f = nativeDouble(context),
    c = f.connection,
    gate = deferred();
  f.plan('connect', { gate: gate.promise });
  const first = c.start();
  assert.equal(c.start(), first);
  gate.resolve();
  await first;
  context.mock.method(MongoClient.prototype, 'close', async () => {
    throw new Error('Native pool close failed');
  });
  f.allowCloseFailure();
  await assert.rejects(c.close(), { code: 'EK_DATABASE_UNAVAILABLE' });
});

test('MongoDB observation uses seconds and milliseconds once and never exposes document values', async (context) => {
  const histograms: number[] = [],
    usage: number[] = [],
    operations: string[] = [],
    missing: string[] = [],
    logs: unknown[] = [];
  const session = {
    recordOperation(name: string) {
      operations.push(name);
    },
    recordUsage(_name: string, value: { value: number }) {
      usage.push(value.value);
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
    warn(message: string, fields: unknown) {
      logs.push({ message, fields });
    },
  } as unknown as Logger;
  const f = nativeDouble(context, { meter, telemetry, logger });
  await f.connection.start();
  await f.connection.insertOne('records', { value: 'private-document' });
  assert.deepEqual(operations, ['db.query']);
  assert.equal(histograms[0], usage[0]! / 1000);
  assert.ok(missing.includes('driver_bytes_unavailable'));
  f.plan('insertOne', { fail: true, error: new MongoNetworkError('private-document') });
  await assert.rejects(f.connection.insertOne('records', { value: 'private-document' }));
  assert.equal(JSON.stringify(logs).includes('private-document'), false);
});

test('MongoDB rejects transactions before readiness and on standalone topology without invoking callbacks', async (context) => {
  const f = nativeDouble(context);
  let calls = 0;
  await assert.rejects(
    f.connection.withTransaction(async () => {
      calls++;
    }),
    { code: 'EK_LIFECYCLE_STATE' },
  );
  f.plan('command', { value: { ok: 1, isWritablePrimary: true } });
  await f.connection.start();
  await assert.rejects(
    f.connection.withTransaction(async () => {
      calls++;
    }),
    { code: 'EK_UNSUPPORTED_CAPABILITY' },
  );
  assert.equal(calls, 0);
  assert.equal(f.connection.stats().sessions, 0);
});

test('MongoDB atomically bounds concurrent transaction creation and releases all native session reservations', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  const gate = deferred();
  let entered = 0;
  const transactions = Array.from({ length: 9 }, () =>
    c.withTransaction(async () => {
      entered++;
      await gate.promise;
      return 42;
    }),
  );
  const settled = Promise.allSettled(transactions);
  await delay(0);
  assert.equal(c.stats().sessions, 8);
  assert.equal(entered, 8);
  await assert.rejects(
    c.withTransaction(async () => 0),
    { code: 'EK_DATABASE_UNAVAILABLE' },
  );
  gate.resolve();
  const results = await settled;
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 8);
  assert.equal(c.stats().sessions, 0);
});

test('MongoDB rejects synchronous transaction callbacks and callback-owned lifecycle changes without replay', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  await assert.rejects(c.withTransaction((() => 42) as never), { code: 'EK_CONFIG_INVALID' });
  let calls = 0;
  await assert.rejects(
    c.withTransaction(async (value) => {
      assert.ok(value instanceof ClientSession);
      calls++;
      await value.abortTransaction();
      return 42;
    }),
    { code: 'EK_DATABASE_TRANSACTION' },
  );
  assert.equal(calls, 1);
  assert.equal(c.stats().sessions, 0);
});

test('MongoDB reports transaction abort and end-session failures instead of claiming a successful release', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  f.allowCloseFailure();
  context.mock.method(ClientSession.prototype, 'abortTransaction', async () => {
    throw new Error('Native abort failed');
  });
  context.mock.method(ClientSession.prototype, 'endSession', async () => {
    throw new Error('Native session close failed');
  });
  await assert.rejects(
    c.withTransaction(async () => {
      throw new Error('The callback failed');
    }),
    (cause: unknown) =>
      cause instanceof KitError &&
      cause.code === 'EK_DATABASE_TRANSACTION' &&
      cause.details.cleanupFailed === true &&
      cause.cause instanceof AggregateError &&
      cause.cause.errors.length === 4,
  );
  await assert.rejects(c.close(), { code: 'EK_DATABASE_UNAVAILABLE' });
});

test('MongoDB readiness failures aggregate cleanup errors and do not activate a stale native handle', async (context) => {
  const f = nativeDouble(context);
  f.allowCloseFailure();
  f.plan('connect', { fail: true, error: new MongoNetworkError('Native startup failed') });
  context.mock.method(MongoClient.prototype, 'close', async () => {
    throw new Error('Startup cleanup failed');
  });
  await assert.rejects(
    f.connection.start(),
    (cause: unknown) =>
      cause instanceof KitError &&
      cause.code === 'EK_DATABASE_CONNECT' &&
      cause.cause instanceof AggregateError,
  );
  assert.throws(() => f.connection.native(), { code: 'EK_RESOURCE_CLOSED' });
});

test('MongoDB closes a connection that finishes startup after its owner has stopped', async (context) => {
  const f = nativeDouble(context),
    gate = deferred();
  f.plan('connect', { gate: gate.promise });
  const starting = f.connection.start(),
    observed = assert.rejects(starting);
  await delay(0);
  const closing = f.connection.close();
  gate.resolve();
  await observed;
  await closing;
  assert.equal(f.connection.stats().ready, 0);
  assert.equal(f.connection.stats().nativePending, 0);
});

test('MongoDB failed diagnostic methods cannot replay work or replace an established native acknowledgment', async (context) => {
  let invocation = 0;
  const telemetry = {
    async withSpan(_name: string, work: () => Promise<unknown>) {
      invocation++;
      await work();
      throw new Error('Trace export failed');
    },
    recordHistogram() {
      throw new Error('Histogram failed');
    },
  } as unknown as Telemetry;
  const meter = {
    current() {
      throw new Error('Meter context failed');
    },
  } as unknown as UsageMeter;
  const logger = {
    warn() {
      throw new Error('Log sink failed');
    },
  } as unknown as Logger;
  const f = nativeDouble(context, { telemetry, meter, logger });
  await f.connection.start();
  assert.equal(await f.connection.insertOne('records', { _id: 'once' }), '"once"');
  assert.equal(invocation, 1);
  assert.equal(f.calls.filter((call) => call.method === 'insertOne').length, 1);
  assert.ok(f.connection.stats().observerFailures! > 0);
});

test('MongoDB incomplete meter quality controls stay diagnostic and delayed wrappers preserve acknowledged results', async (context) => {
  const meter = {
    current: () => ({ recordOperation() {}, recordUsage() {} }),
  } as unknown as UsageMeter;
  const telemetry = {
    async withSpan(_name: string, work: () => Promise<unknown>) {
      await work();
      await delay(30);
    },
    recordHistogram() {},
  } as unknown as Telemetry;
  const f = nativeDouble(context, { meter, telemetry });
  await f.connection.start();
  assert.equal(
    await f.connection.insertOne('records', { _id: 'acknowledged' }, { timeoutMs: 10 }),
    '"acknowledged"',
  );
  assert.equal(f.connection.stats().nativePending, 0);
  assert.ok(f.connection.stats().observerFailures! > 0);
});

test('MongoDB bounded shutdown still attempts native close when arbitrary callback code remains uncooperative', async (context) => {
  const f = nativeDouble(context),
    c = f.connection;
  await c.start();
  f.allowCloseFailure();
  const gate = deferred(),
    work = c.withTransaction(async () => {
      await gate.promise;
      return 1;
    }),
    rejected = assert.rejects(work);
  await delay(0);
  const actual = globalThis.setTimeout;
  let timeout: (() => void) | undefined, timer: ReturnType<typeof setTimeout> | undefined;
  context.mock.method(globalThis, 'setTimeout', (callback: () => void, ms?: number) => {
    const handle = actual(callback, ms);
    if (ms === 20000) {
      timeout = callback;
      timer = handle;
    }
    return handle;
  });
  const closing = c.close();
  await rejected;
  assert.ok(timeout && timer);
  const now = performance.now();
  context.mock.method(performance, 'now', () => now + 20001);
  clearTimeout(timer);
  timeout();
  await assert.rejects(closing, { code: 'EK_DATABASE_UNAVAILABLE' });
  gate.resolve();
  await delay(0);
});
