// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { SqlProvider } from '@arkenivajs/core';
import { createPostgresSecurityStateStore } from '../../dist/security-state-store.js';
import type { SecurityAtomicMutation } from '../../dist/security-state-store.js';

const schema = 'security_' + 'a'.repeat(24),
  owner = 'a'.repeat(64),
  ns = 'security-test';
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
function disposable(t: TestContext) {
  const before = process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  process.env.ARKENIVA_POSTGRES_DISPOSABLE = '1';
  t.after(() => {
    if (before === undefined) delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
    else process.env.ARKENIVA_POSTGRES_DISPOSABLE = before;
  });
}
function backend(failure: unknown = new Error('Private SQL diagnostic')) {
  let calls = 0;
  const fail = async () => {
    calls++;
    throw failure;
  };
  const sql: SqlProvider = {
    query: fail,
    queryOne: fail,
    execute: fail,
    transaction: fail,
    ping: fail,
    stats: () => ({}),
    native: () => undefined,
  };
  return { sql, calls: () => calls };
}
test('Security state rejects unsafe schema, absent authorization and malformed providers without I/O', (t) => {
  disposable(t);
  const b = backend();
  for (const value of ['public', '../security', schema + ';DROP SCHEMA public'])
    assert.throws(
      () => createPostgresSecurityStateStore(b.sql, 'main', value),
      code('EK_CONFIG_INVALID'),
    );
  assert.throws(
    () => createPostgresSecurityStateStore(undefined as never, 'main', schema),
    code('EK_CONFIG_INVALID'),
  );
  let invoked = 0;
  const accessor = Object.defineProperty({}, 'query', {
    get() {
      invoked++;
    },
  });
  assert.throws(
    () => createPostgresSecurityStateStore(accessor as SqlProvider, 'main', schema),
    code('EK_CONFIG_INVALID'),
  );
  delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  assert.throws(
    () => createPostgresSecurityStateStore(b.sql, 'main', schema),
    code('EK_CONFIG_INVALID'),
  );
  assert.equal(invoked, 0);
  assert.equal(b.calls(), 0);
});
test('Security state validates version, owner, bounds and lossless JSON before accessing SQL', async (t) => {
  disposable(t);
  const b = backend(),
    store = createPostgresSecurityStateStore(b.sql, 'main', schema);
  let invoked = 0;
  const accessor = Object.defineProperty({}, 'payload', {
    enumerable: true,
    get() {
      invoked++;
      throw new Error('Getter must not execute');
    },
  });
  for (const value of [
    {},
    { ownerKey: 'short' },
    { ownerKey: owner, version: randomUUID() },
    { ownerKey: owner, undefinedValue: undefined },
    { ownerKey: owner, value: NaN },
    { ownerKey: owner, value: -0 },
    { ownerKey: owner, value: 1n },
    { ownerKey: owner, value: new Date() },
    { ownerKey: owner, value: '\u0000' },
    { ownerKey: owner, value: '\ud800' },
    { ownerKey: owner, values: Array(1) },
    { ownerKey: owner, payload: 'x'.repeat(32769) },
    { ownerKey: owner, expiresAt: '2026-02-30T00:00:00.000Z' },
    accessor,
  ])
    await assert.rejects(store.compareAndSet(ns, 'record', null, value), code('EK_CONFIG_INVALID'));
  await assert.rejects(
    store.compareAndSet(ns, 'record', 'forged-version', { ownerKey: owner }),
    code('EK_CONFIG_INVALID'),
  );
  for (const limit of [0, 1.5, 1001, Infinity])
    await assert.rejects(store.listByOwner(ns, owner, limit), code('EK_CONFIG_INVALID'));
  await assert.rejects(
    store.claimOnce(ns, 'short', new Date(Date.now() + 10000).toISOString()),
    code('EK_CONFIG_INVALID'),
  );
  await assert.rejects(store.read('../scope', 'record'), code('EK_CONFIG_INVALID'));
  assert.equal(invoked, 0);
  assert.equal(b.calls(), 0);
});
test('Security batch rejects holes, duplicate keys, missing ownership and excessive mutations before SQL', async (t) => {
  disposable(t);
  const b = backend(),
    store = createPostgresSecurityStateStore(b.sql, 'main', schema);
  const mutation: SecurityAtomicMutation = {
    namespace: ns,
    id: 'record',
    expectedVersion: null,
    ownerKey: owner,
    next: { value: true },
  };
  for (const values of [
    [],
    Array(1),
    [mutation, mutation],
    Array(33).fill(mutation),
    [{ ...mutation, ownerKey: '' }],
    [{ ...mutation, next: { ownerKey: 'b'.repeat(64) } }],
    [{ ...mutation, next: { ownerKey: null } }],
    [{ ...mutation, next: { payload: 'x'.repeat(32745) } }],
    [
      {
        ...mutation,
        next: Object.fromEntries(Array.from({ length: 64 }, (_, index) => ['field' + index, true])),
      },
    ],
    [{ ...mutation, extra: true }],
  ])
    await assert.rejects(store.atomicBatch(values), code('EK_CONFIG_INVALID'));
  assert.equal(b.calls(), 0);
});
test('Security state rejects zero deadlines, accessor options and forged signals before database work', async (t) => {
  disposable(t);
  const b = backend(),
    store = createPostgresSecurityStateStore(b.sql, 'main', schema);
  let invoked = 0;
  const accessor = () => {
    invoked++;
    throw new Error('Private option getter');
  };
  const options = Object.defineProperty({}, 'timeoutMs', { get: accessor, enumerable: true }),
    controller = new AbortController();
  Object.defineProperty(controller.signal, 'aborted', { get: accessor });
  for (const value of [
    { timeoutMs: 0 },
    { timeoutMs: 5001 },
    options,
    { signal: {} },
    { signal: controller.signal },
    { now: Date.now() },
  ])
    await assert.rejects(store.read(ns, 'record', value as never), code('EK_CONFIG_INVALID'));
  const cancelled = new AbortController();
  cancelled.abort();
  await assert.rejects(store.read(ns, 'record', { signal: cancelled.signal }), code('EK_ABORTED'));
  assert.equal(invoked, 0);
  assert.equal(b.calls(), 0);
});
test('Security persistence errors expose no private cause and retain uncertainty rather than acknowledge writes', async (t) => {
  disposable(t);
  const b = backend(),
    store = createPostgresSecurityStateStore(b.sql, 'main', schema);
  await assert.rejects(store.compareAndSet(ns, 'record', null, { ownerKey: owner }), (error) => {
    assert.ok(code('EK_DATABASE_UNAVAILABLE')(error));
    assert.ok(error instanceof KitError);
    assert.equal(error.cause, undefined);
    assert.equal(error.details.outcome, 'unknown');
    return true;
  });
  assert.equal(b.calls(), 1);
  const timeout = new KitError({ code: 'EK_TIMEOUT', message: 'Private timeout reason' });
  const failing = createPostgresSecurityStateStore(backend(timeout).sql, 'main', schema);
  await assert.rejects(failing.bumpOwnerEpoch(ns, owner), (error) => {
    assert.ok(code('EK_TIMEOUT')(error));
    assert.ok(error instanceof KitError);
    assert.equal(error.cause, undefined);
    assert.equal(error.details.outcome, 'unknown');
    return true;
  });
  await assert.rejects(failing.read(ns, 'record'), (error) => {
    assert.ok(code('EK_TIMEOUT')(error));
    assert.ok(error instanceof KitError);
    assert.equal(error.details.outcome, undefined);
    return true;
  });
});

test('Security storage retains finite admission after timeout until an uncooperative backend actually settles', async (t) => {
  disposable(t);
  let release!: () => void,
    entered = 0,
    ready!: () => void;
  const held = new Promise<void>((resolve) => {
      release = resolve;
    }),
    allEntered = new Promise<void>((resolve) => {
      ready = resolve;
    });
  const b = backend();
  let hanging = true;
  b.sql.queryOne = async <T extends object>() => {
    if (hanging) {
      entered++;
      if (entered === 16) ready();
      await held;
    }
    return null as T | null;
  };
  const store = createPostgresSecurityStateStore(b.sql, 'main', schema),
    controller = new AbortController();
  const pending = Array.from({ length: 16 }, () =>
    store.read(ns, 'record', { signal: controller.signal }),
  );
  const rejected = pending.map((promise) => assert.rejects(promise, code('EK_ABORTED')));
  try {
    await allEntered;
    await assert.rejects(store.read(ns, 'record'), code('EK_BACKEND_UNAVAILABLE'));
    controller.abort();
    await Promise.all(rejected);
    await assert.rejects(store.read(ns, 'record'), code('EK_BACKEND_UNAVAILABLE'));
    release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    hanging = false;
    assert.equal(await store.read(ns, 'record'), null);
  } finally {
    release();
  }
});
test('Security storage does not initiate cancelled work or acknowledge a provider response after its deadline', async (t) => {
  disposable(t);
  const b = backend();
  let calls = 0;
  b.sql.queryOne = async <T extends object>() => {
    calls++;
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    return { epoch: '1' } as unknown as T;
  };
  const store = createPostgresSecurityStateStore(b.sql, 'main', schema),
    controller = new AbortController();
  const pending = store.currentOwnerEpoch(ns, owner, { signal: controller.signal });
  const rejected = assert.rejects(pending, code('EK_ABORTED'));
  controller.abort();
  await rejected;
  assert.equal(calls, 0);
  await assert.rejects(store.bumpOwnerEpoch(ns, owner, { timeoutMs: 5 }), (error) => {
    assert.ok(code('EK_TIMEOUT')(error));
    assert.ok(error instanceof KitError);
    assert.equal(error.details.outcome, 'unknown');
    return true;
  });
  await new Promise<void>((resolve) => setTimeout(resolve, 25));
  assert.equal(calls, 1);
});
