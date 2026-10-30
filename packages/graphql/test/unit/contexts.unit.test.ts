// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OwnedContexts } from '../../dist/contexts.js';
import { buildSchema, execute, parse } from 'graphql';
import { bindMetadata, installMetadata } from '../../dist/metadata.js';
import { Operation } from '../../dist/operation.js';
import { capture } from '../../dist/policy.js';
import { setTimeout as delay } from 'node:timers/promises';

test('Copied ownership symbols cannot turn primitive, executable or proxied anchors into a live context', () => {
  const owned = new OwnedContexts<{ request: number }>(),
    context = {};
  let reads = 0,
    traps = 0;
  const release = owned.bind(context, () => {
    reads++;
    return { request: 1 };
  });
  const key = Object.getOwnPropertySymbols(context)[0]!;
  const hostile = () => {
    traps++;
    throw new Error('Context anchor reflection must not execute');
  };
  try {
    for (const anchor of [
      undefined,
      null,
      1,
      'owned',
      () => {},
      new Proxy({}, { get: hostile, getOwnPropertyDescriptor: hostile, getPrototypeOf: hostile }),
    ]) {
      const forged = { [key]: anchor };
      assert.equal(owned.owns(forged), true);
      assert.equal(owned.get(forged), undefined);
    }
    assert.equal(reads, 0);
    assert.equal(traps, 0);
    assert.deepEqual(owned.get({ ...context }), { request: 1 });
    assert.equal(reads, 1);
  } finally {
    release();
  }
});

test('An already aborted owner and an elapsed monotonic deadline deny resolver work before any effect', async () => {
  const limits = capture({
    schema: 'type Query { ping: String }',
    resolvers: {},
    security: { authorizeField: () => true },
  }).security.limits;
  const aborted = new Operation({ requestId: 'pre-aborted' }, limits, AbortSignal.abort());
  const expired = new Operation(
    { requestId: 'expired' },
    { ...limits, maxOperationMs: 1 },
    new AbortController().signal,
  );
  let effects = 0;
  try {
    await assert.rejects(
      aborted.run(() => {
        effects++;
      }),
      { code: 'EK_GQL_TIMEOUT' },
    );
    await delay(5);
    await assert.rejects(
      expired.run(() => {
        effects++;
      }),
      { code: 'EK_GQL_TIMEOUT' },
    );
    assert.equal(aborted.context.signal.aborted, true);
    assert.equal(expired.context.signal.aborted, true);
    assert.equal(effects, 0);
  } finally {
    aborted.end();
    expired.end();
    await Promise.all([aborted.completion, expired.completion]);
  }
});

test('Owned execution contexts follow native shallow copies and resolve only the current event scope', () => {
  const owned = new OwnedContexts<{ event: number }>();
  let current: { event: number } | undefined = { event: 1 };
  const first = {},
    second = {};
  const retireFirst = owned.bind(first, () => current);
  const retireSecond = owned.bind(second, () => ({ event: 99 }));
  const copied = { ...first },
    copiedAgain = { ...copied };
  assert.equal(owned.get(copied), current);
  current = { event: 2 };
  assert.equal(owned.get(copiedAgain), current);
  current = undefined;
  assert.equal(owned.get(copied), undefined, 'Between events there is no authorized scope');
  current = { event: 3 };
  retireFirst();
  retireFirst();
  assert.equal(
    owned.owns(copiedAgain),
    true,
    'Retirement cannot fall through to unguarded native metadata',
  );
  assert.equal(owned.owns({}), false);
  for (const context of [first, copied, copiedAgain]) assert.equal(owned.get(context), undefined);
  assert.deepEqual(owned.get({ ...second }), { event: 99 });
  retireSecond();
  assert.equal(owned.get(second), undefined);
});

test('Client-like objects, serialization, inherited properties, accessors and proxies cannot forge ownership', () => {
  const owned = new OwnedContexts<{ tenant: string }>();
  const other = new OwnedContexts<{ tenant: string }>();
  const context = {};
  const value = { tenant: 'tenant-a' };
  const retire = owned.bind(context, () => value);
  assert.equal(other.get(context), undefined);
  assert.equal(owned.get({ tenant: 'tenant-a', identity: { tenant: 'tenant-a' } }), undefined);
  assert.equal(owned.get(JSON.parse(JSON.stringify(context)) as object), undefined);
  assert.equal(owned.get(Object.create(context) as object), undefined);
  let calls = 0;
  const symbol = Object.getOwnPropertySymbols(context)[0]!;
  const accessor = Object.defineProperty({}, symbol, {
    get() {
      calls++;
      return value;
    },
  });
  assert.equal(owned.get(accessor), undefined);
  const proxy = new Proxy(context, {
    getOwnPropertyDescriptor() {
      calls++;
      return undefined;
    },
  });
  assert.equal(owned.get(proxy), undefined);
  assert.throws(() => owned.bind(proxy, () => value));
  assert.equal(calls, 0);
  assert.throws(() => owned.bind(context, () => value));
  assert.throws(() => owned.set({ ...context }, value));
  retire();
});

test('Direct HTTP scopes remain isolated and cannot be replaced by a copied binding', () => {
  const owned = new OwnedContexts<{ request: number }>();
  const context = {},
    separate = {};
  const value = { request: 1 };
  owned.set(context, value);
  owned.set(separate, { request: 2 });
  assert.equal(owned.get(context), value);
  assert.equal(owned.get({ ...context }), undefined);
  assert.deepEqual(owned.get(separate), { request: 2 });
  assert.throws(() => owned.bind(context, () => ({ request: 3 })));
});

test('Native metadata execution fails closed between events and after retirement without affecting unrelated schemas', async () => {
  let reads = 0;
  const settings = capture({
    schema: 'type Query { ping: String }',
    resolvers: {},
    security: {
      authorizeField: () => {
        reads++;
        return true;
      },
    },
  });
  const scope = new Operation(
    { requestId: 'metadata-event' },
    settings.security.limits,
    new AbortController().signal,
  );
  const schema = buildSchema(settings.schema),
    document = parse('{ __typename }');
  let active = true;
  const context = {};
  installMetadata();
  const retire = bindMetadata(context, () =>
    active
      ? {
          scope,
          settings,
          authorizeIntrospection() {
            throw new Error('Administrative metadata is disabled');
          },
        }
      : undefined,
  );
  const nativeCopy = { ...context };
  try {
    assert.deepEqual(
      { ...(await execute({ schema, document, contextValue: nativeCopy })).data },
      {
        __typename: 'Query',
      },
    );
    assert.equal(reads, 1);
    active = false;
    const between = await execute({ schema, document, contextValue: nativeCopy });
    assert.equal(between.data, null);
    assert.equal(between.errors?.length, 1);
    active = true;
    retire();
    const retired = await execute({ schema, document, contextValue: nativeCopy });
    assert.equal(retired.data, null);
    assert.equal(retired.errors?.length, 1);
    assert.equal(reads, 1);
    const independent = await execute({ schema, document, contextValue: {} });
    assert.equal(independent.errors, undefined);
    assert.deepEqual({ ...independent.data }, { __typename: 'Query' });
  } finally {
    retire();
    scope.end();
    await scope.completion;
  }
});
