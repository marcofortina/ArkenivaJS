import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ConfigStore, copyData, mergeData, compileSchema, within } from '@arkenivajs/core/support';
import { KitError } from '@arkenivajs/core';

const schema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    count: { type: 'integer', minimum: 0 },
    nullable: { type: ['string', 'null'] },
    nested: {
      type: 'object',
      properties: { value: { type: 'number' }, password: { type: 'string' } },
      additionalProperties: false,
    },
    token: { type: 'string' },
  },
};
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('Configuration getters distinguish missing, null and immutable values', () => {
  const store = new ConfigStore<Record<string, unknown>>(
    {
      count: 1,
      nullable: null,
      nested: { value: 2, password: 'fake-password' },
      token: 'fake-token',
    },
    { schema },
  );
  assert.equal(store.get('count'), 1);
  assert.equal(store.require('count'), 1);
  assert.equal(store.get('missing'), undefined);
  assert.equal(store.has('missing'), false);
  assert.equal(store.has('nullable'), true);
  assert.throws(() => store.require('missing'), code('EK_CONFIG_MISSING'));
  assert.throws(() => store.require('nullable'), code('EK_CONFIG_MISSING'));
  assert.ok(Object.isFrozen(store.get('nested')));
  assert.ok(Object.isFrozen(store.snapshot()));
  assert.ok(Object.isFrozen(store.snapshot().nested));
  assert.ok(!JSON.stringify(store.snapshot()).includes('fake-'));
});

test('Configuration reload validates atomically and leaves previous generations untouched', async () => {
  const store = new ConfigStore<Record<string, unknown>>(
    { count: 1, nested: { value: 1 } },
    {
      schema,
      dynamicPaths: ['count', 'nested.value'],
      preflight(next) {
        if (next.count === 8) throw new Error('rejected');
      },
    },
  );
  const before = store.snapshot();
  await Promise.all([store.reload({ count: 2 }), store.reload({ nested: { value: 3 } })]);
  assert.equal(before.count, 1);
  assert.equal(store.get('count'), 2);
  assert.deepEqual(store.get('nested'), { value: 3 });
  const current = store.snapshot();
  for (const invalid of [
    { count: -1 },
    { count: 8 },
    { nullable: 'static' },
    { token: 'fake' },
    { unknown: true },
  ])
    await assert.rejects(store.reload(invalid), code('EK_CONFIG_RELOAD_REJECTED'));
  assert.equal(current, store.snapshot());
  await store.reload({ count: 5 });
  await store.reload({ count: 5 });
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  await assert.rejects(store.reload(cyclic), code('EK_CONFIG_RELOAD_REJECTED'));
});

test('Data utilities reject cyclic, executable and non-finite inputs before serialization', () => {
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  for (const value of [
    cycle,
    new Date(),
    {
      get value() {
        throw new Error('getter executed');
      },
    },
    JSON.parse('{"__proto__":1}'),
    { value: Infinity },
    { value() {} },
    { value: Symbol() },
    { value: 1n },
  ])
    assert.throws(() => copyData(value), code('EK_CONFIG_INVALID'));
  assert.throws(() => compileSchema({ type: 'imaginary' }), code('EK_CONFIG_INVALID'));
  assert.deepEqual(
    mergeData({ nested: { value: 1 }, array: [1] }, { nested: { value: 2 }, array: [2] }),
    { nested: { value: 2 }, array: [2] },
  );
  assert.deepEqual(copyData(Object.create(null)), {});
});

test('Bounded operations preserve values and reject failure, abort and timeout', async () => {
  assert.equal(await within(() => 42), 42);
  await assert.rejects(
    within(() => {
      throw new Error('failed');
    }),
    /failed/,
  );
  await assert.rejects(
    within(() => 0, { timeoutMs: 0 }),
    code('EK_CONFIG_INVALID'),
  );
  await assert.rejects(
    within(() => 0, { signal: AbortSignal.abort('cancelled') }),
    code('EK_ABORTED'),
  );
  await assert.rejects(
    within(() => new Promise(() => {}), { timeoutMs: 5 }),
    code('EK_TIMEOUT'),
  );
  const controller = new AbortController();
  const work = within(() => new Promise(() => {}), { signal: controller.signal });
  controller.abort();
  await assert.rejects(work, code('EK_ABORTED'));
});

test('Dynamic parent paths cannot bypass redaction or sensitive reload restrictions', async () => {
  const store = new ConfigStore<Record<string, unknown>>(
    { nested: { password: 'fake-password' } },
    { schema, dynamicPaths: ['nested'] },
  );
  await assert.rejects(
    store.reload({ nested: { password: 'changed' } }),
    code('EK_CONFIG_RELOAD_REJECTED'),
  );
  const custom = new ConfigStore<Record<string, unknown>>(
    { nested: { value: 1 } },
    { schema, dynamicPaths: ['nested'], secretPaths: ['nested.value'] },
  );
  await assert.rejects(custom.reload({ nested: { value: 2 } }), code('EK_CONFIG_RELOAD_REJECTED'));
});

test('Hung reload preflight preserves the active generation and releases the queue', async () => {
  const store = new ConfigStore(
    { count: 1 },
    {
      schema,
      dynamicPaths: ['count'],
      preflightTimeoutMs: 5,
      preflight(next) {
        if (next.count === 2) return new Promise<void>(() => {});
      },
    },
  );
  const before = store.snapshot();
  await assert.rejects(store.reload({ count: 2 }), code('EK_CONFIG_RELOAD_REJECTED'));
  assert.equal(store.snapshot(), before);
  await store.reload({ count: 3 });
  assert.equal(store.get('count'), 3);
  assert.throws(
    () => new ConfigStore({ count: 1 }, { schema, preflightTimeoutMs: 0 }),
    code('EK_CONFIG_INVALID'),
  );
});
