import test from 'node:test';
import assert from 'node:assert/strict';
import { BSON } from 'mongodb';
import {
  mongoDocument,
  mongoCollection,
  mongoOptions,
  mongoPipeline,
  mongoInsertedId,
} from '../../dist/common.js';

test('MongoDB captures exact budgets and validates bounded Unicode collection namespaces', () => {
  const controller = new AbortController(),
    options = { timeoutMs: 25, signal: controller.signal };
  const copied = mongoOptions(options);
  options.timeoutMs = 100;
  assert.equal(copied.timeoutMs, 25);
  assert.equal(copied.signal, controller.signal);
  assert.equal(mongoOptions().timeoutMs, 15000);
  assert.equal(mongoOptions(undefined, 5000).timeoutMs, 5000);
  assert.equal(mongoCollection('客户.orders', 'tenant_', 'records'), 'tenant_客户.orders');
  for (const value of [
    null,
    [],
    1,
    'bad',
    { timeoutMs: 0 },
    { timeoutMs: NaN },
    { timeoutMs: 1.5 },
    { timeoutMs: Number.MAX_SAFE_INTEGER + 1 },
    { signal: {} },
  ])
    assert.throws(() => mongoOptions(value as never), { code: 'EK_CONFIG_INVALID' });
  for (const name of [
    '',
    'system.users',
    'bad$collection',
    'bad\0name',
    'bad\nname',
    '\ud800',
    'a'.repeat(235),
  ])
    assert.throws(() => mongoCollection(name, 'prefix_', 'records'), { code: 'EK_CONFIG_INVALID' });
  assert.throws(() => mongoCollection('users', 'system.', 'records'), {
    code: 'EK_CONFIG_INVALID',
  });
});

test('MongoDB snapshots preserve actual BSON classes and isolate mutable identifier, binary and date inputs', () => {
  const id = new BSON.ObjectId(),
    exact = BSON.Long.fromString('9007199254740993'),
    decimal = BSON.Decimal128.fromString('1234567890.123456789'),
    binary = new BSON.Binary(Buffer.from([0, 255])),
    date = new Date('2026-10-25T00:00:00Z');
  const source = {
    id,
    exact,
    decimal,
    binary,
    date,
    integer: new BSON.Int32(42),
    double: new BSON.Double(0.25),
    regexp: new BSON.BSONRegExp('^value', 'i'),
    value: 42,
    children: [{ enabled: true }],
    bigint: 9_223_372_036_854_775_807n,
  };
  const row = mongoDocument(source);
  assert.ok(row.id instanceof BSON.ObjectId && row.id.equals(id));
  assert.ok(row.exact instanceof BSON.Long);
  assert.equal(row.exact.toString(), exact.toString());
  assert.ok(row.decimal instanceof BSON.Decimal128);
  assert.equal(row.decimal.toString(), decimal.toString());
  assert.ok(row.integer instanceof BSON.Int32 && row.integer.valueOf() === 42);
  assert.ok(row.value instanceof BSON.Int32 && row.value.valueOf() === 42);
  assert.ok(row.double instanceof BSON.Double && row.double.valueOf() === 0.25);
  assert.ok(row.bigint instanceof BSON.Long && row.bigint.toString() === '9223372036854775807');
  binary.buffer[0] = 99;
  date.setUTCFullYear(2000);
  source.children[0]!.enabled = false;
  assert.ok(row.binary instanceof BSON.Binary);
  assert.equal(row.binary.buffer[0], 0);
  assert.ok(row.date instanceof Date);
  assert.equal(row.date.getUTCFullYear(), 2026);
  assert.notEqual(row.children, source.children);
});

test('MongoDB validation cannot execute custom serializers, accessors or typed-value overrides', () => {
  let calls = 0;
  const getter = Object.defineProperty({}, 'secret', {
    enumerable: true,
    get() {
      calls++;
      return 'private';
    },
  });
  const serializer = {
    toBSON() {
      calls++;
      return { safe: true };
    },
  };
  const binary = new Uint8Array([1]);
  Object.defineProperty(binary, 'byteLength', {
    get() {
      calls++;
      return 1;
    },
  });
  const date = new Date();
  Object.defineProperty(date, 'getTime', {
    get() {
      calls++;
      return () => 0;
    },
  });
  const regex = /safe/;
  Object.defineProperty(regex, 'source', {
    get() {
      calls++;
      return 'unsafe';
    },
  });
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  for (const input of [
    getter,
    serializer,
    { binary },
    { date },
    { regex },
    cyclic,
    JSON.parse('{"__proto__":{"polluted":true}}'),
    { constructor: 'bad' },
    { prototype: 'bad' },
    { value: undefined },
    { value: () => 1 },
    { value: Symbol('bad') },
    { [Symbol('bad')]: 1 },
    Object.create({ inherited: true }),
    { date: new Date(NaN) },
    { value: 1n << 64n },
    { value: -(1n << 64n) },
    { value: '\ud800' },
    { value: new Array(2) },
  ])
    assert.throws(() => mongoDocument(input), { code: 'EK_CONFIG_INVALID' });
  assert.equal(calls, 0);
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
});

test('MongoDB rejects oversized BSON and deeply nested structures before native submission', () => {
  for (const input of [
    null,
    [],
    new Date(),
    1,
    'bad',
    { value: 'x'.repeat(1_048_577) },
    { value: Buffer.alloc(1_048_577) },
    { value: new Array(50_001).fill(1) },
  ])
    assert.throws(() => mongoDocument(input), { code: 'EK_CONFIG_INVALID' });
  let nested: Record<string, unknown> = {};
  const root = nested;
  for (let index = 0; index < 66; index++) {
    const child = {};
    nested.child = child;
    nested = child;
  }
  assert.throws(() => mongoDocument(root), { code: 'EK_CONFIG_INVALID' });
  assert.throws(() => mongoDocument({ value: 'x'.repeat(1_048_570) }), {
    code: 'EK_CONFIG_INVALID',
  });
});

test('MongoDB cardinality proof preserves the supplied stages and accounts for expansion after a limit', () => {
  const stages = [{ $match: { tenant: 'verified' } }, { $limit: 100 }, { $project: { name: 1 } }];
  const before = BSON.EJSON.stringify(stages, { relaxed: false }),
    proof = mongoPipeline(stages);
  assert.equal(proof.maximum, 100);
  assert.equal(proof.writes, false);
  assert.equal(BSON.EJSON.stringify(proof.pipeline, { relaxed: false }), before);
  assert.equal(BSON.EJSON.stringify(stages, { relaxed: false }), before);
  assert.equal(
    mongoPipeline([{ $limit: BSON.Long.fromString('9007199254740993') }, { $limit: 3 }]).maximum,
    3,
  );
  assert.throws(() => mongoPipeline([{ $limit: 2 }, { $unwind: '$items' }]), {
    code: 'EK_CONFIG_INVALID',
  });
  assert.equal(
    mongoPipeline([{ $limit: 2 }, { $unwind: '$items' }, { $limit: 1000 }]).maximum,
    1000,
  );
  assert.equal(mongoPipeline([{ $count: 'total' }]).maximum, 1);
  assert.equal(mongoPipeline([{ $facet: { items: [{ $match: {} }] } }]).maximum, 1);
});

test('MongoDB proves native sampling, bucket and bounded union cardinalities without hidden limits', () => {
  assert.equal(mongoPipeline([{ $sample: { size: 10 } }]).maximum, 10);
  assert.equal(mongoPipeline([{ $sample: { size: 0 } }]).maximum, 0);
  assert.equal(mongoPipeline([{ $bucketAuto: { groupBy: '$amount', buckets: 5 } }]).maximum, 5);
  assert.equal(
    mongoPipeline([{ $bucket: { groupBy: '$amount', boundaries: [0, 10, 20], default: 'other' } }])
      .maximum,
    3,
  );
  assert.equal(
    mongoPipeline([{ $bucket: { groupBy: '$amount', boundaries: [0, 10, 20] } }]).maximum,
    2,
  );
  assert.equal(
    mongoPipeline([{ $limit: 3 }, { $unionWith: { coll: 'other', pipeline: [{ $limit: 5 }] } }])
      .maximum,
    8,
  );
  assert.throws(() => mongoPipeline([{ $limit: 3 }, { $unionWith: 'other' }]), {
    code: 'EK_CONFIG_INVALID',
  });
  assert.throws(
    () =>
      mongoPipeline([
        { $limit: 999 },
        { $unionWith: { coll: 'other', pipeline: [{ $limit: 2 }] } },
      ]),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.equal(mongoPipeline([{ $merge: 'owned_output' }]).writes, true);
  assert.equal(mongoPipeline([{ $out: 'owned_output' }]).maximum, 0);
});

test('MongoDB rejects absent, malformed, unsafe and unproved aggregation limits', () => {
  for (const input of [
    null,
    {},
    [],
    [{ $match: {} }],
    [{ $limit: 1001 }],
    [{ $limit: 0 }],
    [{ $limit: -1 }],
    [{ $limit: 1.5 }],
    [{ $limit: '2' }],
    [{ $limit: BSON.Long.fromString('-1') }],
    [{ $limit: 2, $match: {} }],
    [{ invalid: 1 }],
    [null],
    [[]],
    [{ $sample: null }],
    [{ $bucket: { boundaries: [0] } }],
    Array(129).fill({ $limit: 1 }),
  ])
    assert.throws(() => mongoPipeline(input as never), { code: 'EK_CONFIG_INVALID' });
});

test('MongoDB inserted identity serialization is typed canonical EJSON for every native ID kind', () => {
  const values = [
    new BSON.ObjectId(),
    'caller-string',
    42,
    BSON.Long.fromString('9007199254740993'),
    BSON.Decimal128.fromString('1.25'),
    new BSON.Binary(Buffer.from([0, 255])),
    { account: 'caller-object' },
    null,
  ];
  const encoded = values.map(mongoInsertedId);
  assert.equal(new Set(encoded).size, values.length);
  for (const id of encoded)
    assert.equal(
      BSON.EJSON.stringify(BSON.EJSON.parse(id, { relaxed: false }), { relaxed: false }),
      id,
    );
  assert.equal(mongoInsertedId('caller-string'), '"caller-string"');
  assert.throws(() => mongoInsertedId(undefined), { code: 'EK_DOCUMENT_OPERATION' });
  assert.throws(() => mongoInsertedId('x'.repeat(1_048_577)), { code: 'EK_DOCUMENT_OPERATION' });
});
