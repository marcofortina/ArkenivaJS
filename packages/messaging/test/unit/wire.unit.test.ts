import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  encodeMessage,
  decodeMessage,
  messageCorrelation,
  messageTopic,
  MAX_MESSAGE_BYTES,
} from '../../dist/wire.js';

const envelope = (payload: unknown) => ({
  schemaVersion: 1 as const,
  messageId: randomUUID(),
  topic: 'orders.created',
  payload,
});
test('Messaging wire JSON preserves finite values, Unicode, aliases and explicit correlation without minting identity', () => {
  for (const payload of [
    null,
    false,
    true,
    0,
    -1.25,
    '',
    '\uFEFF日本語 😀',
    [],
    [null, false, 42],
    { name: 'Ada' },
  ]) {
    const source = { ...envelope(payload), correlationId: 'request:42' },
      decoded = decodeMessage(encodeMessage(source), source.topic);
    assert.deepEqual(decoded, {
      messageId: source.messageId,
      topic: source.topic,
      payload,
      correlationId: 'request:42',
    });
    assert.equal(Object.hasOwn(decoded, 'tenant'), false);
    assert.ok(Object.isFrozen(decoded));
  }
  const shared = { value: 1 },
    source = envelope([shared, shared]);
  assert.deepEqual(decodeMessage(encodeMessage(source), source.topic).payload, [
    { value: 1 },
    { value: 1 },
  ]);
  const business = envelope({ tenant: { tenantId: 'untrusted-business-data' } });
  assert.equal(decodeMessage(encodeMessage(business), business.topic).tenant, undefined);
});

test('Messaging wire encoding never executes getters or custom serializers and rejects non-JSON values', () => {
  let invoked = 0;
  const accessor = Object.defineProperty({}, 'secret', {
    get() {
      invoked++;
      return 'private';
    },
  });
  const serializer = {
    toJSON() {
      invoked++;
      return 'private';
    },
  };
  const sparse = new Array(2),
    named: unknown[] = [1];
  Object.defineProperty(named, 'extra', { value: 1 });
  const symbolic = { [Symbol('hidden')]: 1 },
    cycle: unknown[] = [];
  cycle.push(cycle);
  const prototypeKey = JSON.parse('{"__proto__":{"polluted":true}}');
  for (const value of [
    undefined,
    1n,
    NaN,
    Infinity,
    -Infinity,
    Symbol('data'),
    () => true,
    new Date(),
    new Map(),
    new Set(),
    accessor,
    serializer,
    sparse,
    named,
    symbolic,
    cycle,
    prototypeKey,
  ])
    assert.throws(() => encodeMessage(envelope(value)), { code: 'EK_CONFIG_INVALID' });
  assert.equal(invoked, 0);
  assert.equal(({} as { polluted?: boolean }).polluted, undefined);
});

test('Messaging bounds aggregate bytes, JSON escape expansion, depth, item counts and object field counts', () => {
  let deep: unknown = null;
  for (let index = 0; index < 66; index++) deep = [deep];
  const wide = Object.fromEntries(
    Array.from({ length: 10002 }, (_, index) => ['field' + index, index]),
  );
  for (const value of [
    deep,
    wide,
    new Array(10001).fill(null),
    'a'.repeat(MAX_MESSAGE_BYTES),
    '\0'.repeat(200000),
    new Array(20).fill('x'.repeat(100000)),
    new Array(10000).fill(new Array(10).fill(null)),
  ])
    assert.throws(() => encodeMessage(envelope(value)), { code: 'EK_CONFIG_INVALID' });
});

test('Messaging wire decode rejects untrusted schema, topic confusion, prototype fields and invalid UTF-8', () => {
  const source = envelope({ orderId: '42' });
  for (const value of [
    null,
    {},
    { ...source, schemaVersion: 2 },
    { ...source, tenant: { tenantId: 'spoof' } },
    { ...source, extra: true },
    { ...source, messageId: 'wrong' },
    { ...source, messageId: source.messageId + '\n' },
    { ...source, topic: 'different' },
    { ...source, correlationId: 'bad\n' },
    { ...source, payload: { constructor: 'invalid' } },
  ])
    assert.throws(() => decodeMessage(Buffer.from(JSON.stringify(value)), source.topic), {
      code: 'EK_BACKEND_UNAVAILABLE',
    });
  for (const bytes of [
    Buffer.from('{'),
    Buffer.from([255]),
    Buffer.alloc(MAX_MESSAGE_BYTES + 1),
    'wrong' as never,
    Buffer.from(JSON.stringify(source).replace('"42"', '1e10000')),
  ])
    assert.throws(() => decodeMessage(bytes, source.topic), { code: 'EK_BACKEND_UNAVAILABLE' });
});

test('Messaging literal subject and correlation validation cannot accept wildcard or trailing line escapes', () => {
  for (const value of ['a', 'a.b_c-1', 'A.B']) assert.equal(messageTopic(value), value);
  for (const value of [undefined, 'a', 'request-42', 'a'.repeat(128)])
    assert.equal(messageCorrelation(value), value);
  for (const value of [
    '',
    '.',
    'a..b',
    'a.*',
    'a.>',
    'a b',
    'a\r',
    'a\n',
    'a\0',
    '日本語',
    'a'.repeat(257),
    42,
  ])
    assert.throws(() => messageTopic(value as never), { code: 'EK_CONFIG_INVALID' });
  for (const value of ['', 'a\n', 'a\r', 'a b', 'a'.repeat(129), 42])
    assert.throws(() => messageCorrelation(value as never), { code: 'EK_CONFIG_INVALID' });
});
