// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { AmqpHeaders } from '../../dist/index.js';
import { outgoing, incoming, ownedBytes } from '../../dist/headers.js';
import { nativeCodec, validateNativeCodec } from '../../dist/native-codec.js';

const code = (error: unknown) => error instanceof KitError && error.code === 'EK_AMQP_PUBLISH';
function nativeRoundtrip(value: object) {
  const buffer = Buffer.alloc(32768),
    size = nativeCodec.encodeTable(buffer, value, 0);
  return nativeCodec.decodeFields(buffer.subarray(4, size));
}
function roundtrip(value: AmqpHeaders) {
  return incoming(nativeRoundtrip(outgoing(value).native));
}
test('An unpatched native installation fails closed before unsafe header normalization', () => {
  validateNativeCodec();
  assert.throws(
    () =>
      validateNativeCodec({
        encodeTable: nativeCodec.encodeTable,
        decodeFields(bytes) {
          const value = nativeCodec.decodeFields(bytes);
          return { integer: Number(value.integer) };
        },
      }),
    (error: unknown) => error instanceof KitError && error.code === 'EK_AMQP_CONFIG',
  );
});
test('AMQP native fields roundtrip binary, exact signed 64-bit boundaries, timestamps and nested values', () => {
  const date = new Date('2026-10-27T12:00:00.000Z'),
    input = {
      text: 'àλ\0value',
      bytes: Uint8Array.of(0, 255, 1),
      minimum: -(1n << 63n),
      maximum: (1n << 63n) - 1n,
      date,
      nil: null,
      yes: true,
      fractional: 1.25,
      zero: -0,
      nested: { list: [1, 'two', null] },
    },
    value = roundtrip(input);
  assert.equal(value.minimum, input.minimum);
  assert.equal(value.maximum, input.maximum);
  assert.deepEqual(value.bytes, input.bytes);
  assert.equal(value.text, input.text);
  assert.ok(value.date instanceof Date);
  assert.equal(value.date.getTime(), date.getTime());
  assert.equal(value.nil, null);
  assert.equal(value.yes, true);
  assert.equal(value.fractional, 1.25);
  assert.ok(Object.is(value.zero, -0));
  assert.ok(Object.isFrozen(value));
  assert.equal(Object.getPrototypeOf(value), null);
  const nested = value.nested as { list: readonly unknown[] };
  assert.deepEqual(nested.list, [1, 'two', null]);
  assert.ok(Object.isFrozen(nested.list));
});
test('The scoped native decoder retains unsafe int64 values without changing safe native numeric results', () => {
  const value = nativeRoundtrip({
    large: { '!': 'int64', value: (1n << 63n) - 1n },
    small: { '!': 'int64', value: 42n },
    negative: { '!': 'int64', value: -(1n << 63n) },
  });
  assert.equal(value.large, (1n << 63n) - 1n);
  assert.equal(value.small, 42);
  assert.equal(value.negative, -(1n << 63n));
});
test('Native decoding preserves hostile field names so the adapter can reject them without prototype mutation', () => {
  const hostile = Object.create(null) as Record<string, unknown>;
  hostile.__proto__ = { inherited: 'blocked' };
  const value = nativeRoundtrip(hostile);
  assert.equal(Object.getPrototypeOf(value), null);
  assert.ok(Object.hasOwn(value, '__proto__'));
  assert.equal(value.inherited, undefined);
  assert.throws(() => incoming(value), code);
  assert.equal(({} as { inherited?: string }).inherited, undefined);
});
test('Public headers and native delivery bytes remain independent of caller and driver-owned storage', () => {
  const input = Uint8Array.of(1, 2, 3),
    encoded = outgoing({ binary: input });
  input.fill(9);
  assert.deepEqual(encoded.native.binary, Buffer.from([1, 2, 3]));
  const native = nativeRoundtrip(encoded.native),
    value = incoming(native);
  assert.ok(native.binary instanceof Buffer);
  native.binary.fill(7);
  assert.deepEqual(value.binary, Uint8Array.of(1, 2, 3));
  assert.deepEqual(ownedBytes(new Uint8Array(), 0), Buffer.alloc(0));
});
test('AMQP rejects values that cannot be represented faithfully before native publication', () => {
  assert.throws(() => outgoing(null as unknown as AmqpHeaders), code);
  assert.throws(() => incoming(null), code);
  const values: unknown[] = [
    undefined,
    NaN,
    Infinity,
    -Infinity,
    Number.MAX_SAFE_INTEGER + 1,
    1n << 63n,
    -(1n << 63n) - 1n,
    new Date(NaN),
    new Date(-1000),
    new Date(1),
    /unsupported/,
    () => undefined,
    new Uint8Array(new SharedArrayBuffer(16)),
    '\ud800',
    { '!': 'int64', value: 2n },
  ];
  for (const value of values) assert.throws(() => outgoing({ field: value } as AmqpHeaders), code);
  for (const value of [
    JSON.parse('{"constructor":1}'),
    JSON.parse('{"__proto__":null}'),
    JSON.parse('{"prototype":1}'),
    { ['x\0']: 1 },
  ])
    assert.throws(() => outgoing(value), code);
});
test('AMQP uses the native encoded-size calculation at the exact 16 KiB boundary', () => {
  const value = 'x'.repeat(16384 - 11);
  assert.equal(outgoing({ x: value }).size, 16384);
  assert.throws(() => outgoing({ x: value + 'x' }), code);
  assert.throws(() => outgoing({ x: Buffer.alloc(16384) }), code);
});
test('Recursive header limits reject cycles, accessors, sparse arrays, excessive entries and depth', () => {
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  let calls = 0;
  const accessor = Object.defineProperty({}, 'field', {
    enumerable: true,
    get() {
      calls++;
      throw new Error('Must not execute');
    },
  });
  for (const value of [
    cyclic,
    accessor,
    { list: new Array(2) },
    { list: Array.from({ length: 257 }, () => 1) },
    Object.fromEntries(Array.from({ length: 129 }, (_, i) => ['field' + i, 1])),
  ])
    assert.throws(() => outgoing(value as AmqpHeaders), code);
  let nested: unknown = 'valid';
  for (let i = 0; i < 4; i++) nested = { child: nested };
  assert.ok(outgoing({ nested } as AmqpHeaders));
  assert.throws(() => outgoing({ nested: { child: nested } } as AmqpHeaders), code);
  assert.equal(calls, 0);
});
test('Native timestamps are distinguished from ordinary tables and unsupported decimal values are explicit errors', () => {
  const value = incoming(nativeRoundtrip({ date: { '!': 'timestamp', value: 1000 } }));
  assert.ok(value.date instanceof Date);
  assert.equal(value.date.getTime(), 1000000);
  for (const native of [
    nativeRoundtrip({ bad: { '!': 'decimal', value: { digits: 123, places: 2 } } }),
    nativeRoundtrip({ bad: { '!': 'timestamp', value: 8640000000001 } }),
    { bad: { '!': 'unknown', value: 1 } },
  ])
    assert.throws(() => incoming(native), code);
  const ordinary = Object.create(null) as Record<string, unknown>;
  ordinary['!'] = 'timestamp';
  ordinary.value = 1000;
  // Encode an actual ordinary table through another native table layer, without a type override.
  assert.throws(() => incoming({ bad: ordinary }), code);
});
