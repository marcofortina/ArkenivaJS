// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { headers, publication } from '../../dist/payload.js';
import { array, bytes, fields, integer, offset, text, topic } from '../../dist/validation.js';

test('Kafka payload snapshots distinguish tombstones, empty values and binary keys without aliasing', () => {
  const key = new Uint8Array([0, 255]),
    value = new Uint8Array([1, 128]);
  const result = publication({ cluster: 'owned', topic: 'orders.created', key, value }, 4);
  key.fill(9);
  value.fill(9);
  assert.deepEqual([...result.key!], [0, 255]);
  assert.deepEqual([...result.value!], [1, 128]);
  assert.equal(
    publication({ cluster: 'owned', topic: 'orders.created', key, value: null }, 4).value,
    null,
  );
  assert.equal(
    publication({ cluster: 'owned', topic: 'orders.created', value: new Uint8Array() }, 4).value!
      .byteLength,
    0,
  );
  for (const invalid of [
    { value: null },
    { value: null, key: new Uint8Array() },
    { value: 'text' },
    { value: new Uint8Array(5) },
    { value: new Uint8Array(3), key: new Uint8Array(2) },
    { value: new Uint8Array(), unknown: true },
  ])
    assert.throws(() => publication({ cluster: 'owned', topic: 'orders.created', ...invalid }, 4), {
      code: 'EK_KAFKA_CONFIG',
    });
});

test('Kafka header snapshots retain duplicate order, null, binary bytes and untrusted tenant claims', () => {
  const binary = new Uint8Array([0, 255]);
  const result = headers({ duplicate: ['first', binary, null, ''], tenant_id: 'untrusted' });
  binary.fill(1);
  const duplicate = result.duplicate as readonly (string | Uint8Array | null)[];
  assert.deepEqual(duplicate, ['first', Buffer.from([0, 255]), null, '']);
  assert.equal(result.tenant_id, 'untrusted');
  assert.ok(!Object.hasOwn(result, 'verifiedTenant'));
  assert.ok(Object.isFrozen(duplicate) && Object.isFrozen(result));
  const reserved = headers(
    JSON.parse('{"__proto__":"wire-bytes","constructor":null,"prototype":"retained"}'),
  );
  assert.equal(Object.getPrototypeOf(reserved), null);
  assert.equal(reserved.__proto__, 'wire-bytes');
  assert.equal(reserved.constructor, null);
  assert.equal(reserved.prototype, 'retained');
  for (const value of [
    null,
    { a: [] },
    { a: 1 },
    { a: undefined },
    { a: ['x'.repeat(16384)] },
    { a: new Uint8Array(16385) },
    Object.fromEntries(Array.from({ length: 129 }, (_, i) => ['h' + i, 'v'])),
    { a: Array.from({ length: 257 }, () => '') },
  ])
    assert.throws(() => headers(value), { code: 'EK_KAFKA_CONFIG' });
});

test('Kafka offsets preserve the entire nonnegative signed 64-bit domain without unsafe numeric conversion', () => {
  for (const value of [
    '0',
    '9007199254740991',
    '9007199254740992',
    '9007199254740993',
    '9223372036854775807',
  ])
    assert.equal(offset(value), value);
  for (const value of [
    0,
    9007199254740992,
    1n,
    '-1',
    '+1',
    '01',
    '1.0',
    '1e3',
    '9223372036854775808',
    '9'.repeat(100),
  ])
    assert.throws(() => offset(value), { code: 'EK_KAFKA_OFFSET' });
});

test('Kafka data guards reject executable objects, shared bytes and malformed structural input without executing hooks', () => {
  let calls = 0;
  const accessor = Object.defineProperty({}, 'value', {
    get() {
      calls++;
      return new Uint8Array();
    },
  });
  const proxy = new Proxy(
    {},
    {
      getPrototypeOf() {
        calls++;
        return null;
      },
      ownKeys() {
        calls++;
        return [];
      },
    },
  );
  for (const value of [
    accessor,
    proxy,
    Object.create({ inherited: true }),
    [],
    null,
    { [Symbol('x')]: 1 },
    JSON.parse('{"__proto__":{}}'),
  ])
    assert.throws(() => fields(value));
  const sparse = new Array(1);
  const accessed: unknown[] = [];
  Object.defineProperty(accessed, '0', {
    get() {
      calls++;
      return 1;
    },
  });
  for (const value of [sparse, accessed, new Proxy([], {})]) assert.throws(() => array(value, 4));
  const binary = new Uint8Array([1]);
  Object.defineProperty(binary, Symbol.iterator, {
    value() {
      calls++;
      throw new Error('The iterator must not execute');
    },
  });
  assert.deepEqual(bytes(binary, 4), Buffer.from([1]));
  for (const value of [
    new Uint16Array(1),
    new Uint8Array(new SharedArrayBuffer(1)),
    new Proxy(new Uint8Array(), {}),
  ])
    assert.throws(() => bytes(value, 4));
  const detached = new Uint8Array(1);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  assert.throws(() => bytes(detached, 4));
  assert.equal(calls, 0);
});

test('Kafka names, sizes and text guards reject ambiguous or unbounded configuration', () => {
  assert.equal(topic('orders.created-v1_0'), 'orders.created-v1_0');
  for (const value of ['', '.', '..', 'a/b', 'a'.repeat(250), 'x\n'])
    assert.throws(() => topic(value));
  for (const value of [0, -1, 0.5, NaN, Infinity, 101]) assert.throws(() => integer(value, 100));
  assert.equal(integer(1, 100), 1);
  assert.equal(integer(100, 100), 100);
  assert.equal(text('', 1, true), '');
  for (const value of ['\ud800', '\0', '\n', 'éé']) assert.throws(() => text(value, 3));
});
