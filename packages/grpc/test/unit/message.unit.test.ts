// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import protobuf from 'protobufjs';
import { ownMessage } from '../../dist/message.js';

const root = protobuf
    .parse(
      `syntax="proto3"; message Value {
  string text=1; bytes bytes=2; int32 signed=3; uint32 unsigned=4;
  int64 large=5; uint64 positive=6; bool enabled=7; float fraction=8;
  repeated Value children=9; map<string,Value> mapping=10;
  oneof choice { string first=11; int32 second=12; }
  map<int32,string> numbers=13; Value child=14;
}`,
    )
    .root.resolveAll(),
  type = root.lookupType('Value');

test('Protobuf ownership preserves empty values, byte buffers and exact integer extrema', () => {
  const input = {
    text: '',
    enabled: false,
    signed: -2147483648,
    unsigned: 4294967295,
    large: '-9223372036854775808',
    positive: '18446744073709551615',
    bytes: Buffer.from([0, 255]),
    children: [{ text: 'child' }],
    mapping: { one: { first: 'selected' } },
    numbers: { '-1': 'negative' },
  };
  const owned = ownMessage(type, input, 4096);
  assert.equal(owned.large, input.large);
  assert.equal(owned.enabled, false);
  assert.equal(owned.text, '');
  assert.deepEqual(owned.bytes, input.bytes);
  assert.notEqual(owned.bytes, input.bytes);
  assert.notEqual(owned.children, input.children);
});
for (const [name, value] of [
  ['unknown fields', { typo: 'lost' }],
  ['integer overflow', { signed: 2147483648 }],
  ['negative unsigned', { unsigned: -1 }],
  ['fractional integer', { signed: 0.5 }],
  ['lossy int64 number', { large: 9007199254740992 }],
  ['int64 overflow', { large: '9223372036854775808' }],
  ['uint64 overflow', { positive: '18446744073709551616' }],
  ['leading zero integer', { large: '001' }],
  ['string coercion', { text: 1 }],
  ['boolean coercion', { enabled: 1 }],
  ['base64 coercion', { bytes: 'AA==' }],
  ['nonfinite float', { fraction: Infinity }],
  ['float32 overflow', { fraction: 1e100 }],
  ['multiple oneof values', { first: 'one', second: 2 }],
  ['noncanonical map key', { numbers: { '01': 'one' } }],
  ['oversized scalar', { text: 'x'.repeat(4097) }],
  ['excessive repeated items', { children: Array.from({ length: 4097 }, () => ({})) }],
] as const)
  test(`Protobuf ownership rejects ${name}`, () =>
    assert.throws(() => ownMessage(type, value, 4096), { code: 'EK_GRPC_STATUS' }));

test('Protobuf ownership rejects accessors, proxies, cycles and depth before native conversion', () => {
  let accesses = 0;
  const accessor = Object.defineProperty({}, 'text', {
    enumerable: true,
    get() {
      accesses++;
      return 'unsafe';
    },
  });
  assert.throws(() => ownMessage(type, accessor, 4096));
  assert.equal(accesses, 0);
  const proxy = new Proxy(
    {},
    {
      getPrototypeOf() {
        accesses++;
        return Object.prototype;
      },
    },
  );
  assert.throws(() => ownMessage(type, proxy, 4096));
  assert.equal(accesses, 0);
  const cyclic: { child?: unknown } = {};
  cyclic.child = cyclic;
  assert.throws(() => ownMessage(type, cyclic, 4096));
  let deep: unknown = {};
  for (let depth = 0; depth < 34; depth++) deep = { child: deep };
  assert.throws(() => ownMessage(type, deep, 4096));
});
test('Native oneof discriminators are checked and omitted from wire fields', () => {
  const value = ownMessage(type, { first: 'selected', choice: 'first' }, 4096);
  assert.equal(value.first, 'selected');
  assert.equal(Object.hasOwn(value, 'choice'), false);
  assert.throws(() => ownMessage(type, { first: 'selected', choice: 'second' }, 4096));
});
