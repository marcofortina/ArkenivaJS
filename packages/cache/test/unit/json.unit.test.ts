// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { cacheSerializer } from '../../dist/json.js';

test('Cache JSON round trips versioned plain data and isolates decoded generations without instantiating tagged objects', () => {
  const codec = cacheSerializer();
  for (const value of [
    null,
    true,
    false,
    42,
    'Unicode: α😀',
    [],
    {},
    { values: [null, false, { name: 'Ada', $type: 'UntrustedClass' }] },
  ]) {
    const text = codec.encode(value);
    assert.deepEqual(JSON.parse(text), { schemaVersion: 1, value });
    assert.deepEqual(codec.decode(text), value);
  }
  const text = codec.encode({ nested: { value: 1 } });
  const first = codec.decode(text) as { nested: { value: number } };
  first.nested.value = 2;
  assert.deepEqual(codec.decode(text), { nested: { value: 1 } });
});

test('Cache JSON rejects lossy values, custom classes, cycles, symbols and serializers without executing accessors', () => {
  const codec = cacheSerializer(),
    cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  let invoked = 0;
  const getter = Object.defineProperty({}, 'secret', {
    enumerable: true,
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
    named = Object.assign([], { other: 1 });
  for (const value of [
    undefined,
    NaN,
    Infinity,
    1n,
    Symbol('private'),
    () => 1,
    new Date(),
    new Map(),
    new Set(),
    new Uint8Array([1]),
    cyclic,
    getter,
    serializer,
    { value: undefined },
    sparse,
    named,
    { [Symbol('private')]: 1 },
    JSON.parse('{"__proto__":{"polluted":true}}'),
  ])
    assert.throws(() => codec.encode(value), { code: 'EK_CONFIG_INVALID' });
  assert.equal(invoked, 0);
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
});

test('Cache JSON bounds bytes, nodes, depth, array size and object fields before serialization', () => {
  const codec = cacheSerializer();
  let deep: unknown = null;
  for (let index = 0; index < 70; index++) deep = { deep };
  const many = Object.fromEntries(
    Array.from({ length: 10002 }, (_, index) => ['key' + index, index]),
  );
  for (const value of [
    'x'.repeat(1_048_577),
    '😀'.repeat(300000),
    deep,
    Array.from({ length: 10001 }, () => 1),
    many,
    Array.from({ length: 100 }, () => 'shared-string'.repeat(5000)),
    Array.from({ length: 100 }, () => Array.from({ length: 1000 }, () => 1)),
  ])
    assert.throws(() => codec.encode(value), { code: 'EK_CONFIG_INVALID' });
  let bounded: unknown = { value: 'leaf' };
  for (let index = 0; index < 60; index++) bounded = { bounded };
  assert.deepEqual(codec.decode(codec.encode(bounded)), bounded);
});

test('Cache JSON refuses corrupt, incompatible and unsafe stored envelopes instead of returning a cache miss', () => {
  const codec = cacheSerializer();
  for (const text of [
    '{',
    'null',
    '[]',
    '{}',
    '{"schemaVersion":2,"value":1}',
    '{"schemaVersion":1,"value":1,"extra":true}',
    '{"schemaVersion":1,"value":{"constructor":{}}}',
    'x'.repeat(1_048_577),
    42 as never,
  ])
    assert.throws(() => codec.decode(text), { code: 'EK_BACKEND_UNAVAILABLE' });
});
