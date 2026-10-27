// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { parse, stringify, snapshot, options } from '../../dist/codec.js';
import { record } from '../../dist/validation.js';
import { failure } from '../../dist/validation.js';
const limits = options({ maxBytes: 4096, maxDepth: 8 });
const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;

test('Native JSON preserves strings, null, booleans and finite numbers in immutable owned values', () => {
  const source =
    '{"id":"001","name":"Ελληνικά שלום 🦉","active":true,"amount":12.5,"none":null,"items":[1,"2",false]}';
  const result = parse(source, limits) as Record<string, unknown>;
  assert.equal(stringify(result, limits), source);
  assert.equal(Object.getPrototypeOf(result), null);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.items));
  assert.equal(parse('"2026-10-27T12:34:56Z"', limits), '2026-10-27T12:34:56Z');
  assert.equal(
    parse('{"id":1,"id":2}', limits) &&
      (parse('{"id":1,"id":2}', limits) as Record<string, unknown>).id,
    2,
  );
});
test('JSON input and complete pretty output enforce exact UTF-8 byte budgets and explicit depth', () => {
  assert.equal(parse('"é"', options({ maxBytes: 4 })), 'é');
  assert.throws(() => parse('"é"', options({ maxBytes: 3 })), code('EK_JSON_PARSE'));
  assert.equal(stringify({ a: 1 }, options({ maxBytes: 7 })), '{"a":1}');
  assert.throws(
    () => stringify({ a: 1 }, options({ maxBytes: 7, indentSpaces: 2 })),
    code('EK_JSON_PARSE'),
  );
  assert.equal(stringify({ a: 1 }, options({ indentSpaces: 2 })), '{\n  "a": 1\n}');
  assert.throws(() => parse('[[[0]]]', options({ maxDepth: 2 })), code('EK_JSON_PARSE'));
  assert.equal(stringify(parse('[[0]]', options({ maxDepth: 2 })), limits), '[[0]]');
});
test('Malformed text, invalid Unicode, overflowing and unsafe integer numbers never become accepted data', () => {
  for (const text of [
    '{',
    '{"x":undefined}',
    'NaN',
    'Infinity',
    '1e999',
    '9007199254740993',
    '"\\ud800"',
    '"\ud800"',
    '\ufeff{}',
  ])
    assert.throws(() => parse(text, limits), code('EK_JSON_PARSE'));
  for (const value of [
    undefined,
    NaN,
    Infinity,
    9007199254740992,
    1n,
    Symbol('x'),
    () => true,
    new Date(),
    new Map(),
    new Uint8Array(1),
  ])
    assert.throws(() => snapshot(value, limits), code('EK_JSON_PARSE'));
});
test('Dangerous properties, inherited objects, cycles, sparse arrays and extra array fields are rejected', () => {
  for (const key of ['__proto__', 'prototype', 'constructor']) {
    assert.throws(() => parse('{"safe":{"' + key + '":1}}', limits), code('EK_JSON_PARSE'));
    assert.throws(() => snapshot({ [key]: 1 }, limits), code('EK_JSON_PARSE'));
  }
  const cycle: unknown[] = [];
  cycle.push(cycle);
  for (const value of [
    cycle,
    new Array(3),
    Object.assign([1], { extra: true }),
    Object.create({ inherited: true }),
    Object.assign({}, { [Symbol('x')]: true }),
  ])
    assert.throws(() => snapshot(value, limits), code('EK_JSON_PARSE'));
  const child = { value: 1 };
  assert.equal(stringify([child, child], limits), '[{"value":1},{"value":1}]');
});
test('Getters, toJSON and Proxy traps cannot execute while snapshotting caller data', () => {
  let calls = 0;
  const getter = Object.defineProperty({}, 'data', {
    enumerable: true,
    get() {
      calls++;
      return 'private';
    },
  });
  const custom = {
    toJSON() {
      calls++;
      return 'private';
    },
  };
  const proxy = new Proxy(
    {},
    {
      ownKeys() {
        calls++;
        return [];
      },
      getPrototypeOf() {
        calls++;
        return null;
      },
    },
  );
  for (const value of [getter, custom, proxy])
    assert.throws(() => snapshot(value, limits), code('EK_JSON_PARSE'));
  assert.throws(() => record(proxy), code('EK_CONFIG_INVALID'));
  assert.equal(calls, 0);
});
test('JSON options reject null, unknown fields, accessors, fractional limits and insecure widening', () => {
  for (const value of [
    null,
    { maxBytes: 0 },
    { maxDepth: 129 },
    { indentSpaces: 11 },
    { indentSpaces: -1 },
    { maxBytes: 1.5 },
    { maxDepth: NaN },
    { extra: true },
  ])
    assert.throws(() => options(value as never), code('EK_CONFIG_INVALID'));
  assert.throws(() => options({ maxBytes: 4097 }, limits), code('EK_CONFIG_INVALID'));
  assert.throws(
    () =>
      options(
        Object.defineProperty({}, 'maxDepth', {
          enumerable: true,
          get() {
            throw Error('Never execute');
          },
        }),
      ),
    code('EK_CONFIG_INVALID'),
  );
});
test('Native JSON errors do not expose input text or parser causes', () => {
  const sentinel = 'private-json-document';
  assert.throws(
    () => parse('{"' + sentinel + '":', limits),
    (error: unknown) =>
      error instanceof KitError &&
      error.code === 'EK_JSON_PARSE' &&
      !JSON.stringify(error.toSafeJSON()).includes(sentinel) &&
      error.cause === undefined,
  );
});

test('Codec checkpoints preserve cancellation and deadlines instead of remapping them as malformed data', () => {
  for (const name of ['EK_TIMEOUT', 'EK_ABORTED'] as const) {
    const stop = () => {
      throw failure(name);
    };
    assert.throws(() => parse('[1,2]', limits, stop), code(name));
    assert.throws(() => stringify([1, 2], limits, stop), code(name));
  }
  assert.throws(
    () => snapshot(new Array(100001).fill(null), options({ maxBytes: 1048576 })),
    code('EK_JSON_PARSE'),
  );
});
