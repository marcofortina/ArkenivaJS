// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { Schemas } from '../../dist/schemas.js';
import { parse, options } from '../../dist/codec.js';
const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
test('The actual Ajv 2020 compiler enforces tuple, unevaluated property and strict format validation without coercion', () => {
  const schemas = new Schemas({
    record: {
      type: 'object',
      properties: {
        items: {
          type: 'array',
          prefixItems: [{ type: 'string' }, { type: 'integer' }],
          items: false,
          minItems: 2,
        },
        date: { type: 'string', format: 'date-time' },
      },
      required: ['items', 'date'],
      unevaluatedProperties: false,
    },
  });
  const value = { items: ['001', 2], date: '2026-10-27T12:34:56Z' };
  assert.equal(schemas.validate(value, 'record').valid, true);
  for (const input of [
    { ...value, items: ['001', '2'] },
    { ...value, extra: true },
    { ...value, date: '27/10/2026' },
    { ...value, items: ['001', 2, 3] },
  ])
    assert.equal(schemas.validate(input, 'record').valid, false);
  assert.deepEqual(value, { items: ['001', 2], date: '2026-10-27T12:34:56Z' });
});
test('Offline registered schema references and RFC6901 escaped definitions resolve through the actual compiler', () => {
  const schemas = new Schemas({
    name: { type: 'string', minLength: 2 },
    customer: {
      type: 'object',
      $defs: { 'a/b~c': { type: 'integer' }, allow: true, deny: false },
      properties: {
        name: { $ref: 'name' },
        count: { $ref: '#/$defs/a~1b~0c' },
        anything: { $ref: '#/$defs/allow' },
        nothing: { $ref: '#/$defs/deny' },
      },
      required: ['name', 'count'],
    },
  });
  assert.equal(schemas.validate({ name: 'ok', count: 1, anything: null }, 'customer').valid, true);
  assert.equal(schemas.validate({ name: 'x', count: 1 }, 'customer').valid, false);
  assert.equal(schemas.validate({ name: 'ok', count: 1, nothing: 1 }, 'customer').valid, false);
});
test('Schema registries reject external references, local and cross-catalog cycles before native compilation', () => {
  for (const source of [
    { a: { $ref: 'https://external.invalid/schema' } },
    { a: { $ref: 'file:///private/schema' } },
    { a: { $ref: '#' } },
    {
      a: {
        $defs: { node: { type: 'object', properties: { next: { $ref: '#/$defs/node' } } } },
        $ref: '#/$defs/node',
      },
    },
    { a: { $ref: 'b' }, b: { $ref: 'a' } },
    { a: { type: 'array', prefixItems: [{ $ref: '#' }] } },
    { a: { type: 'object', dependentSchemas: { x: { $ref: '#' } } } },
    { a: { type: 'object', dependencies: { x: { $ref: '#' } } } },
    { a: { $ref: '#missing' } },
  ])
    assert.throws(() => new Schemas(source), code('EK_JSON_SCHEMA'));
});
test('Unsupported schema resources, async validators, unknown keywords and invalid native formats fail closed', () => {
  for (const source of [
    { a: { $async: true, type: 'string' } },
    { a: { $schema: 'http://json-schema.org/draft-07/schema#' } },
    { a: { $defs: { nested: { $id: 'other', type: 'string' } } } },
    { a: { $dynamicRef: '#node' } },
    { a: { $anchor: 'node' } },
    { a: { type: 'unsupported' } },
    { a: { customJavaScript: 'return true' } },
    { a: { type: 'string', format: 'unknown-format' } },
  ])
    assert.throws(() => new Schemas(source), code('EK_JSON_SCHEMA'));
});
test('Schema metadata is owned and immutable; literal metadata is not mistaken for executable schema keywords', () => {
  const original = { type: 'string', minLength: 2 };
  const schemas = new Schemas({
    a: original,
    b: { enum: [{ $ref: 'https://literal.invalid/not-a-schema' }] },
  });
  original.minLength = 100;
  assert.equal(schemas.validate('ok', 'a').valid, true);
  assert.equal(schemas.validate({ $ref: 'https://literal.invalid/not-a-schema' }, 'b').valid, true);
  assert.ok(Object.isFrozen(schemas.catalog.a));
  assert.throws(
    () =>
      new Schemas(
        Object.fromEntries(
          Array.from({ length: 129 }, (_, i) => ['schema' + i, { type: 'string' }]),
        ),
      ),
    code('EK_JSON_SCHEMA'),
  );
  assert.throws(
    () => new Schemas(parse('{"__proto__":{}}', options()) as never),
    code('EK_JSON_PARSE'),
  );
});
test('Native schema failures return only a stable instance path and safe fixed messages', () => {
  const schemas = new Schemas({
    a: {
      type: 'object',
      properties: { amount: { type: 'integer' } },
      required: ['amount'],
      additionalProperties: false,
    },
  });
  const result = schemas.validate({ amount: 'private-schema-sentinel' }, 'a');
  assert.equal(result.valid, false);
  assert.equal(result.errors[0]?.path, '/amount');
  assert.equal(JSON.stringify(result).includes('private-schema-sentinel'), false);
  assert.throws(() => schemas.validate({}, 'unknown'), code('EK_JSON_SCHEMA'));
});

test('Native enum and const comparisons preserve method-like JSON members without executing them', () => {
  const expected = { valueOf: 'text', toString: { nested: [1, false, null] } };
  const schemas = new Schemas({ a: { const: expected }, b: { enum: [expected, { valueOf: 2 }] } });
  assert.equal(schemas.validate(expected, 'a').valid, true);
  assert.equal(schemas.validate(expected, 'b').valid, true);
  assert.equal(schemas.validate({ ...expected, valueOf: 'changed' }, 'a').valid, false);
  assert.equal(schemas.validate({ valueOf: 2 }, 'b').valid, true);
  assert.equal(schemas.validate({ valueOf: 3 }, 'b').valid, false);
});
