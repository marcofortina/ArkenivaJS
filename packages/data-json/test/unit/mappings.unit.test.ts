// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { Schemas } from '../../dist/schemas.js';
import { Mappings, captureMappings } from '../../dist/mappings.js';
import { mappingGrammar } from '../../dist/mapping-grammar.js';
import { failure } from '../../dist/validation.js';
import type { JsonMappingV1, JsonMappingExpr, JsonMappingRegistry } from '../../dist/index.js';
const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
const schemas = new Schemas({ input: {}, output: { type: 'object' } });
function mapping(
  fields: Readonly<Record<string, JsonMappingExpr>>,
  limits: Partial<JsonMappingV1['limits']> = {},
): JsonMappingV1 {
  return {
    schemaVersion: '1.0.0',
    id: 'mapping.v1',
    inputSchemaId: 'input',
    outputSchemaId: 'output',
    fields,
    limits: { maxDepth: 16, maxNodes: 2048, maxArrayItems: 100, maxOutputBytes: 4096, ...limits },
  };
}
function run(
  fields: Readonly<Record<string, JsonMappingExpr>>,
  input: unknown = {},
  limits: Partial<JsonMappingV1['limits']> = {},
) {
  return new Mappings([mapping(fields, limits)], schemas).transform(input, 'mapping.v1') as Record<
    string,
    unknown
  >;
}
test('The fixed native grammar accepts only the complete closed versioned mapping language', () => {
  const valid = mapping({
    one: { op: 'copy', path: '/id', required: true },
    two: { op: 'literal', value: null },
    three: { op: 'concat', args: [{ op: 'literal', value: 'a' }], separator: ' ' },
    four: { op: 'array-map', path: '/items', item: { op: 'copy', path: '' }, maxItems: 5 },
  });
  assert.equal(mappingGrammar(valid), true);
  for (const value of [
    { ...valid, schemaVersion: '2.0.0' },
    { ...valid, extra: true },
    { ...valid, fields: {} },
    { ...valid, fields: { x: { op: 'eval', code: 'return true' } } },
    { ...valid, fields: { x: { op: 'copy', path: '$.id' } } },
    { ...valid, fields: { x: { op: 'literal', value: 1, unknown: 1 } } },
    { ...valid, fields: { x: { op: 'coalesce', args: [] } } },
    { ...valid, limits: { ...valid.limits, maxNodes: 2049 } },
    { ...valid, limits: { ...valid.limits, maxOutputBytes: 0 } },
  ]) {
    assert.equal(mappingGrammar(value), false);
    assert.throws(() => new Mappings([value as never], schemas), code('EK_JSON_TRANSFORM'));
  }
});
test('Deployment registry enumeration captures each ID once, rejects duplicates and never trusts a get-only provider', () => {
  const item = mapping({ x: { op: 'literal', value: 1 } });
  let calls = 0;
  class Registry implements JsonMappingRegistry {
    readonly ids = ['mapping.v1'];
    get() {
      calls++;
      return item;
    }
  }
  const captured = captureMappings(new Registry());
  assert.equal(calls, 1);
  assert.ok(Object.isFrozen(captured));
  assert.ok(Object.isFrozen(captured[0]!.fields));
  const compiled = new Mappings(captured, schemas);
  assert.equal((compiled.transform({}, item.id) as Record<string, unknown>).x, 1);
  assert.equal(calls, 1);
  for (const registry of [
    { get: () => item },
    { ids: [item.id, item.id], get: () => item },
    { ids: [item.id], get: () => null },
    { ids: ['different.id'], get: () => item },
    { ids: [item.id], get: () => Promise.resolve(item) },
    {
      ids: [item.id],
      get() {
        throw new Error('private-provider-error');
      },
    },
    { ids: new Array(2), get: () => item },
    new Proxy(
      {},
      {
        get() {
          throw Error('Never execute');
        },
      },
    ),
  ])
    assert.throws(() => captureMappings(registry as never), code('EK_JSON_TRANSFORM'));
});
test('Missing optional properties are omitted, existing null is preserved and required copy fails explicitly', () => {
  const output = run(
    { missing: { op: 'copy', path: '/missing' }, present: { op: 'copy', path: '/present' } },
    { present: null },
  );
  assert.equal(Object.hasOwn(output, 'missing'), false);
  assert.equal(output.present, null);
  assert.equal(Object.getPrototypeOf(output), null);
  assert.throws(
    () => run({ required: { op: 'copy', path: '/missing', required: true } }),
    code('EK_JSON_TRANSFORM'),
  );
  assert.equal(run({ root: { op: 'copy', path: '' } }, null).root, null);
});
test('RFC6901 pointers resolve escaped names and array indexes without inherited or dangerous property access', () => {
  assert.equal(
    run(
      { x: { op: 'copy', path: '/a~1b/~0key/0/id', required: true } },
      { 'a/b': { '~key': [{ id: '001' }] } },
    ).x,
    '001',
  );
  assert.equal(
    run({ x: { op: 'copy', path: '//', required: true } }, { '': { '': 'empty' } }).x,
    'empty',
  );
  for (const path of [
    '/constructor',
    '/a/__proto__',
    '/prototype',
    '/a~2b',
    'https://untrusted.invalid/x',
  ])
    assert.throws(() => run({ x: { op: 'copy', path } }), code('EK_JSON_TRANSFORM'));
  for (const path of ['/items/01', '/items/length', '/items/-'])
    assert.equal(Object.hasOwn(run({ x: { op: 'copy', path } }, { items: [1] }), 'x'), false);
});
test('Coalesce returns the first non-null existing value and does not suppress conversion errors', () => {
  const fields = {
    x: {
      op: 'coalesce',
      args: [
        { op: 'copy', path: '/missing' },
        { op: 'copy', path: '/nil' },
        { op: 'copy', path: '/kept' },
        { op: 'literal', value: 'fallback' },
      ],
    },
  } as const;
  for (const value of ['', 0, false])
    assert.equal(run(fields, { nil: null, kept: value }).x, value);
  assert.equal(
    Object.hasOwn(
      run({
        x: {
          op: 'coalesce',
          args: [
            { op: 'literal', value: null },
            { op: 'copy', path: '/missing' },
          ],
        },
      }),
      'x',
    ),
    false,
  );
  assert.throws(
    () =>
      run({
        x: {
          op: 'coalesce',
          args: [
            { op: 'to-number', value: { op: 'literal', value: 'bad' } },
            { op: 'literal', value: 1 },
          ],
        },
      }),
    code('EK_JSON_TRANSFORM'),
  );
});
test('Concat and scalar-to-string conversions are deterministic and never coerce objects or null', () => {
  assert.equal(
    run(
      {
        x: {
          op: 'concat',
          args: [
            { op: 'copy', path: '/a' },
            { op: 'literal', value: 'שלום' },
          ],
          separator: ' / ',
        },
      },
      { a: '001' },
    ).x,
    '001 / שלום',
  );
  for (const value of [null, 1, true, {}, []])
    assert.throws(
      () => run({ x: { op: 'concat', args: [{ op: 'literal', value }] } }),
      code('EK_JSON_TRANSFORM'),
    );
  for (const value of [false, true, 1.25, '001'])
    assert.equal(
      run({ x: { op: 'to-string', value: { op: 'literal', value } } }).x,
      typeof value === 'string' ? value : JSON.stringify(value),
    );
  for (const value of [null, {}, []])
    assert.throws(
      () => run({ x: { op: 'to-string', value: { op: 'literal', value } } }),
      code('EK_JSON_TRANSFORM'),
    );
});
test('Strict numeric and boolean conversions reject hex, locale coercion, unsafe precision and nonfinite results', () => {
  for (const [value, expected] of [
    ['0', 0],
    ['-2', -2],
    ['1.25e2', 125],
    [2.5, 2.5],
  ] as const)
    assert.equal(run({ x: { op: 'to-number', value: { op: 'literal', value } } }).x, expected);
  for (const value of [
    '',
    ' 1',
    '+1',
    '01',
    '0x10',
    '1,2',
    'Infinity',
    'NaN',
    '1e999',
    '1e-999',
    '9007199254740993',
    true,
    null,
    [],
    {},
  ])
    assert.throws(
      () => run({ x: { op: 'to-number', value: { op: 'literal', value } } }),
      code('EK_JSON_TRANSFORM'),
    );
  for (const value of [true, false, 'true', 'false'])
    assert.equal(
      run({ x: { op: 'to-boolean', value: { op: 'literal', value } } }).x,
      value === true || value === 'true',
    );
  for (const value of ['TRUE', 'False', '1', 1, 0, null])
    assert.throws(
      () => run({ x: { op: 'to-boolean', value: { op: 'literal', value } } }),
      code('EK_JSON_TRANSFORM'),
    );
});
test('Array-map uses item-relative pointers, preserves order and never drops missing results', () => {
  const fields = {
    x: {
      op: 'array-map',
      path: '/items',
      maxItems: 4,
      item: { op: 'to-string', value: { op: 'copy', path: '/id', required: true } },
    },
  } as const;
  assert.deepEqual(run(fields, { items: [{ id: 2 }, { id: 1 }] }).x, ['2', '1']);
  for (const input of [
    {},
    { items: null },
    { items: 'array' },
    { items: new Array(5).fill({ id: 1 }) },
    { items: [{}] },
  ])
    assert.throws(() => run(fields, input), code('EK_JSON_TRANSFORM'));
  assert.throws(
    () =>
      run(
        {
          x: {
            op: 'array-map',
            path: '/items',
            maxItems: 4,
            item: { op: 'copy', path: '/missing' },
          },
        },
        { items: [{}] },
      ),
    code('EK_JSON_TRANSFORM'),
  );
});
test('Cumulative mapping node, expression depth, expanded array and output byte budgets are enforced', () => {
  assert.throws(
    () =>
      run({ a: { op: 'literal', value: 1 }, b: { op: 'literal', value: 2 } }, {}, { maxNodes: 1 }),
    code('EK_JSON_TRANSFORM'),
  );
  assert.throws(
    () => run({ a: { op: 'to-string', value: { op: 'literal', value: 1 } } }, {}, { maxDepth: 1 }),
    code('EK_JSON_TRANSFORM'),
  );
  const field = {
    op: 'array-map',
    path: '/items',
    maxItems: 4,
    item: { op: 'copy', path: '' },
  } as const;
  assert.throws(
    () => run({ a: field, b: field }, { items: [1, 2, 3] }, { maxArrayItems: 5 }),
    code('EK_JSON_TRANSFORM'),
  );
  assert.throws(
    () => run({ a: field }, { items: [1, 2, 3] }, { maxNodes: 3 }),
    code('EK_JSON_TRANSFORM'),
  );
  assert.throws(
    () =>
      run(
        {
          x: {
            op: 'concat',
            args: [
              { op: 'literal', value: 'éé' },
              { op: 'literal', value: 'éé' },
            ],
          },
        },
        {},
        { maxOutputBytes: 7 },
      ),
    code('EK_JSON_TRANSFORM'),
  );
  assert.throws(
    () => run({ x: { op: 'literal', value: 'é' } }, {}, { maxOutputBytes: 9 }),
    code('EK_JSON_TRANSFORM'),
  );
});
test('Input and output schemas remain actual native acceptance boundaries with no partial transformation result', () => {
  const catalog = new Schemas({
    input: { type: 'object', properties: { n: { type: 'string' } }, required: ['n'] },
    output: {
      type: 'object',
      properties: { x: { type: 'integer', minimum: 1 } },
      required: ['x'],
      additionalProperties: false,
    },
  });
  const item = mapping({
    x: { op: 'to-number', value: { op: 'copy', path: '/n', required: true } },
  });
  const transforms = new Mappings([item], catalog);
  assert.equal((transforms.transform({ n: '2' }, item.id) as Record<string, unknown>).x, 2);
  for (const input of [{ n: 2 }, { n: '0' }, {}, null])
    assert.throws(() => transforms.transform(input, item.id), code('EK_JSON_TRANSFORM'));
  for (const source of [
    [{ ...item, inputSchemaId: 'unknown' }],
    [{ ...item, outputSchemaId: 'unknown' }],
    [item, item],
  ])
    assert.throws(() => new Mappings(source, catalog), code('EK_JSON_TRANSFORM'));
  assert.throws(
    () => new Mappings([mapping({ wrong: { op: 'literal', value: 1 } })], catalog),
    code('EK_JSON_TRANSFORM'),
  );
  assert.throws(
    () => new Mappings([item], new Schemas({ input: {}, output: { type: 'string' } })),
    code('EK_JSON_TRANSFORM'),
  );
});
test('Mappings reject executable values and hostile keys, remain immutable, and preserve safe timeout errors', () => {
  const item = mapping({ x: { op: 'copy', path: '/value', required: true } }),
    compiled = new Mappings([item], schemas);
  (item.fields as Record<string, JsonMappingExpr>).x = { op: 'literal', value: 'mutated' };
  assert.equal(
    (compiled.transform({ value: 'original' }, item.id) as Record<string, unknown>).x,
    'original',
  );
  for (const value of [
    {
      get private() {
        throw Error('Never execute');
      },
    },
    JSON.parse('{"__proto__":{}}'),
    () => true,
    1n,
    new Date(),
  ])
    assert.throws(() => compiled.transform(value, item.id), code('EK_JSON_TRANSFORM'));
  assert.throws(() => compiled.transform({ value: 1 }, 'unknown'), code('EK_JSON_TRANSFORM'));
  for (const name of ['EK_TIMEOUT', 'EK_ABORTED'] as const)
    assert.throws(
      () =>
        compiled.transform({ value: 1 }, item.id, () => {
          throw failure(name);
        }),
      code(name),
    );
  assert.throws(
    () => compiled.transform({ value: () => true }, item.id),
    (error: unknown) =>
      error instanceof KitError && !JSON.stringify(error.toSafeJSON()).includes('original'),
  );
});

test('Known literal and scalar-conversion output incompatibilities fail during native startup compilation', () => {
  const catalog = new Schemas({
    input: {},
    output: { type: 'object', properties: { x: { type: 'integer', minimum: 1 } } },
  });
  for (const expr of [
    { op: 'literal', value: 0 },
    { op: 'literal', value: 'wrong' },
    { op: 'to-string', value: { op: 'literal', value: 1 } },
    { op: 'to-boolean', value: { op: 'literal', value: true } },
  ] as const)
    assert.throws(() => new Mappings([mapping({ x: expr })], catalog), code('EK_JSON_TRANSFORM'));
  assert.equal(
    (
      new Mappings([mapping({ x: { op: 'literal', value: 1 } })], catalog).transform(
        {},
        'mapping.v1',
      ) as Record<string, unknown>
    ).x,
    1,
  );
});

test('Literal and copied output trees cannot bypass cumulative node, array-item or nested depth limits', () => {
  assert.equal(run({ x: { op: 'literal', value: 1 } }, {}, { maxNodes: 1, maxDepth: 1 }).x, 1);
  assert.throws(
    () => run({ x: { op: 'literal', value: [1, 2] } }, {}, { maxArrayItems: 1 }),
    code('EK_JSON_TRANSFORM'),
  );
  assert.throws(
    () => run({ x: { op: 'literal', value: { a: 1 } } }, {}, { maxDepth: 1 }),
    code('EK_JSON_TRANSFORM'),
  );
  assert.throws(
    () => run({ x: { op: 'literal', value: { a: 1, b: 2 } } }, {}, { maxNodes: 2 }),
    code('EK_JSON_TRANSFORM'),
  );
  assert.throws(
    () => run({ x: { op: 'copy', path: '/items' } }, { items: [1, 2] }, { maxArrayItems: 1 }),
    code('EK_JSON_TRANSFORM'),
  );
  assert.throws(
    () => run({ x: { op: 'copy', path: '/item' } }, { item: { a: 1, b: 2 } }, { maxNodes: 2 }),
    code('EK_JSON_TRANSFORM'),
  );
});
