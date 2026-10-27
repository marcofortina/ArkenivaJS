// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { Schemas } from '../../dist/schemas.js';
import { Mappings } from '../../dist/mappings.js';
import type { JsonMappingV1 } from '../../dist/index.js';

test('Bounded mapping corpus preserves item order, strict conversions and missing versus null semantics', () => {
  const schemas = new Schemas({
    input: {
      type: 'object',
      properties: {
        items: { type: 'array', items: { type: 'string' } },
        label: { type: ['string', 'null'] },
      },
      required: ['items'],
    },
    output: {
      type: 'object',
      properties: {
        items: { type: 'array', items: { type: 'integer' } },
        label: { type: 'string' },
      },
      required: ['items', 'label'],
      additionalProperties: false,
    },
  });
  const mapping: JsonMappingV1 = {
    schemaVersion: '1.0.0',
    id: 'corpus.v1',
    inputSchemaId: 'input',
    outputSchemaId: 'output',
    fields: {
      items: {
        op: 'array-map',
        path: '/items',
        maxItems: 16,
        item: { op: 'to-number', value: { op: 'copy', path: '', required: true } },
      },
      label: {
        op: 'coalesce',
        args: [
          { op: 'copy', path: '/label' },
          { op: 'literal', value: 'fallback' },
        ],
      },
    },
    limits: { maxDepth: 8, maxNodes: 64, maxArrayItems: 16, maxOutputBytes: 8192 },
  };
  const mappings = new Mappings([mapping], schemas);
  fc.assert(
    fc.property(
      fc.array(fc.integer(), { maxLength: 16 }),
      fc.option(fc.string({ maxLength: 32 }), { nil: null }),
      (items, label) => {
        const output = mappings.transform({ items: items.map(String), label }, mapping.id) as {
          items: readonly number[];
          label: string;
        };
        assert.deepEqual(output.items, items);
        assert.equal(output.label, label ?? 'fallback');
        assert.ok(Object.isFrozen(output.items));
      },
    ),
    { seed: 20261028, numRuns: 250 },
  );
});
