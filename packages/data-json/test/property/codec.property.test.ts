// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { parse, stringify, options } from '../../dist/codec.js';
import { Schemas } from '../../dist/schemas.js';

test('Bounded JSON corpus retains native roundtrips and actual schema decisions without coercion', () => {
  const limits = options({ maxBytes: 65536, maxDepth: 16 });
  const schemas = new Schemas({
    rows: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          count: { type: 'integer' },
          values: { type: 'array' },
        },
        required: ['name', 'count', 'values'],
        additionalProperties: false,
      },
    },
  });
  const row = fc.record({
    name: fc.string({ maxLength: 32 }),
    count: fc.integer(),
    values: fc.array(
      fc.oneof(fc.boolean(), fc.integer(), fc.string({ maxLength: 32 }), fc.constant(null)),
      { maxLength: 8 },
    ),
  });
  fc.assert(
    fc.property(fc.array(row, { maxLength: 12 }), (value) => {
      const text = JSON.stringify(value),
        owned = parse(text, limits);
      assert.equal(stringify(owned, limits), text);
      assert.equal(schemas.validate(owned, 'rows').valid, true);
    }),
    { seed: 20261027, numRuns: 250 },
  );
});
