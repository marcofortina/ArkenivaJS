// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { createConfig } from '@arkenivajs/config';
import { KitError } from '@arkenivajs/core';

test('EK-CONF-001 random hostile JSON values are validated or rejected without mutation', async () => {
  await fc.assert(
    fc.asyncProperty(fc.jsonValue(), async (value) => {
      const text = JSON.stringify(value);
      try {
        const config = await createConfig<Record<string, unknown>>({
          workspace: process.cwd(),
          schema: {
            type: 'object',
            additionalProperties: false,
            properties: { count: { type: 'integer', minimum: 0, maximum: 100 } },
          },
          runtime: value as Record<string, unknown>,
          environment: {},
        });
        assert.ok(Object.isFrozen(config.snapshot()));
      } catch (error) {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_CONFIG_INVALID');
      }
      assert.equal(JSON.stringify(value), text);
    }),
    { seed: 2403, numRuns: 300 },
  );
});

test('EK-CONF-001 concurrent reload generations preserve atomic order', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.integer({ min: 0, max: 100 }), { minLength: 1, maxLength: 25 }),
      async (counts) => {
        const events: unknown[] = [];
        const config = await createConfig<{ count: number }>({
          workspace: process.cwd(),
          schema: {
            type: 'object',
            additionalProperties: false,
            properties: { count: { type: 'integer' } },
            required: ['count'],
          },
          runtime: { count: 0 },
          dynamicPaths: ['count'],
          environment: {},
          onDiagnostic(event) {
            events.push(event);
          },
        });
        const before = config.snapshot();
        await Promise.all(counts.map((count) => config.reload({ count })));
        assert.equal(config.require('count'), counts.at(-1));
        assert.equal(before.count, 0);
        assert.equal(events.length, counts.length);
      },
    ),
    { seed: 2404, numRuns: 100 },
  );
});
