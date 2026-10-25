// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { ConfigStore } from '@arkenivajs/core/support';
import { KitError } from '@arkenivajs/core';

const schema = {
  type: 'object',
  additionalProperties: false,
  properties: { count: { type: 'integer', minimum: 0, maximum: 100 } },
  required: ['count'],
};

test('EK-CONF-001 random concurrent reloads retain complete immutable generations', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.integer({ min: 0, max: 100 }), { minLength: 1, maxLength: 20 }),
      async (counts) => {
        const events: unknown[] = [];
        const store = new ConfigStore(
          { count: 0 },
          {
            schema,
            dynamicPaths: ['count'],
            onDiagnostic(event) {
              events.push(event);
            },
          },
        );
        const before = store.snapshot();
        await Promise.all(counts.map((count) => store.reload({ count })));
        assert.equal(store.require('count'), counts.at(-1));
        assert.equal(events.length, counts.length);
        assert.equal(before.count, 0);
        assert.ok(Object.isFrozen(store.snapshot()));
        await assert.rejects(
          store.reload({ count: -1 }),
          (error) => error instanceof KitError && error.code === 'EK_CONFIG_RELOAD_REJECTED',
        );
        assert.equal(store.require('count'), counts.at(-1));
      },
    ),
    { seed: 2410, numRuns: 100 },
  );
});
