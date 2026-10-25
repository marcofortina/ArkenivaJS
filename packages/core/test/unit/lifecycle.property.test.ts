// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { createApplication, KitError } from '@arkenivajs/core';

test('EK-CORE-001 random lifecycle sequences preserve terminal closure and exact hook counts', async () => {
  await fc.assert(
    fc.asyncProperty(fc.array(fc.boolean(), { maxLength: 30 }), async (operations) => {
      let starts = 0,
        closes = 0;
      const app = await createApplication({
        service: { name: 'state-test', version: '1.0.0', environment: 'test' },
        plugins: [
          {
            id: 'counter',
            version: '1.0.0',
            capabilities: new Set(),
            init() {
              starts++;
            },
            close() {
              closes++;
            },
          },
        ],
      });
      for (const start of operations) {
        if (start && app.state === 'CLOSED')
          await assert.rejects(
            app.start(),
            (error) => error instanceof KitError && error.code === 'EK_LIFECYCLE_STATE',
          );
        else if (start) await Promise.all([app.start(), app.start()]);
        else await Promise.all([app.stop(), app.stop()]);
      }
      await app.stop();
      assert.equal(app.state, 'CLOSED');
      assert.equal(starts, closes);
      assert.ok(starts <= 1);
    }),
    { seed: 2402, numRuns: 100 },
  );
});
