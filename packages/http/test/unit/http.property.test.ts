// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { KitError } from '@arkenivajs/core';
import { createHttpClient } from '@arkenivajs/http';

test('EK-HTTP-002 arbitrary URLs cannot escape an empty destination policy', async () => {
  const client = createHttpClient({ allowedOrigins: [] });
  try {
    await fc.assert(
      fc.asyncProperty(fc.string(), async (input) => {
        await assert.rejects(
          client.get(input),
          (error) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
        );
      }),
      { seed: 2502, numRuns: 300 },
    );
  } finally {
    await client.close();
  }
});
