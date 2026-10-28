// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

test('GraphQL contract imports expose no listener or implicit engine initialization', async () => {
  const require = createRequire(import.meta.url);
  const engine = require.resolve('mercurius');
  assert.equal(require.cache[engine], undefined);
  const contracts = await import('../../dist/index.js');
  assert.equal(typeof contracts.GRAPHQL_CAPABILITY, 'symbol');
  assert.deepEqual(Object.keys(contracts), ['GRAPHQL_CAPABILITY']);
  assert.equal(require.cache[engine], undefined);
});
