// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runJsonExample } from '../dist/main.js';
test('The compiled public JSON consumer parses, validates and transforms versioned data through actual native workers', async () => {
  const value = await runJsonExample();
  assert.equal(value.valid, true);
  assert.equal(value.item, '001');
  assert.equal(value.enabled, true);
  assert.ok(value.outputBytes > 0);
});
