// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runXmlExample } from '../dist/main.js';
test('The compiled public XML consumer roundtrips expanded names and ordered Unicode content through actual workers', async () => {
  const result = await runXmlExample();
  assert.deepEqual(result.roundtrip, result.document);
  assert.ok(result.outputBytes > 0);
});
