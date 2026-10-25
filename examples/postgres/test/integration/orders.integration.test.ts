// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { runOrdersExample } from '../../dist/main.js';

test('The built PostgreSQL consumer preserves precision, classifies duplicates and rolls back real writes', async () => {
  assert.deepEqual(await runOrdersExample(), {
    rows: [{ id: '9007199254740993', total: '5.25' }],
    duplicateRejected: true,
    rollbackVerified: true,
  });
});
