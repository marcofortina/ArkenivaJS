// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { runMysqlOrdersExample } from '../../dist/main.js';

test('The built MySQL consumer verifies exact values, real duplicate rejection and rollback against disposable InnoDB', async () => {
  assert.deepEqual(await runMysqlOrdersExample(), {
    rows: [{ id: '9007199254740993', total: '5.25' }],
    duplicateRejected: true,
    rollbackVerified: true,
  });
});
