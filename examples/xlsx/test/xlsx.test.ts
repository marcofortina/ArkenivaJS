// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runXlsxExample } from '../dist/main.js';

test('The public XLSX consumer preserves typed, styled Unicode values across two streamed sheets', async () => {
  const result = await runXlsxExample();
  assert.deepEqual(result.counts, [3, 1]);
  assert.equal(result.receipt.sheetCount, 2);
  assert.equal(result.receipt.writtenRows, 4);
  assert.ok(result.receipt.outputBytes > 0);
  const id = result.sample[0],
    amount = result.sample[2];
  assert.equal(id && typeof id === 'object' && 'value' in id ? id.value : id, '001');
  assert.ok(amount && typeof amount === 'object' && 'style' in amount);
  assert.equal(amount.value, 123.45);
  assert.equal(amount.style?.numberFormat, '#,##0.00');
  assert.equal(amount.style?.fontColorHex, '#112233');
});
