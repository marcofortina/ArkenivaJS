// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runPdfExample } from '../dist/main.js';

test('The public PDF consumer creates searchable text, preserves rotations and merges two pages', async () => {
  const result = await runPdfExample();
  assert.equal(result.info.pages, 2);
  assert.equal(result.info.signed, false);
  assert.equal(result.info.encrypted, false);
  assert.ok(result.pages.every((page) => page.text.includes('Protocol 12345/2026')));
  assert.ok(result.pages[1]!.text.includes('Reviewed'));
  assert.ok(result.outputBytes > 0);
});
