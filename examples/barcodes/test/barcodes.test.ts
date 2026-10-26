// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { runBarcodesExample } from '../dist/main.js';

test('Public packed example roundtrips QR, CODE128 and EAN13 through the process capability', async () => {
  assert.deepEqual(await runBarcodesExample(), { roundtrips: 3, svgGenerated: true });
});
test('The executable example exits after cleanup and prints only bounded result metadata', async () => {
  const result = await promisify(execFile)(
    process.execPath,
    [fileURLToPath(new URL('../dist/main.js', import.meta.url))],
    { timeout: 10000 },
  );
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), { roundtrips: 3, svgGenerated: true });
});
