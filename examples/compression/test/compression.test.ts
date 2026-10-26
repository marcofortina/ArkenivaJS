// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { runCompressionExample } from '../dist/main.js';

test('The public compression example roundtrips actual GZIP and individually verified ZIP files', async () => {
  assert.deepEqual(await runCompressionExample(), {
    gzipRoundtrip: true,
    zipEntries: 2,
    verifiedContents: true,
  });
});
test('The executable exits after closing streams and prints only bounded status metadata', async () => {
  const result = await promisify(execFile)(
    process.execPath,
    [fileURLToPath(new URL('../dist/main.js', import.meta.url))],
    { timeout: 10000 },
  );
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), {
    gzipRoundtrip: true,
    zipEntries: 2,
    verifiedContents: true,
  });
});
