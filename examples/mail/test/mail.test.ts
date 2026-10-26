// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { runMailExample } from '../dist/main.js';

const expected = {
  transportVerified: true,
  accepted: 1,
  logsPrivate: true,
  logObserved: true,
  messages: 1,
  attachmentVerified: true,
  htmlSanitized: true,
  metricsObserved: true,
  metricsPrivate: true,
};
test('The public SMTP example verifies real STARTTLS, MIME, attachments and private SDK observations', async () => {
  assert.deepEqual(await runMailExample(), expected);
});
test('The documented SMTP executable prints only safe status and exits after owned resource cleanup', async () => {
  const result = await promisify(execFile)(
    process.execPath,
    [fileURLToPath(new URL('../dist/main.js', import.meta.url))],
    { timeout: 15000 },
  );
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), expected);
});
