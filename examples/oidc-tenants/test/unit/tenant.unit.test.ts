// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { runTenantExample } from '../../src/main.js';
const expected = {
  permitted: 200,
  spoofed: 404,
  missing: 401,
  wrongAudience: 401,
  missingScope: 403,
};
test('Tenant guide signs real assertions and rejects spoofing, token confusion and scope denial', async () => {
  assert.deepEqual(await runTenantExample(), expected);
});
test('Documented tenant CLI prints only status evidence and exits after resource cleanup', async () => {
  const result = await promisify(execFile)(process.execPath, ['dist/main.js'], { timeout: 10_000 });
  assert.deepEqual(JSON.parse(result.stdout), expected);
  assert.equal(result.stderr, '');
});
