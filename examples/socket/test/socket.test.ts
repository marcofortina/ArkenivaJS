// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { runSocketExample } from '../dist/main.js';

const expected = { tcpBytes: 4, tlsBytes: 4, unixBytes: 4, udpBytes: 4, privatePathRemoved: true };
test(
  'The public socket example exchanges actual TCP, verified TLS, Unix and UDP bytes and cleans its paths',
  { timeout: 10000 },
  async () => {
    assert.deepEqual(await runSocketExample(), expected);
  },
);
test('The public socket CLI emits only safe status counts', { timeout: 10000 }, async () => {
  const { stdout, stderr } = await promisify(execFile)(process.execPath, ['dist/main.js'], {
    cwd: new URL('../', import.meta.url),
    timeout: 10000,
  });
  assert.deepEqual(JSON.parse(stdout), expected);
  assert.equal(stderr, '');
});
