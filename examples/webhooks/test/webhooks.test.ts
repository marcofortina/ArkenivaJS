// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { runWebhooksExample } from '../dist/main.js';

const expected = {
  accepted: true,
  attempts: 1,
  deliveries: 1,
  unauthenticatedDenied: true,
  replayDenied: true,
  logsPrivate: true,
  metricsObserved: true,
  metricsPrivate: true,
};
test('The public webhook example verifies signed OIDC roles, actual HTTP HMAC delivery, replay denial and private SDK exports', async () => {
  assert.deepEqual(await runWebhooksExample(), expected);
});
test('The documented webhook executable exits after owned transport and secret cleanup', async () => {
  const result = await promisify(execFile)(
    process.execPath,
    [fileURLToPath(new URL('../dist/main.js', import.meta.url))],
    { timeout: 15000 },
  );
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), expected);
});
