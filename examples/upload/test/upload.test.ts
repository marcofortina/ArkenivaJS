// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { runUploadExample } from '../dist/main.js';

const expected = {
  accepted: 200,
  denied: 401,
  files: 1,
  bytes: 6,
  wireBytesVerified: true,
  tenantVerified: true,
  logsPrivate: true,
  metricsObserved: true,
  metricsPrivate: true,
  meterObserved: true,
  meterPrivate: true,
  meterClosed: true,
  meterGap: false,
};
test('The public multipart example verifies OIDC tenant provenance, actual wire bytes and private Pino/OTel/meter observations', async () => {
  assert.deepEqual(await runUploadExample(), expected);
});
test('The documented multipart executable prints safe results and exits after owned resource cleanup', async () => {
  const result = await promisify(execFile)(
    process.execPath,
    [fileURLToPath(new URL('../dist/main.js', import.meta.url))],
    { timeout: 15000 },
  );
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), expected);
});

test('Missing custom metering dimensions report a gap, close their session and preserve the actual upload outcome', async () => {
  assert.deepEqual(await runUploadExample(false), {
    ...expected,
    meterObserved: false,
    meterGap: true,
  });
});
