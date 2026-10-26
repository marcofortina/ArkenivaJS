// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { KitError } from '@arkenivajs/core';
import { runCertificateExample } from '../../src/main.js';
import { createCertificateFixture } from '../../src/trust-fixture.js';

test('The public certificate example verifies TLS, fingerprints, CRL revocation and lifecycle', async () => {
  const result = await runCertificateExample({ testOnly: true });
  assert.deepEqual(result, {
    parsed: true,
    fingerprints: true,
    trustedBeforeRevocation: true,
    wrongHostnameDenied: true,
    revokedCertificateDenied: true,
    closed: true,
    trustChecks: 2,
  });
  assert.equal(JSON.stringify(result).includes('localhost'), false);
});
test('Disposable certificate creation requires explicit test authorization before opening resources', async () => {
  await assert.rejects(
    createCertificateFixture({ testOnly: false } as never),
    (error) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
  );
});
test('The certificate CLI refuses implicit disposable infrastructure with safe diagnostics', () => {
  const env = { ...process.env };
  delete env.ARKENIVA_X509_DISPOSABLE;
  const result = spawnSync(process.execPath, ['dist/main.js'], {
    encoding: 'utf8',
    env,
    timeout: 10000,
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  const error = JSON.parse(result.stderr) as { code: string; cause?: unknown };
  assert.equal(error.code, 'EK_CONFIG_INVALID');
  assert.equal(error.cause, undefined);
});
