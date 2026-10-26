// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { KitError } from '@arkenivajs/core';
import { createTelemetry } from '@arkenivajs/telemetry';
import { createCertificateFixture } from '../../../examples/certificates/dist/trust-fixture.js';
import { nativeCertificateOperations } from '../x509-native.mjs';

test('The native certificate comparison exercises all utilities and actual TLS/CRL verification', async () => {
  const backend = await createCertificateFixture({ testOnly: true });
  try {
    const operations = nativeCertificateOperations(backend.provider, backend),
      certificate = new X509Certificate(backend.leafDer);
    assert.equal(operations.parse().fingerprint256, certificate.fingerprint256);
    assert.equal(
      operations.daysUntilExpiry(),
      Math.floor((certificate.validToDate.getTime() - Date.now()) / 86400000),
    );
    assert.deepEqual(operations.getFingerprints(), {
      sha256: certificate.fingerprint256.replaceAll(':', '').toLowerCase(),
      sha512: certificate.fingerprint512.replaceAll(':', '').toLowerCase(),
    });
    assert.equal((await operations.inspectChain()).status, 'trusted');
    await backend.revoke();
    await assert.rejects(operations.inspectChain());
    assert.equal(backend.checks(), 2);
  } finally {
    await backend.close();
  }
});
test('The certificate runner rejects deferred campaigns and product-local output before opening fixtures', () => {
  const file = fileURLToPath(new URL('../x509.mjs', import.meta.url));
  for (const args of [
    ['--full', '/tmp/unapproved-certificate-campaign'],
    [
      '--smoke',
      fileURLToPath(new URL('../../../.build/forbidden-certificate-evidence', import.meta.url)),
    ],
  ]) {
    const result = spawnSync(process.execPath, [file, ...args], {
      encoding: 'utf8',
      timeout: 10000,
    });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.ok(!result.stderr.includes('Certificate smoke profile passed'));
  }
});
test('Certificate diagnostics do not broaden the native SDK label policy to accept arbitrary status labels', () => {
  assert.throws(
    () =>
      createTelemetry({
        service: { name: 'certificate-policy', version: '1.0.0', environment: 'test' },
        mode: 'off',
        labelValues: { status: ['trusted'] },
      }),
    (error) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
  );
});
