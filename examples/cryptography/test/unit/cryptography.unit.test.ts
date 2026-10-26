// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { KitError } from '@arkenivajs/core';
import { runCryptographyExample } from '../../src/main.js';
import { createSecretFixture } from '../../src/secret-fixture.js';

const expected = {
  encryption: true,
  validMac: true,
  validSignature: true,
  rotation: true,
  closed: true,
  secretRequests: 11,
};
test('The cryptography guide uses verified HTTPS secrets, version rotation and completed cleanup', async () => {
  assert.deepEqual(await runCryptographyExample({ testOnly: true }), expected);
});
test('The explicit cryptography CLI prints only outcomes and refuses implicit live authorization', () => {
  const env = { ...process.env, ARKENIVA_CRYPTO_DISPOSABLE: '1' };
  const result = spawnSync(process.execPath, ['dist/main.js'], {
    encoding: 'utf8',
    env,
    timeout: 15000,
  });
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), expected);
  delete (env as Record<string, string | undefined>).ARKENIVA_CRYPTO_DISPOSABLE;
  const denied = spawnSync(process.execPath, ['dist/main.js'], {
    encoding: 'utf8',
    env,
    timeout: 15000,
  });
  assert.equal(denied.status, 1);
  assert.equal(denied.stdout, '');
  assert.equal(JSON.parse(denied.stderr).code, 'EK_CONFIG_INVALID');
});
test('The disposable HTTPS provider has bounded failure, explicit authorization and idempotent closure', async () => {
  await assert.rejects(
    createSecretFixture({ testOnly: false } as never),
    (error) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
  );
  const fixture = await createSecretFixture({ testOnly: true });
  try {
    const secret = await fixture.provider.get('hmac', { timeoutMs: 1000 });
    assert.equal(secret.bytes.length, 32);
    secret.bytes.fill(0);
    await assert.rejects(
      fixture.provider.get('unknown'),
      (error) => error instanceof KitError && error.code === 'EK_CRYPTO_KEY_UNAVAILABLE',
    );
    const requests = fixture.requestCount();
    await assert.rejects(
      fixture.untrustedProvider.get('hmac'),
      (error) => error instanceof KitError && error.code === 'EK_CRYPTO_KEY_UNAVAILABLE',
    );
    assert.equal(fixture.requestCount(), requests);
    await assert.rejects(
      fixture.provider.get('hmac', { timeoutMs: 0 }),
      (error) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
    );
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      fixture.provider.get('hmac', { signal: controller.signal }),
      (error) => error instanceof KitError && error.code === 'EK_CRYPTO_KEY_UNAVAILABLE',
    );
  } finally {
    await fixture.close();
    await fixture.close();
  }
  await assert.rejects(
    fixture.provider.get('hmac'),
    (error) => error instanceof KitError && error.code === 'EK_CRYPTO_KEY_UNAVAILABLE',
  );
});
