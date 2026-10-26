// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { directApiKeyVerifier } from '../apikey-native.mjs';
import { countSensitiveValues, fingerprint, rememberSensitiveValues } from '../mfa-privacy.mjs';
import {
  fixtureSettings,
  application,
  grant,
} from '../../../packages/security-apikey/dist-test/unit/fixture.js';

test('Direct credential reference retains real HMAC, shared state and authority boundaries', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, { ...grant(), allowedIpRanges: ['192.0.2.0/24'] }),
      verify = await directApiKeyVerifier({ ...f.settings, store: f.settings.store.store });
    assert.equal((await verify(issued.value, { clientIp: '192.0.2.15' })).keyId, issued.id);
    await assert.rejects(
      verify(issued.keyPrefix + '.' + randomBytes(32).toString('base64url'), {
        clientIp: '192.0.2.15',
      }),
    );
    await assert.rejects(
      verify('ak1.' + randomUUID() + '.' + randomBytes(32).toString('base64url'), {
        clientIp: '192.0.2.15',
      }),
    );
    await assert.rejects(verify(issued.value, {}));
    await assert.rejects(verify(issued.value, { clientIp: '198.51.100.2' }));
    f.state.enabled = false;
    await assert.rejects(verify(issued.value, { clientIp: '192.0.2.15' }));
    f.state.enabled = true;
    await keys.revoke(issued.id, f.owner);
    await assert.rejects(verify(issued.value, { clientIp: '192.0.2.15' }));
  } finally {
    await app.stop();
  }
});
test('Direct credential reference denies stale final versions and unavailable storage', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, grant()),
      read = f.store.read.bind(f.store);
    let credentialReads = 0;
    const store = {
      ...f.store,
      async read(namespace, id, options) {
        const row = await read(namespace, id, options);
        if (namespace === 'apikey.records.v1' && ++credentialReads === 2)
          return { ...row, version: randomUUID() };
        return row;
      },
    };
    const verify = await directApiKeyVerifier({ ...f.settings, store });
    await assert.rejects(verify(issued.value, {}));
    f.state.fail = true;
    await assert.rejects(verify(issued.value, {}));
  } finally {
    await app.stop();
  }
});
test('Credential privacy corpus ignores only empty absence while detecting whole and embedded verifier material', () => {
  const secret = randomBytes(32).toString('base64url'),
    version = randomUUID(),
    digest = randomBytes(32).toString('hex'),
    privateValues = new Set();
  rememberSensitiveValues(
    { absent: '', parts: ['negative', '', secret], verifier: version + ':' + digest },
    privateValues,
  );
  assert.equal(privateValues.has(fingerprint('')), false);
  assert.equal(countSensitiveValues({ description: '' }, privateValues), 0);
  assert.ok(countSensitiveValues({ token: secret }, privateValues) > 0);
  assert.ok(
    countSensitiveValues({ message: 'Verifier ' + version + ':' + digest }, privateValues) > 0,
  );
  assert.ok(countSensitiveValues({ keyVersion: version }, privateValues) > 0);
  assert.throws(
    () =>
      rememberSensitiveValues(
        Object.defineProperty({}, 'private', {
          get() {
            throw new Error('Getter must not run');
          },
          enumerable: true,
        }),
        privateValues,
      ),
    /data properties/,
  );
});
test('Credential smoke rejects deferred campaigns and product-local reports before opening storage', () => {
  const result = spawnSync(
    process.execPath,
    ['tools/benchmark/apikey.mjs', '--full', '/invalid/report'],
    { cwd: new URL('../../../', import.meta.url), encoding: 'utf8', env: {} },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Use --smoke/);
  const local = spawnSync(
    process.execPath,
    [
      'tools/benchmark/apikey.mjs',
      '--smoke',
      fileURLToPath(new URL('../../../', import.meta.url)).replace(/\/$/, ''),
    ],
    {
      cwd: new URL('../../../', import.meta.url),
      encoding: 'utf8',
      env: { ARKENIVA_POSTGRES_DISPOSABLE: '1' },
    },
  );
  assert.notEqual(local.status, 0);
  assert.match(local.stderr, /Benchmark evidence must remain outside/);
});
