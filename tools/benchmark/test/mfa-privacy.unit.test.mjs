// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomInt } from 'node:crypto';
import { mkdtemp, rm, symlink, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { fingerprint, countSensitiveValues } from '../mfa-privacy.mjs';

test('MFA privacy controls detect actual ephemeral material inside structured and diagnostic values', () => {
  const otp = String(randomInt(100000, 1000000));
  const challenge = randomBytes(32).toString('base64url');
  const uri = 'otpauth://totp/Synthetic?secret=' + randomBytes(20).toString('hex');
  const values = [otp, challenge, uri],
    hashes = new Set(values.map(fingerprint));
  for (const value of values) {
    assert.ok(countSensitiveValues({ nested: [{ value }] }, hashes) > 0);
    assert.ok(countSensitiveValues({ message: "Rejected '" + value + "'" }, hashes) > 0);
  }
  assert.equal(
    countSensitiveValues(
      { operation: 'totp.verify', errors: 0, traceId: randomBytes(16).toString('hex') },
      hashes,
    ),
    0,
  );
  let invoked = 0;
  assert.throws(
    () =>
      countSensitiveValues(
        {
          get value() {
            invoked++;
            return otp;
          },
        },
        hashes,
      ),
    /data properties/,
  );
  assert.equal(invoked, 0);
  const cyclic = {};
  cyclic.self = cyclic;
  assert.equal(countSensitiveValues(cyclic, hashes), 0);
});

test('MFA benchmark evidence cannot enter the repository through a direct or symlinked parent', async () => {
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mfa-path-test-'));
  const env = {
    ...process.env,
    ARKENIVA_POSTGRES_DISPOSABLE: '1',
    ARKENIVA_WEBAUTHN_BROWSER_DISPOSABLE: '1',
    ARKENIVA_WEBAUTHN_BROWSER_URL: 'http://127.0.0.1:1',
  };
  try {
    await symlink(root, join(directory, 'repo'));
    for (const output of [
      join(root, '..mfa-test-output'),
      join(directory, 'repo', '..mfa-test-output'),
    ]) {
      const result = spawnSync(process.execPath, ['tools/benchmark/mfa.mjs', '--smoke', output], {
        cwd: root,
        env,
        encoding: 'utf8',
        timeout: 10000,
      });
      assert.equal(result.status, 1);
      assert.match(result.stderr, /outside the product repository/);
      await assert.rejects(access(join(root, '..mfa-test-output')), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
