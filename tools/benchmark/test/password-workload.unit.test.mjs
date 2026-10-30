// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { Writable } from 'node:stream';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import * as argon2 from 'argon2';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { passwordPlugin } from '@arkenivajs/security-password';
import { nativePassword, passwordSettings, verifyPassword } from '../password-workload.mjs';

test('Native password comparison checks actual Argon2id salt, matching, rejection and legacy rehash', async () => {
  const plain = randomBytes(24).toString('base64url'),
    fixture = {
      plain,
      legacyPhc: await argon2.hash(plain, {
        type: argon2.argon2id,
        memoryCost: 4096,
        timeCost: 1,
        parallelism: 1,
        hashLength: 32,
      }),
    };
  assert.deepEqual(await verifyPassword(nativePassword(), fixture), {
    checkedHashes: 2,
    checkedVerifications: 3,
    independentSaltVerified: true,
    legacyRehashVerified: true,
  });
});
test('KDF comparison denies reset operations and rejects test-only providers in production', async () => {
  const settings = passwordSettings({
    endpoint: 'http://127.0.0.1:1/budget',
    bearer: randomBytes(32).toString('base64url'),
  });
  await assert.rejects(settings.authority.require());
  await assert.rejects(settings.resetCommitter.commitReset());
  let secretCalls = 0;
  settings.secretProvider.get = async () => {
    secretCalls++;
    throw new Error('Production must reject the fixture before secret loading');
  };
  const destination = new Writable({
      write(_chunk, _encoding, done) {
        done();
      },
    }),
    app = await createApplication({
      service: { name: 'password-comparison-guard', version: '1.0.0', environment: 'production' },
      plugins: [loggingPlugin({ destination }), passwordPlugin(settings)],
    });
  try {
    await assert.rejects(app.start(), { code: 'EK_PLUGIN_FAILED' });
    assert.equal(secretCalls, 0);
  } finally {
    await app.stop();
    destination.destroy();
  }
});
test('Password CLI refuses sampling and missing disposable database authorization before output creation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-password-guard-')),
    script = fileURLToPath(new URL('../password.mjs', import.meta.url));
  try {
    for (const mode of ['--verify', '--smoke']) {
      const output = join(directory, mode.slice(2));
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, mode, output], {
          env: { NODE_ENV: 'test', LANG: 'C.UTF-8' },
          timeout: 5000,
          maxBuffer: 1048576,
        }),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
