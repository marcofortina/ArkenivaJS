// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { nativeCryptoOperations } from '../crypto-native.mjs';

test('The native crypto comparison preserves borrowed keys and verifies every configured primitive', async () => {
  const ed = generateKeyPairSync('ed25519'),
    ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const fixture = {
    input: randomBytes(1024),
    aad: randomBytes(32),
    edPublicKey: ed.publicKey.export({ format: 'der', type: 'spki' }),
    ecPublicKey: ec.publicKey.export({ format: 'der', type: 'spki' }),
    values: new Map([
      ['encryption', { bytes: randomBytes(32), keyVersion: randomUUID() }],
      ['hmac', { bytes: randomBytes(32), keyVersion: randomUUID() }],
      [
        'ed',
        { bytes: ed.privateKey.export({ format: 'der', type: 'pkcs8' }), keyVersion: randomUUID() },
      ],
      [
        'ec',
        { bytes: ec.privateKey.export({ format: 'der', type: 'pkcs8' }), keyVersion: randomUUID() },
      ],
    ]),
  };
  const originals = [...fixture.values.values()].map((value) => Buffer.from(value.bytes));
  const operations = nativeCryptoOperations(
    { get: async (reference) => fixture.values.get(reference) },
    fixture,
  );
  try {
    fixture.envelope = await operations.encrypt();
    assert.deepEqual(await operations.decrypt(), fixture.input);
    fixture.mac = await operations.hmac();
    assert.equal(await operations.verifyMac(), true);
    fixture.edSignature = await operations.signEd25519();
    assert.equal(await operations.verifyEd25519(), true);
    fixture.ecSignature = await operations.signP256();
    assert.equal(await operations.verifyP256(), true);
    [...fixture.values.values()].forEach((value, index) =>
      assert.deepEqual(value.bytes, originals[index]),
    );
    fixture.aad[0] ^= 1;
    await assert.rejects(operations.decrypt());
    fixture.aad[0] ^= 1;
    fixture.mac[0] ^= 1;
    assert.equal(await operations.verifyMac(), false);
    fixture.edSignature[0] ^= 1;
    assert.equal(await operations.verifyEd25519(), false);
    fixture.ecSignature[0] ^= 1;
    assert.equal(await operations.verifyP256(), false);
    fixture.values.set('encryption', {
      ...fixture.values.get('encryption'),
      keyVersion: randomUUID(),
    });
    await assert.rejects(operations.decrypt(), /version mismatch/);
  } finally {
    for (const value of fixture.values.values()) value.bytes.fill(0);
    for (const value of originals) value.fill(0);
  }
});
test('The crypto runner rejects deferred full campaigns and in-repository evidence before starting a worker', () => {
  const file = fileURLToPath(new URL('../crypto.mjs', import.meta.url));
  for (const args of [
    ['--full', '/tmp/unapproved-crypto-campaign'],
    [
      '--smoke',
      fileURLToPath(new URL('../../../.build/forbidden-crypto-evidence', import.meta.url)),
    ],
  ]) {
    const result = spawnSync(process.execPath, [file, ...args], {
      encoding: 'utf8',
      timeout: 10000,
    });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.ok(!result.stderr.includes('Crypto smoke profile passed'));
  }
});
