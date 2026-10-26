// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApplication, KitError } from '@arkenivajs/core';
import { cryptoPlugin, CRYPTO_CAPABILITY } from '@arkenivajs/security-crypto';
import type { CryptoService } from '@arkenivajs/security-crypto';
import { createSecretFixture } from './secret-fixture.js';

/** Run a disposable HTTPS-backed encryption/signature flow, returning only non-secret outcomes. */
export async function runCryptographyExample(authorization: { readonly testOnly: true }) {
  const fixture = await createSecretFixture(authorization);
  let app: Awaited<ReturnType<typeof createApplication>> | undefined;
  const plaintext = Buffer.from('Disposable demonstration payload'),
    aad = Buffer.from('verified-tenant:document-purpose');
  try {
    app = await createApplication({
      service: { name: 'cryptography-example', version: '1.0.0', environment: 'test' },
      plugins: [
        cryptoPlugin({
          secrets: fixture.provider,
          signingKeyRefs: ['hmac', 'signing'],
          encryptionKeyRefs: ['encryption', 'previous'],
          policy: { maxConcurrent: 4, timeoutMs: 3000, maxInputBytes: 4096, maxOutputBytes: 4124 },
        }),
      ],
    });
    await app.start();
    const crypto = app.resolve<CryptoService>(CRYPTO_CAPABILITY);
    const envelope = await crypto.encrypt(plaintext, 'encryption', aad);
    const decrypted = await crypto.decrypt(envelope, 'encryption', aad);
    assert.deepEqual(decrypted, plaintext);
    decrypted.fill(0);
    const mac = await crypto.hmac(plaintext, 'hmac');
    const validMac = await crypto.verifyMac(plaintext, mac, 'hmac');
    mac.fill(0);
    const signature = await crypto.sign(plaintext, 'signing');
    const validSignature = await crypto.verifySignature(plaintext, signature, fixture.publicKey);
    signature.fill(0);
    fixture.rotate();
    await assert.rejects(
      crypto.decrypt(envelope, 'encryption', aad),
      (error) => error instanceof KitError && error.code === 'EK_CRYPTO_KEY_UNAVAILABLE',
    );
    const previous = await crypto.decrypt(envelope, 'previous', aad);
    assert.deepEqual(previous, plaintext);
    previous.fill(0);
    await app.stop();
    await assert.rejects(
      crypto.hmac(plaintext, 'hmac'),
      (error) => error instanceof KitError && error.code === 'EK_RESOURCE_CLOSED',
    );
    return {
      encryption: true,
      validMac,
      validSignature,
      rotation: true,
      closed: true,
      secretRequests: fixture.requestCount(),
    };
  } finally {
    plaintext.fill(0);
    aad.fill(0);
    try {
      await app?.stop();
    } finally {
      await fixture.close();
    }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.env.ARKENIVA_CRYPTO_DISPOSABLE !== '1')
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Explicit disposable cryptography example authorization is required',
      });
    console.log(JSON.stringify(await runCryptographyExample({ testOnly: true })));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The cryptography example could not finish' },
      ),
    );
    process.exitCode = 1;
  }
}
