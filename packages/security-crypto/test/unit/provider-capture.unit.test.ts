// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, createHmac } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { cryptoPlugin, CRYPTO_CAPABILITY } from '../../dist/index.js';
import type { CryptoPluginSettings, CryptoService } from '../../dist/index.js';
import { captureSettings } from '../../dist/runtime.js';

function settings(): CryptoPluginSettings {
  return {
    secrets: {
      async get() {
        throw new Error('The original disposable key provider is unavailable');
      },
    },
    encryptionKeyRefs: ['fixture/encryption'],
    signingKeyRefs: ['fixture/mac'],
    policy: { maxConcurrent: 4, timeoutMs: 2000 },
  };
}

test('Custom secret callback bind metadata cannot replace an unavailable cryptographic provider', async () => {
  const input = settings();
  let redirected = 0;
  Object.defineProperty(input.secrets.get, 'bind', {
    value: () => async () => {
      redirected++;
      return { bytes: randomBytes(32), keyVersion: 'fixture' };
    },
  });
  const captured = captureSettings(input);
  await assert.rejects(captured.get('fixture/encryption'), {
    message: 'The original disposable key provider is unavailable',
  });
  assert.equal(redirected, 0);
});

test('Actual native AES and HMAC retain captured key-provider implementation and receiver without callable metadata', async () => {
  const encryption = randomBytes(32),
    macKey = randomBytes(32),
    version = randomUUID(),
    input = settings();
  let effects = 0,
    calls = 0,
    available = true;
  const provider = {
    usage: 'test-only' as const,
    async get(reference: string) {
      assert.equal(this, provider);
      calls++;
      if (!available) throw new Error('The disposable key authority is unavailable');
      if (!['fixture/encryption', 'fixture/mac'].includes(reference))
        throw new Error('Unknown owned reference');
      return {
        bytes: reference === 'fixture/encryption' ? encryption : macKey,
        keyVersion: version,
      };
    },
  };
  for (const field of ['bind', 'name', 'length'])
    Object.defineProperty(provider.get, field, {
      get() {
        effects++;
        throw new Error('Executable cryptographic provider metadata');
      },
    });
  const plugin = cryptoPlugin({ ...input, secrets: provider });
  assert.equal(calls, 0);
  provider.get = async () => {
    throw new Error('Late key-provider replacement');
  };
  const app = await createApplication({
    service: { name: 'crypto-provider-capture', version: '1.0.0', environment: 'test' },
    plugins: [plugin],
  });
  try {
    await app.start();
    const crypto = app.resolve<CryptoService>(CRYPTO_CAPABILITY),
      plaintext = Buffer.from('Owned cryptographic provider round trip'),
      aad = Buffer.from('owned-purpose'),
      sealed = await crypto.encrypt(plaintext, 'fixture/encryption', aad);
    assert.deepEqual(await crypto.decrypt(sealed, 'fixture/encryption', aad), plaintext);
    await assert.rejects(
      crypto.decrypt(sealed, 'fixture/encryption', Buffer.from('foreign-purpose')),
    );
    const mac = await crypto.hmac(plaintext, 'fixture/mac');
    assert.deepEqual(mac, createHmac('sha256', macKey).update(plaintext).digest());
    assert.equal(await crypto.verifyMac(plaintext, mac, 'fixture/mac'), true);
    assert.equal(await crypto.verifyMac(Buffer.from('altered'), mac, 'fixture/mac'), false);
    available = false;
    await assert.rejects(crypto.encrypt(plaintext, 'fixture/encryption'), {
      code: 'EK_CRYPTO_KEY_UNAVAILABLE',
    });
    await assert.rejects(crypto.hmac(plaintext, 'fixture/mac'), {
      code: 'EK_CRYPTO_KEY_UNAVAILABLE',
    });
    assert.ok(calls >= 8);
    assert.equal(effects, 0);
  } finally {
    await app.stop();
    encryption.fill(0);
    macKey.fill(0);
  }
});

test('Cryptographic provider/function proxies and hidden test-only classification fail before executable metadata', () => {
  const input = settings();
  let effects = 0;
  const traps = {
    get() {
      effects++;
      throw new Error('Executable key provider get');
    },
    getOwnPropertyDescriptor() {
      effects++;
      throw new Error('Executable key provider descriptor');
    },
    getPrototypeOf() {
      effects++;
      throw new Error('Executable key provider prototype');
    },
    apply() {
      effects++;
      throw new Error('Executable key provider call');
    },
  };
  for (const secrets of [
    new Proxy(input.secrets, traps),
    { get: new Proxy(input.secrets.get, traps) },
    Object.create(new Proxy({}, traps)) as typeof input.secrets,
  ])
    assert.throws(() => cryptoPlugin({ ...input, secrets }), { code: 'EK_CONFIG_INVALID' });
  let deep: object = { usage: 'test-only' };
  for (let depth = 0; depth < 33; depth++) deep = Object.create(deep) as object;
  const hidden = Object.create(deep) as typeof input.secrets;
  Object.defineProperty(hidden, 'get', { value: input.secrets.get });
  assert.throws(() => cryptoPlugin({ ...input, secrets: hidden }), { code: 'EK_CONFIG_INVALID' });
  assert.equal(effects, 0);
});
