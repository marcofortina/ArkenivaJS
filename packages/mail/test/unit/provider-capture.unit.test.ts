// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { createApplication } from '@arkenivajs/core';
import { mailPlugin, MAIL_CAPABILITY } from '../../dist/index.js';
import type { MailService, SecretProvider } from '../../dist/index.js';

const settings = (secretProvider: SecretProvider) => ({
  transports: [
    {
      name: 'local',
      host: 'localhost',
      port: 1,
      requireTls: true as const,
      usernameRef: 'user',
      passwordRef: 'password',
      allowedFromAddresses: ['sender@example.test'],
      maxAttachmentBytes: 1024,
    },
  ],
  secretProvider,
  policy: { maxConcurrent: 1, timeoutMs: 1000 },
});

test('Mail captures secret providers without reading executable callable metadata', () => {
  let effects = 0;
  const provider: SecretProvider = {
    async get() {
      throw new Error('The provider must not run during configuration');
    },
  };
  for (const key of ['bind', 'name', 'length'])
    Object.defineProperty(provider.get, key, {
      get() {
        effects++;
        throw new Error('Callable metadata must not execute');
      },
    });
  assert.doesNotThrow(() => mailPlugin(settings(provider)));
  assert.equal(effects, 0);
});

test('Mail retains the original provider receiver and denial after custom bind and late replacement', async () => {
  let calls = 0,
    redirected = 0;
  const provider: SecretProvider = {
    async get() {
      assert.equal(this, provider);
      calls++;
      throw new Error('The original provider is unavailable');
    },
  };
  Object.defineProperty(provider.get, 'bind', {
    value: () => async () => {
      redirected++;
      return { bytes: new Uint8Array(), keyVersion: 'unused' };
    },
  });
  const plugin = mailPlugin(settings(provider));
  provider.get = async () => {
    redirected++;
    throw new Error('The late replacement must not run');
  };
  const app = await createApplication({
    service: { name: 'mail-provider-capture', version: '1.0.0', environment: 'test' },
    plugins: [plugin],
  });
  try {
    await app.start();
    const mail = app.resolve<MailService>(MAIL_CAPABILITY);
    await assert.rejects(mail.verifyTransport(), { code: 'EK_MAIL_SEND' });
    // Admission remains owned until physical cleanup completes after the public failure.
    await nextTurn();
    await assert.rejects(
      mail.send({
        from: { address: 'sender@example.test' },
        to: [{ address: 'recipient@example.test' }],
        subject: 'fixture',
        text: 'fixture',
      }),
      { code: 'EK_MAIL_SEND' },
    );
    assert.ok(calls >= 2);
    assert.equal(redirected, 0);
  } finally {
    await app.stop();
  }
});

test('Mail rejects secret method accessors, proxies and excessive prototype depth without effects', () => {
  let effects = 0;
  const fail = () => {
    effects++;
    throw new Error('Executable provider inspection must not run');
  };
  const handler: ProxyHandler<object> = {
    get: fail,
    getPrototypeOf: fail,
    getOwnPropertyDescriptor: fail,
  };
  const provider: SecretProvider = {
    async get() {
      throw new Error('The provider must not run');
    },
  };
  let deep: object = provider;
  for (let index = 0; index < 33; index++) deep = Object.create(deep);
  for (const input of [
    Object.defineProperty({}, 'get', { get: fail }),
    new Proxy(provider, handler),
    { get: new Proxy(provider.get, handler) },
    Object.create(new Proxy(provider, handler)),
    deep,
  ])
    assert.throws(() => mailPlugin(settings(input as SecretProvider)), { code: 'EK_MAIL_CONFIG' });
  assert.equal(effects, 0);
});
