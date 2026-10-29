// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { webhooksPlugin } from '../../dist/index.js';
import { fixture, fixtureSettings } from './fixture.js';

test('Webhook authorization cannot be replaced through custom callable bind metadata', async () => {
  const input = fixtureSettings();
  const authority = input.settings.authority;
  const original = authority.require;
  let redirected = 0;
  Object.defineProperty(original, 'bind', {
    value:
      () =>
      (...args: Parameters<typeof original>) => {
        redirected++;
        return input.asTenant('tenant-a', () => Reflect.apply(original, authority, args));
      },
  });
  const f = await fixture(input);
  try {
    await assert.rejects(f.service.sign(Buffer.from('{}'), 'current', f.context()), {
      code: 'EK_AUTH_FORBIDDEN',
    });
    assert.equal(redirected, 0);
    assert.equal(f.state.secretCalls, 0);
  } finally {
    await f.close();
  }
});

test('Native webhook HMAC and single-use nonce retain original provider methods without callable metadata', async () => {
  const input = fixtureSettings();
  let effects = 0;
  const providers = [
    input.settings.secretProvider,
    input.settings.authority,
    input.settings.nonceStore.store,
  ];
  for (const provider of providers)
    for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(provider)))
      if ('value' in descriptor && typeof descriptor.value === 'function')
        for (const key of ['bind', 'name', 'length'])
          Object.defineProperty(descriptor.value, key, {
            get() {
              effects++;
              throw new Error('Provider callable metadata must not execute');
            },
          });
  const f = await fixture(input);
  try {
    Object.defineProperty(input.settings.secretProvider, 'get', {
      value() {
        throw new Error('A late secret provider replacement must not run');
      },
    });
    Object.defineProperty(input.settings.authority, 'require', {
      value() {
        throw new Error('A late authority replacement must not run');
      },
    });
    Object.defineProperty(input.settings.nonceStore.store, 'claimOnce', {
      value() {
        throw new Error('A late nonce provider replacement must not run');
      },
    });
    const context = f.context(),
      body = Buffer.from(' {"owned":"raw"}\n');
    const signature = await f.asTenant('tenant-a', () => f.service.sign(body, 'current', context));
    const framing = Buffer.from(
      JSON.stringify([
        'arkenivajs.webhooks.v1',
        'tenant-a',
        'receiver',
        'event-one',
        context.timestamp,
        context.nonce,
        'one',
      ]) + '\n',
    );
    assert.equal(
      signature.signature,
      createHmac('sha256', f.keys.get('current')!.bytes)
        .update(framing)
        .update(body)
        .digest('base64url'),
    );
    await f.asTenant('tenant-a', () => f.service.verify(body, signature, context));
    await assert.rejects(
      f.asTenant('tenant-a', () => f.service.verify(body, signature, context)),
      { code: 'EK_WEBHOOK_REPLAY' },
    );
    assert.equal(f.state.claimCalls, 2);
    assert.equal(effects, 0);
    assert.ok(!f.logs.join('').includes(signature.signature));
  } finally {
    await f.close();
  }
});

test('Webhook provider capture rejects proxy callbacks and classification prototypes without executing traps', () => {
  const f = fixtureSettings();
  let effects = 0;
  const fail = () => {
    effects++;
    throw new Error('Proxy inspection must not execute');
  };
  const handler: ProxyHandler<object> = {
    get: fail,
    getPrototypeOf: fail,
    getOwnPropertyDescriptor: fail,
  };
  try {
    for (const provider of [
      new Proxy(f.settings.authority, handler),
      { require: new Proxy(f.settings.authority.require, handler) },
      Object.assign(Object.create(new Proxy({}, handler)), f.settings.authority),
    ])
      assert.throws(() => webhooksPlugin({ ...f.settings, authority: provider }), {
        code: 'EK_CONFIG_INVALID',
      });
    assert.equal(effects, 0);
  } finally {
    for (const key of f.keys.values()) key.bytes.fill(0);
  }
});

test('Webhook provider descriptors reject missing methods, accessors and excessive depth while retaining inherited data methods', () => {
  const f = fixtureSettings();
  let effects = 0;
  const accessor = Object.defineProperty({}, 'get', {
    get() {
      effects++;
      throw new Error('A provider accessor must not run');
    },
  });
  let deep: object = f.settings.secretProvider;
  for (let index = 0; index < 65; index++) deep = Object.create(deep);
  try {
    for (const secretProvider of [
      null,
      1,
      {},
      { get: false },
      accessor,
      deep,
      { ...f.settings.secretProvider, usage: 'unsupported' },
    ])
      assert.throws(() => webhooksPlugin({ ...f.settings, secretProvider } as never), {
        code: 'EK_CONFIG_INVALID',
      });
    const inherited = Object.create(f.settings.secretProvider);
    assert.doesNotThrow(() => webhooksPlugin({ ...f.settings, secretProvider: inherited }));
    assert.equal(effects, 0);
  } finally {
    for (const key of f.keys.values()) key.bytes.fill(0);
  }
});
