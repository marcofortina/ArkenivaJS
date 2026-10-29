// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { magicLinksPlugin } from '../../dist/index.js';
import { fixture, application } from '../fixture.js';

test('Custom authority bind metadata cannot issue a magic link without authentication', async () => {
  const f = fixture();
  f.state.authenticated = false;
  let redirected = 0;
  Object.defineProperty(f.settings.authority.require, 'bind', {
    value: () => async () => {
      redirected++;
      return f.owner;
    },
  });
  const { app, magic } = await application(f.settings);
  try {
    await assert.rejects(magic.issue(f.owner, 'login'), { code: 'EK_MAGICLINK_INVALID' });
    assert.equal(redirected, 0);
    assert.equal(f.rows.size, 0);
  } finally {
    await app.stop();
  }
});

test('Native HMAC magic-link issuance, one-use confirmation and revocation retain original provider receivers', async () => {
  const f = fixture(),
    providers = [f.settings.stateStore.store, f.settings.hmac, f.settings.authority],
    calls = new Set<string>();
  let effects = 0;
  for (const provider of providers)
    for (const name of Object.keys(provider)) {
      const original = Object.getOwnPropertyDescriptor(provider, name)?.value as unknown;
      if (typeof original !== 'function') continue;
      const captured = function (this: unknown, ...args: unknown[]) {
        assert.equal(this, provider);
        calls.add(name);
        return Reflect.apply(original, this, args);
      };
      for (const field of ['bind', 'name', 'length'])
        Object.defineProperty(captured, field, {
          get() {
            effects++;
            throw new Error('Executable magic-link provider metadata');
          },
        });
      Object.defineProperty(provider, name, {
        configurable: true,
        writable: true,
        value: captured,
      });
    }
  const { app, magic } = await application(f.settings);
  for (const provider of providers)
    for (const name of Object.keys(provider))
      if (typeof Object.getOwnPropertyDescriptor(provider, name)?.value === 'function')
        Object.defineProperty(provider, name, {
          value: () => {
            throw new Error('Late magic-link provider replacement');
          },
        });
  try {
    const issued = await magic.issue(f.owner, 'login');
    await assert.rejects(
      magic.consume(issued.value, { method: 'GET' as 'POST', purpose: 'login' }),
      { code: 'EK_CONFIG_INVALID' },
    );
    assert.equal(
      (await magic.consume(issued.value, { method: 'POST', purpose: 'login' })).subject.subject,
      f.owner.subject,
    );
    await assert.rejects(magic.consume(issued.value, { method: 'POST', purpose: 'login' }), {
      code: 'EK_MAGICLINK_REPLAY',
    });
    const revoked = await magic.issue(f.owner, 'account-recover');
    await magic.revoke(revoked.issueId);
    await assert.rejects(
      magic.consume(revoked.value, { method: 'POST', purpose: 'account-recover' }),
    );
    for (const name of ['require', 'digest', 'verify', 'read', 'atomicBatch'])
      assert.ok(calls.has(name), 'The original ' + name + ' provider must run');
    assert.equal(effects, 0);
  } finally {
    await app.stop();
  }
});

test('Magic-link provider and callable proxies and proxy prototypes fail without executing traps', () => {
  const f = fixture();
  let effects = 0;
  const traps = {
    get() {
      effects++;
      throw new Error('Executable magic-link provider get');
    },
    getOwnPropertyDescriptor() {
      effects++;
      throw new Error('Executable magic-link descriptor');
    },
    getPrototypeOf() {
      effects++;
      throw new Error('Executable magic-link prototype');
    },
    apply() {
      effects++;
      throw new Error('Executable magic-link call');
    },
  };
  for (const field of ['hmac', 'authority'] as const) {
    const provider = f.settings[field];
    assert.throws(() => magicLinksPlugin({ ...f.settings, [field]: new Proxy(provider, traps) }), {
      code: 'EK_CONFIG_INVALID',
    });
    for (const name of Object.keys(provider)) {
      const value = Object.getOwnPropertyDescriptor(provider, name)?.value as unknown;
      if (typeof value !== 'function') continue;
      assert.throws(
        () =>
          magicLinksPlugin({
            ...f.settings,
            [field]: { ...provider, [name]: new Proxy(value, traps) },
          }),
        { code: 'EK_CONFIG_INVALID' },
      );
    }
  }
  assert.throws(
    () =>
      magicLinksPlugin({
        ...f.settings,
        stateStore: {
          ...f.settings.stateStore,
          store: new Proxy(f.settings.stateStore.store, traps),
        },
      }),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.throws(
    () =>
      magicLinksPlugin({
        ...f.settings,
        authority: Object.create(new Proxy({}, traps)) as typeof f.settings.authority,
      }),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.equal(effects, 0);
});
