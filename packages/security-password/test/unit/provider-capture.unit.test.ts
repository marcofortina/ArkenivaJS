// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { passwordPlugin } from '../../dist/index.js';
import { application, fixtureSettings } from './fixture.js';

test('Custom authority bind metadata cannot authorize password reset without primary authentication', async () => {
  const f = fixtureSettings();
  f.state.primary = false;
  let redirected = 0;
  Object.defineProperty(f.settings.authority.require, 'bind', {
    value: () => async () => {
      redirected++;
      return f.owner();
    },
  });
  const { app, passwords } = await application(f.settings);
  try {
    await assert.rejects(passwords.createReset(f.owner(), f.owner()), {
      code: 'EK_PASSWORD_RESET',
    });
    assert.equal(redirected, 0);
    // Rejected attempts still spend the prescribed shared rate budget, without issuing reset state.
    assert.deepEqual(
      [...f.rows.values()].map((row) => row.kind),
      ['reset'],
    );
    assert.equal(f.credentials.size, 0);
  } finally {
    await app.stop();
    f.close();
  }
});

test(
  'Password storage, secret, authority, breach and reset callbacks retain original receivers without callable metadata',
  { timeout: 15000 },
  async () => {
    const f = fixtureSettings(),
      providers = [
        f.store,
        f.settings.secretProvider,
        f.settings.authority,
        f.settings.resetCommitter,
        f.settings.breaches!,
      ],
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
              throw new Error('Executable password provider metadata');
            },
          });
        Object.defineProperty(provider, name, {
          configurable: true,
          writable: true,
          value: captured,
        });
      }
    const { app, passwords } = await application({
      ...f.settings,
      policy: { ...f.settings.policy, blockBreachedPasswords: true },
    });
    for (const provider of providers)
      for (const name of Object.keys(provider))
        if (typeof Object.getOwnPropertyDescriptor(provider, name)?.value === 'function')
          Object.defineProperty(provider, name, {
            value: () => {
              throw new Error('Late password provider replacement');
            },
          });
    try {
      const reset = await passwords.createReset(f.owner(), f.owner()),
        plain = randomBytes(24).toString('base64url');
      await passwords.consumeReset(reset.value, plain);
      const stored = f.credentials.get(f.binding(f.owner()))!;
      assert.equal((await passwords.verify(plain, stored)).valid, true);
      await assert.rejects(
        passwords.consumeReset(reset.value, randomBytes(24).toString('base64url')),
      );
      assert.equal(f.epochs.get(f.binding(f.owner())), 1);
      for (const name of [
        'get',
        'require',
        'commitReset',
        'lookup',
        'read',
        'compareAndSet',
        'atomicBatch',
      ])
        assert.ok(calls.has(name), 'The original ' + name + ' provider must run');
      assert.equal(effects, 0);
    } finally {
      await app.stop();
      f.close();
    }
  },
);

test('Password provider and callable proxies and deeply inherited authorization fail without executing traps', () => {
  const f = fixtureSettings();
  let effects = 0;
  const traps = {
    get() {
      effects++;
      throw new Error('Executable password provider get');
    },
    getOwnPropertyDescriptor() {
      effects++;
      throw new Error('Executable password descriptor');
    },
    getPrototypeOf() {
      effects++;
      throw new Error('Executable password prototype');
    },
    apply() {
      effects++;
      throw new Error('Executable password provider call');
    },
  };
  try {
    for (const field of ['secretProvider', 'authority', 'resetCommitter', 'breaches'] as const) {
      const provider = f.settings[field]!;
      assert.throws(() => passwordPlugin({ ...f.settings, [field]: new Proxy(provider, traps) }), {
        code: 'EK_CONFIG_INVALID',
      });
      for (const name of Object.keys(provider)) {
        const value = Object.getOwnPropertyDescriptor(provider, name)?.value as unknown;
        if (typeof value !== 'function') continue;
        assert.throws(
          () =>
            passwordPlugin({
              ...f.settings,
              [field]: { ...provider, [name]: new Proxy(value, traps) },
            }),
          { code: 'EK_CONFIG_INVALID' },
        );
      }
    }
    assert.throws(
      () =>
        passwordPlugin({
          ...f.settings,
          resetStore: { ...f.settings.resetStore, store: new Proxy(f.store, traps) },
        }),
      { code: 'EK_CONFIG_INVALID' },
    );
    let deep: object = f.settings.authority;
    for (let depth = 0; depth < 33; depth++) deep = Object.create(deep) as object;
    assert.throws(
      () => passwordPlugin({ ...f.settings, authority: deep as typeof f.settings.authority }),
      { code: 'EK_CONFIG_INVALID' },
    );
    assert.throws(
      () =>
        passwordPlugin({
          ...f.settings,
          authority: Object.create(new Proxy({}, traps)) as typeof f.settings.authority,
        }),
      { code: 'EK_CONFIG_INVALID' },
    );
    assert.equal(effects, 0);
  } finally {
    f.close();
  }
});
