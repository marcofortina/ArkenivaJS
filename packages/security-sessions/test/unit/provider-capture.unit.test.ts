// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sessionsPlugin } from '../../dist/index.js';
import { application, fixtureSettings } from './fixture.js';

test('Executable authority bind metadata cannot authorize global session revocation without primary authentication', async () => {
  const f = fixtureSettings();
  f.state.primary = false;
  let redirected = 0;
  Object.defineProperty(f.settings.authority.require, 'bind', {
    value: () => async () => {
      redirected++;
      return f.owner();
    },
  });
  const { app, sessions } = await application(f.settings);
  try {
    await assert.rejects(sessions.revokeAll(f.owner()), { code: 'EK_SESSION_INVALID' });
    assert.equal(redirected, 0);
    assert.equal(f.epochs.size, 0);
    assert.equal(f.rows.size, 0);
  } finally {
    await app.stop();
  }
});

test('Session storage, HMAC and identity callbacks retain original receivers without executable function metadata', async () => {
  const f = fixtureSettings(),
    providers = [f.store, f.settings.hmac, f.settings.authority],
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
            throw new Error('Executable session provider metadata');
          },
        });
      Object.defineProperty(provider, name, {
        configurable: true,
        writable: true,
        value: captured,
      });
    }
  const { app, sessions } = await application(f.settings);
  for (const provider of providers)
    for (const name of Object.keys(provider))
      if (typeof Object.getOwnPropertyDescriptor(provider, name)?.value === 'function')
        Object.defineProperty(provider, name, {
          value: () => {
            throw new Error('Late session provider replacement');
          },
        });
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
    const renewed = await sessions.renew(issued.value);
    await assert.rejects(sessions.validate(issued.value));
    assert.equal((await sessions.validate(renewed.value)).sessionId, renewed.sessionId);
    assert.equal(await sessions.revokeAll(f.owner()), 1);
    await assert.rejects(sessions.validate(renewed.value));
    const current = await sessions.create(f.identity(), f.settings.defaultPolicy);
    await sessions.revoke(current.sessionId);
    await assert.rejects(sessions.validate(current.value));
    for (const name of [
      'resolveIdentity',
      'require',
      'digest',
      'verify',
      'read',
      'atomicBatch',
      'listByOwner',
      'bumpOwnerEpoch',
      'currentOwnerEpoch',
    ])
      assert.ok(calls.has(name), 'The original ' + name + ' provider must run');
    assert.equal(effects, 0);
  } finally {
    await app.stop();
  }
});

test('Session provider proxies, callable proxies and unbounded authorization prototypes fail without traps', () => {
  const f = fixtureSettings();
  let effects = 0;
  const traps = {
    get() {
      effects++;
      throw new Error('Executable session provider get');
    },
    getOwnPropertyDescriptor() {
      effects++;
      throw new Error('Executable session descriptor');
    },
    getPrototypeOf() {
      effects++;
      throw new Error('Executable session prototype');
    },
    apply() {
      effects++;
      throw new Error('Executable session provider call');
    },
  };
  for (const field of ['hmac', 'authority'] as const) {
    const provider = f.settings[field];
    assert.throws(() => sessionsPlugin({ ...f.settings, [field]: new Proxy(provider, traps) }), {
      code: 'EK_CONFIG_INVALID',
    });
    for (const name of Object.keys(provider)) {
      const value = Object.getOwnPropertyDescriptor(provider, name)?.value as unknown;
      if (typeof value !== 'function') continue;
      assert.throws(
        () =>
          sessionsPlugin({
            ...f.settings,
            [field]: { ...provider, [name]: new Proxy(value, traps) },
          }),
        { code: 'EK_CONFIG_INVALID' },
      );
    }
  }
  assert.throws(
    () =>
      sessionsPlugin({
        ...f.settings,
        store: { ...f.settings.store, store: new Proxy(f.store, traps) },
      }),
    { code: 'EK_CONFIG_INVALID' },
  );
  let deep: object = f.settings.authority;
  for (let depth = 0; depth < 33; depth++) deep = Object.create(deep) as object;
  assert.throws(
    () => sessionsPlugin({ ...f.settings, authority: deep as typeof f.settings.authority }),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.throws(
    () =>
      sessionsPlugin({
        ...f.settings,
        authority: Object.create(new Proxy({}, traps)) as typeof f.settings.authority,
      }),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.equal(effects, 0);
});
