// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { apiKeyPlugin } from '../../dist/index.js';
import { application, fixtureSettings, grant } from './fixture.js';

test('Executable authority bind metadata cannot replace the original API key authorization decision', async () => {
  const f = fixtureSettings();
  f.state.authenticated = false;
  let redirected = 0;
  Object.defineProperty(f.settings.authority.require, 'bind', {
    value: () => async () => {
      redirected++;
      return f.owner;
    },
  });
  const { app, keys } = await application(f.settings);
  try {
    await assert.rejects(keys.issue(f.owner, grant()), { code: 'EK_APIKEY_INVALID' });
    assert.equal(redirected, 0);
    assert.deepEqual(f.state.calls, ['apikey.issue']);
    assert.equal(f.rows.size, 0);
  } finally {
    await app.stop();
  }
});

test('API key provider capture ignores callable metadata and retains each original receiver', async () => {
  const f = fixtureSettings(),
    providers = [f.store, f.settings.hmac, f.settings.authority];
  let effects = 0,
    calls = 0;
  for (const provider of providers)
    for (const name of Object.keys(provider)) {
      const original = Object.getOwnPropertyDescriptor(provider, name)?.value as unknown;
      if (typeof original !== 'function') continue;
      const captured = function (this: unknown, ...args: unknown[]) {
        assert.equal(this, provider);
        calls++;
        return Reflect.apply(original, this, args);
      };
      for (const field of ['bind', 'name', 'length'])
        Object.defineProperty(captured, field, {
          get() {
            effects++;
            throw new Error('Executable API key provider metadata');
          },
        });
      Object.defineProperty(provider, name, {
        configurable: true,
        writable: true,
        value: captured,
      });
    }
  const { app, keys } = await application(f.settings);
  // All configured functions were already captured during plugin construction.
  for (const provider of providers)
    for (const name of Object.keys(provider)) {
      if (typeof Object.getOwnPropertyDescriptor(provider, name)?.value === 'function')
        Object.defineProperty(provider, name, {
          value: () => {
            throw new Error('Late provider replacement');
          },
        });
    }
  try {
    const issued = await keys.issue(f.owner, grant());
    assert.equal((await keys.verify(issued.value, {})).keyId, issued.id);
    assert.equal((await keys.list(f.owner)).length, 1);
    const rotated = await keys.rotate(issued.id, f.owner);
    await assert.rejects(keys.verify(issued.value, {}), { code: 'EK_APIKEY_INVALID' });
    await keys.revoke(rotated.id, f.owner);
    assert.deepEqual(await keys.list(f.owner), []);
    assert.ok(calls > 10);
    assert.equal(effects, 0);
  } finally {
    await app.stop();
  }
});

test('API key provider proxies, callable proxies and unbounded prototype chains fail before executable metadata', () => {
  const f = fixtureSettings();
  let effects = 0;
  const traps = {
    get() {
      effects++;
      throw new Error('Executable provider get');
    },
    getOwnPropertyDescriptor() {
      effects++;
      throw new Error('Executable provider descriptor');
    },
    getPrototypeOf() {
      effects++;
      throw new Error('Executable provider prototype');
    },
    apply() {
      effects++;
      throw new Error('Executable provider call');
    },
  };
  for (const field of ['hmac', 'authority'] as const) {
    assert.throws(
      () => apiKeyPlugin({ ...f.settings, [field]: new Proxy(f.settings[field], traps) }),
      { code: 'EK_CONFIG_INVALID' },
    );
  }
  assert.throws(
    () =>
      apiKeyPlugin({
        ...f.settings,
        store: { ...f.settings.store, store: new Proxy(f.store, traps) },
      }),
    { code: 'EK_CONFIG_INVALID' },
  );
  for (const field of ['digest', 'verify'] as const)
    assert.throws(
      () =>
        apiKeyPlugin({
          ...f.settings,
          hmac: { ...f.settings.hmac, [field]: new Proxy(f.settings.hmac[field], traps) },
        }),
      { code: 'EK_CONFIG_INVALID' },
    );
  assert.throws(
    () =>
      apiKeyPlugin({
        ...f.settings,
        authority: { require: new Proxy(f.settings.authority.require, traps) },
      }),
    { code: 'EK_CONFIG_INVALID' },
  );
  let deep: object = f.settings.authority;
  for (let depth = 0; depth < 33; depth++) deep = Object.create(deep) as object;
  assert.throws(
    () => apiKeyPlugin({ ...f.settings, authority: deep as typeof f.settings.authority }),
    { code: 'EK_CONFIG_INVALID' },
  );
  const inherited = Object.create(new Proxy({}, traps)) as typeof f.settings.authority;
  assert.throws(() => apiKeyPlugin({ ...f.settings, authority: inherited }), {
    code: 'EK_CONFIG_INVALID',
  });
  assert.equal(effects, 0);
});
