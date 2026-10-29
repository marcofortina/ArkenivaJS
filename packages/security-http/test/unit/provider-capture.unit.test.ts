// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { securityHttpPlugin } from '../../dist/index.js';
import { fixtureSettings, startFixture } from './fixture.js';

test('Custom authority bind metadata cannot issue CSRF credentials while the original authority is unavailable', async () => {
  const input = fixtureSettings();
  input.state.authorityAvailable = false;
  let redirected = 0;
  Object.defineProperty(input.settings.authority.require, 'bind', {
    value: () => async () => {
      redirected++;
      return input.alice.subject;
    },
  });
  const f = await startFixture(input);
  try {
    await assert.rejects(f.service.csrfToken({ sessionId: f.alice.sessionId }));
    assert.equal(redirected, 0);
    assert.equal(f.state.authorizations, 1);
    assert.equal(f.rows.size, 0);
  } finally {
    await f.close();
  }
});

test('Native browser CSRF uses original storage, HMAC, cookie-session and authority receivers without callable metadata', async () => {
  const input = fixtureSettings(),
    providers = [
      input.settings.csrfStore.store,
      input.settings.csrfHmac,
      input.settings.cookieSession!,
      input.settings.authority,
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
            throw new Error('Executable HTTP security provider metadata');
          },
        });
      Object.defineProperty(provider, name, {
        configurable: true,
        writable: true,
        value: captured,
      });
    }
  const f = await startFixture(input);
  for (const provider of providers)
    for (const name of Object.keys(provider))
      if (typeof Object.getOwnPropertyDescriptor(provider, name)?.value === 'function')
        Object.defineProperty(provider, name, {
          value: () => {
            throw new Error('Late HTTP security provider replacement');
          },
        });
  try {
    const token = await f.as(f.alice.cookie, () =>
        f.service.csrfToken({ sessionId: f.alice.sessionId }),
      ),
      cookie =
        '__Host-session=' + f.alice.cookie + '; __Host-arkeniva-csrf=' + token.split('.')[1]!;
    await f.as(f.alice.cookie, () =>
      f.service.verifyCsrf(
        { sessionId: f.alice.sessionId, origin: 'https://app.fixture.invalid' },
        token,
      ),
    );
    const accepted = await fetch(f.origin + '/protected', {
      method: 'POST',
      headers: {
        cookie,
        origin: 'https://app.fixture.invalid',
        'x-csrf-token': token,
      },
    });
    assert.equal(accepted.status, 200);
    await accepted.arrayBuffer();
    const denied = await fetch(f.origin + '/protected', {
      method: 'POST',
      headers: {
        cookie,
        origin: 'https://foreign.fixture.invalid',
        'x-csrf-token': token,
      },
    });
    assert.equal(denied.status, 403);
    await denied.arrayBuffer();
    assert.equal(f.state.effects, 1);
    for (const name of ['read', 'compareAndSet', 'digest', 'resolve', 'require'])
      assert.ok(calls.has(name), 'The original ' + name + ' provider must run');
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});

test('HTTP security provider and callable proxies and excessive prototype traversal fail without executing traps', () => {
  const f = fixtureSettings();
  let effects = 0;
  const traps = {
    get() {
      effects++;
      throw new Error('Executable HTTP security get');
    },
    getOwnPropertyDescriptor() {
      effects++;
      throw new Error('Executable HTTP security descriptor');
    },
    getPrototypeOf() {
      effects++;
      throw new Error('Executable HTTP security prototype');
    },
    apply() {
      effects++;
      throw new Error('Executable HTTP security call');
    },
  };
  for (const field of ['csrfHmac', 'authority', 'cookieSession'] as const) {
    const provider = f.settings[field]!;
    assert.throws(
      () => securityHttpPlugin({ ...f.settings, [field]: new Proxy(provider, traps) }),
      { code: 'EK_HTTP_SECURITY_POLICY' },
    );
    for (const name of Object.keys(provider)) {
      const value = Object.getOwnPropertyDescriptor(provider, name)?.value as unknown;
      if (typeof value !== 'function') continue;
      assert.throws(
        () =>
          securityHttpPlugin({
            ...f.settings,
            [field]: { ...provider, [name]: new Proxy(value, traps) },
          }),
        { code: 'EK_HTTP_SECURITY_POLICY' },
      );
    }
  }
  assert.throws(
    () =>
      securityHttpPlugin({
        ...f.settings,
        csrfStore: { ...f.settings.csrfStore, store: new Proxy(f.settings.csrfStore.store, traps) },
      }),
    { code: 'EK_HTTP_SECURITY_POLICY' },
  );
  let deep: object = f.settings.authority;
  for (let depth = 0; depth < 65; depth++) deep = Object.create(deep) as object;
  assert.throws(
    () => securityHttpPlugin({ ...f.settings, authority: deep as typeof f.settings.authority }),
    { code: 'EK_HTTP_SECURITY_POLICY' },
  );
  assert.throws(
    () =>
      securityHttpPlugin({
        ...f.settings,
        authority: Object.create(new Proxy({}, traps)) as typeof f.settings.authority,
      }),
    { code: 'EK_HTTP_SECURITY_POLICY' },
  );
  assert.equal(effects, 0);
});
