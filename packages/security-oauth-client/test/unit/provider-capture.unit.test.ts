// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { oauthClientPlugin } from '../../dist/index.js';
import { fixture } from './fixture.js';

test('Custom authority bind metadata cannot start OAuth authorization without primary authentication', async () => {
  const f = await fixture();
  let redirected = 0;
  Object.defineProperty(f.settings.authority.require, 'bind', {
    value: () => async () => {
      redirected++;
      return f.owner();
    },
  });
  try {
    const { oauth } = await f.instance();
    f.state.primary = false;
    await assert.rejects(
      oauth.beginAuthorization({
        subject: f.owner(),
        audience: f.server.audience,
        scopes: ['openid', 'orders.read'],
        returnPath: '/orders',
      }),
      { code: 'EK_OAUTH_POLICY' },
    );
    assert.equal(redirected, 0);
    assert.equal(
      [...f.memory.rows.values()].some((row) => row.kind === 'authorization'),
      false,
    );
    assert.equal(f.server.counts.token, 0);
  } finally {
    await f.close();
  }
});

test(
  'Native signed PKCE exchange, refresh and revocation retain original provider receivers without callable metadata',
  { timeout: 30000 },
  async () => {
    const f = await fixture(),
      providers = [f.settings.stateStore.store, f.settings.secretProvider, f.settings.authority],
      calls = new Set<string>();
    let effects = 0;
    try {
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
                throw new Error('Executable OAuth provider metadata');
              },
            });
          Object.defineProperty(provider, name, {
            configurable: true,
            writable: true,
            value: captured,
          });
        }
      const { oauth } = await f.instance();
      for (const provider of providers)
        for (const name of Object.keys(provider))
          if (typeof Object.getOwnPropertyDescriptor(provider, name)?.value === 'function')
            Object.defineProperty(provider, name, {
              value: () => {
                throw new Error('Late OAuth provider replacement');
              },
            });
      const start = await oauth.beginAuthorization({
          subject: f.owner(),
          audience: f.server.audience,
          scopes: ['openid', 'orders.read'],
          returnPath: '/orders',
        }),
        url = new URL(start.authorizationUrl);
      assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
      const callback = await f.server.authorize(start.authorizationUrl),
        grant = await oauth.exchangeCode(callback);
      assert.equal(grant.tokenType, 'Bearer');
      assert.ok(grant.refreshRef);
      const refreshed = await oauth.refresh(grant.refreshRef);
      assert.ok(refreshed.refreshRef);
      assert.notEqual(refreshed.refreshRef, grant.refreshRef);
      await oauth.revoke(refreshed.refreshRef);
      await assert.rejects(oauth.refresh(refreshed.refreshRef));
      for (const name of ['get', 'require', 'read', 'compareAndSet', 'atomicBatch'])
        assert.ok(calls.has(name), 'The original ' + name + ' provider must run');
      assert.ok(f.server.counts.token > 0);
      assert.ok(f.server.counts.jwks > 0);
      assert.ok(f.server.counts.revoke > 0);
      assert.equal(effects, 0);
    } finally {
      await f.close();
    }
  },
);

test('OAuth provider and callable proxies and excessive authorization prototypes fail without executing traps', async () => {
  const f = await fixture();
  let effects = 0;
  const traps = {
    get() {
      effects++;
      throw new Error('Executable OAuth provider get');
    },
    getOwnPropertyDescriptor() {
      effects++;
      throw new Error('Executable OAuth descriptor');
    },
    getPrototypeOf() {
      effects++;
      throw new Error('Executable OAuth prototype');
    },
    apply() {
      effects++;
      throw new Error('Executable OAuth provider call');
    },
  };
  try {
    for (const field of ['secretProvider', 'authority'] as const) {
      const provider = f.settings[field];
      assert.throws(
        () => oauthClientPlugin({ ...f.settings, [field]: new Proxy(provider, traps) }),
        { code: 'EK_CONFIG_INVALID' },
      );
      for (const name of Object.keys(provider)) {
        const value = Object.getOwnPropertyDescriptor(provider, name)?.value as unknown;
        if (typeof value !== 'function') continue;
        assert.throws(
          () =>
            oauthClientPlugin({
              ...f.settings,
              [field]: { ...provider, [name]: new Proxy(value, traps) },
            }),
          { code: 'EK_CONFIG_INVALID' },
        );
      }
    }
    assert.throws(
      () =>
        oauthClientPlugin({
          ...f.settings,
          stateStore: {
            ...f.settings.stateStore,
            store: new Proxy(f.settings.stateStore.store, traps),
          },
        }),
      { code: 'EK_CONFIG_INVALID' },
    );
    let deep: object = f.settings.authority;
    for (let depth = 0; depth < 33; depth++) deep = Object.create(deep) as object;
    assert.throws(
      () => oauthClientPlugin({ ...f.settings, authority: deep as typeof f.settings.authority }),
      { code: 'EK_CONFIG_INVALID' },
    );
    assert.throws(
      () =>
        oauthClientPlugin({
          ...f.settings,
          authority: Object.create(new Proxy({}, traps)) as typeof f.settings.authority,
        }),
      { code: 'EK_CONFIG_INVALID' },
    );
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});
