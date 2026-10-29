// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApplication } from '@arkenivajs/core';
import type { Application } from '@arkenivajs/core';
import { x509Plugin, X509_CAPABILITY } from '../../dist/index.js';
import type { X509Service } from '../../dist/index.js';
import { fixture } from '../fixture.js';

test('Custom trust callback bind metadata cannot replace actual X509 path and revocation verification', async () => {
  const f = await fixture();
  let app: Application | undefined,
    redirected = 0;
  Object.defineProperty(f.provider.verifyChainAndRevocation, 'bind', {
    value: () => async () => {
      redirected++;
      throw new Error('An unapproved trust substitute must not run');
    },
  });
  try {
    app = await createApplication({
      service: { name: 'x509-provider-capture', version: '1.0.0', environment: 'test' },
      plugins: [x509Plugin(f.settings)],
    });
    await app.start();
    const x509 = app.resolve<X509Service>(X509_CAPABILITY),
      policy = { trustRoots: f.roots, expectedHostname: 'localhost', requireRevocationCheck: true };
    assert.equal((await x509.inspectChain(f.chain, policy)).status, 'trusted');
    assert.ok(f.calls() > 0);
    f.unavailable(true);
    assert.equal((await x509.inspectChain(f.chain, policy)).status, 'indeterminate');
    assert.equal(redirected, 0);
  } finally {
    try {
      await app?.stop();
    } finally {
      await f.close();
    }
  }
});

test(
  'Actual native X509 verification retains its original receiver after callable metadata and late replacement, including real CRL revocation',
  { timeout: 15000 },
  async () => {
    const f = await fixture(),
      original = f.provider.verifyChainAndRevocation;
    let app: Application | undefined,
      effects = 0,
      calls = 0;
    const provider = {
      usage: 'test-only' as const,
      async verifyChainAndRevocation(...args: Parameters<typeof original>) {
        assert.equal(this, provider);
        calls++;
        return Reflect.apply(original, f.provider, args);
      },
    };
    for (const field of ['bind', 'name', 'length'])
      Object.defineProperty(provider.verifyChainAndRevocation, field, {
        get() {
          effects++;
          throw new Error('Executable X509 trust metadata');
        },
      });
    try {
      const plugin = x509Plugin({ ...f.settings, trustProvider: provider });
      assert.equal(calls, 0);
      provider.verifyChainAndRevocation = async () => {
        throw new Error('Late X509 trust replacement');
      };
      app = await createApplication({
        service: { name: 'x509-original-provider', version: '1.0.0', environment: 'test' },
        plugins: [plugin],
      });
      await app.start();
      const x509 = app.resolve<X509Service>(X509_CAPABILITY),
        policy = {
          trustRoots: f.roots,
          expectedHostname: 'localhost',
          requireRevocationCheck: true,
        };
      assert.equal((await x509.inspectChain(f.chain, policy)).status, 'trusted');
      await f.revoke();
      assert.equal((await x509.inspectChain(f.chain, policy)).status, 'indeterminate');
      assert.equal(calls, 2);
      assert.equal(effects, 0);
    } finally {
      try {
        await app?.stop();
      } finally {
        await f.close();
      }
    }
  },
);

test('X509 provider, callable and prototype proxies and hidden classification fail before executable metadata', async () => {
  const f = await fixture();
  let effects = 0;
  const traps = {
    get() {
      effects++;
      throw new Error('Executable X509 provider get');
    },
    getOwnPropertyDescriptor() {
      effects++;
      throw new Error('Executable X509 descriptor');
    },
    getPrototypeOf() {
      effects++;
      throw new Error('Executable X509 prototype');
    },
    apply() {
      effects++;
      throw new Error('Executable X509 provider call');
    },
  };
  try {
    for (const trustProvider of [
      new Proxy(f.provider, traps),
      { verifyChainAndRevocation: new Proxy(f.provider.verifyChainAndRevocation, traps) },
      Object.create(new Proxy({}, traps)) as typeof f.provider,
    ])
      assert.throws(() => x509Plugin({ ...f.settings, trustProvider }), {
        code: 'EK_CONFIG_INVALID',
      });
    let deep: object = { usage: 'test-only' };
    for (let depth = 0; depth < 33; depth++) deep = Object.create(deep) as object;
    const hidden = Object.create(deep) as typeof f.provider;
    Object.defineProperty(hidden, 'verifyChainAndRevocation', {
      value: f.provider.verifyChainAndRevocation,
    });
    assert.throws(() => x509Plugin({ ...f.settings, trustProvider: hidden }), {
      code: 'EK_CONFIG_INVALID',
    });
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});
