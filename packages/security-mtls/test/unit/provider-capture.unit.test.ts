// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import type { Application } from '@arkenivajs/core';
import { mtlsPlugin, MTLS_CAPABILITY } from '../../dist/index.js';
import type { MtlsService, TlsTrustVerificationPolicy } from '../../dist/index.js';
import { fixture } from '../fixture.js';

type Fixture = Awaited<ReturnType<typeof fixture>>;
const peerPolicy = (f: Fixture): TlsTrustVerificationPolicy => ({
  trustRootsRef: 'fixture',
  allowedIdentities: f.profiles.client!.allowedIdentities,
  hostname: 'localhost',
  revocation: 'crl-required',
});
const serverDer = (f: Fixture) => new X509Certificate(f.materials.get('server')!.cert).raw;

test('Custom provider bind metadata cannot replace native mTLS credential loading or trust verification', async (context) => {
  for (const kind of ['credentials', 'trust'] as const)
    await context.test(kind, async () => {
      const f = await fixture();
      let app: Application | undefined,
        redirected = 0;
      const callback =
        kind === 'credentials'
          ? f.credentialProvider.load
          : f.trustProvider.verifyChainAndRevocation;
      Object.defineProperty(callback, 'bind', {
        value: () => async () => {
          redirected++;
          throw new Error('An unapproved mTLS provider substitute must not run');
        },
      });
      try {
        app = await createApplication({
          service: { name: 'mtls-provider-capture', version: '1.0.0', environment: 'test' },
          plugins: [mtlsPlugin(f.settings)],
        });
        await app.start();
        const mtls = app.resolve<MtlsService>(MTLS_CAPABILITY),
          client = await mtls.createClientOptions(f.profiles.client!, 'localhost');
        assert.equal(mtls.toNodeClientOptions(client).rejectUnauthorized, true);
        assert.deepEqual((await mtls.verifyPeer(serverDer(f), peerPolicy(f))).uriSans, [
          'spiffe://fixture/server',
        ]);
        assert.ok(f.loads() > 0);
        assert.ok(f.verifications() > 0);
        f.unavailable(true);
        await assert.rejects(mtls.verifyPeer(serverDer(f), peerPolicy(f)), {
          code: 'EK_MTLS_INVALID_PEER',
        });
        await assert.rejects(mtls.reloadCertificates(), { code: 'EK_MTLS_CONFIGURATION' });
        assert.equal(redirected, 0);
      } finally {
        try {
          await app?.stop();
        } finally {
          await f.close();
        }
      }
    });
});

test('Native mTLS material and real CRL checks retain original provider receivers after metadata traps and late replacement', async () => {
  const f = await fixture(),
    providers = [f.credentialProvider, f.trustProvider],
    calls = new Set<string>();
  let app: Application | undefined,
    effects = 0;
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
              throw new Error('Executable mutual TLS provider metadata');
            },
          });
        Object.defineProperty(provider, name, {
          configurable: true,
          writable: true,
          value: captured,
        });
      }
    const plugin = mtlsPlugin(f.settings);
    assert.equal(calls.size, 0);
    for (const provider of providers)
      for (const name of Object.keys(provider))
        if (typeof Object.getOwnPropertyDescriptor(provider, name)?.value === 'function')
          Object.defineProperty(provider, name, {
            value: () => {
              throw new Error('Late mTLS provider replacement');
            },
          });
    app = await createApplication({
      service: { name: 'mtls-original-provider', version: '1.0.0', environment: 'test' },
      plugins: [plugin],
    });
    await app.start();
    const mtls = app.resolve<MtlsService>(MTLS_CAPABILITY),
      client = await mtls.createClientOptions(f.profiles.client!, 'localhost'),
      server = await mtls.createServerOptions(f.profiles.server!);
    assert.equal(mtls.toNodeClientOptions(client).rejectUnauthorized, true);
    assert.equal(mtls.toNodeServerOptions(server).requestCert, true);
    assert.deepEqual((await mtls.verifyPeer(serverDer(f), peerPolicy(f))).uriSans, [
      'spiffe://fixture/server',
    ]);
    await mtls.reloadCertificates();
    assert.deepEqual((await mtls.verifyPeer(serverDer(f), peerPolicy(f))).uriSans, [
      'spiffe://fixture/server',
    ]);
    assert.equal(calls.has('load'), true);
    assert.equal(calls.has('verifyChainAndRevocation'), true);
    assert.equal(effects, 0);
  } finally {
    try {
      await app?.stop();
    } finally {
      await f.close();
    }
  }
});

test('mTLS provider/function/prototype proxies and hidden provider classification fail without executing traps', async () => {
  const f = await fixture();
  let effects = 0;
  const traps = {
    get() {
      effects++;
      throw new Error('Executable mTLS provider get');
    },
    getOwnPropertyDescriptor() {
      effects++;
      throw new Error('Executable mTLS descriptor');
    },
    getPrototypeOf() {
      effects++;
      throw new Error('Executable mTLS prototype');
    },
    apply() {
      effects++;
      throw new Error('Executable mTLS provider call');
    },
  };
  try {
    for (const field of ['credentialProvider', 'trustProvider'] as const) {
      const provider = f.settings[field];
      assert.throws(() => mtlsPlugin({ ...f.settings, [field]: new Proxy(provider, traps) }), {
        code: 'EK_MTLS_CONFIGURATION',
      });
      for (const name of Object.keys(provider)) {
        const value = Object.getOwnPropertyDescriptor(provider, name)?.value as unknown;
        if (typeof value !== 'function') continue;
        assert.throws(
          () =>
            mtlsPlugin({
              ...f.settings,
              [field]: { ...provider, [name]: new Proxy(value, traps) },
            }),
          { code: 'EK_MTLS_CONFIGURATION' },
        );
      }
      assert.throws(
        () =>
          mtlsPlugin({
            ...f.settings,
            [field]: Object.create(new Proxy({}, traps)) as typeof provider,
          }),
        { code: 'EK_MTLS_CONFIGURATION' },
      );
      let deep: object = { usage: 'test-only' };
      for (let depth = 0; depth < 33; depth++) deep = Object.create(deep) as object;
      const hidden = Object.create(deep) as object;
      for (const name of Object.keys(provider)) {
        const value = Object.getOwnPropertyDescriptor(provider, name)?.value as unknown;
        if (typeof value === 'function') Object.defineProperty(hidden, name, { value });
      }
      assert.throws(() => mtlsPlugin({ ...f.settings, [field]: hidden }), {
        code: 'EK_MTLS_CONFIGURATION',
      });
    }
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});
