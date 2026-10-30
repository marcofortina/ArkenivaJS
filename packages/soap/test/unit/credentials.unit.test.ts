// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import { credentials } from '../../dist/credentials.js';
import { capture } from '../../dist/settings.js';
import { Calls } from '../../dist/calls.js';
import type { SoapPluginSettings } from '../../dist/index.js';

const profile = {
  id: 'stock',
  wsdlFile: '/offline/stock.wsdl',
  endpoint: 'https://stock.fixture.invalid/soap',
  protocol: '1.1' as const,
  allowedOperations: ['ReadStock'],
  credentialsRef: 'auth',
  maxResponseBytes: 4096,
};
const settings: SoapPluginSettings = {
  services: [profile],
  policy: { timeoutMs: 1000, maxConcurrent: 1 },
  secretProvider: {
    async get() {
      throw new Error('No provider is configured');
    },
  },
};
const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
test('Versioned secret bundles support explicit Basic, Bearer and native UsernameToken digest modes without modifying provider bytes', async () => {
  for (const bundle of [
    {
      version: 1,
      httpAuth: { scheme: 'basic', username: 'fixture-user', password: 'sample' },
    },
    { version: 1, httpAuth: { scheme: 'bearer', token: 'fixture-token' } },
    {
      version: 1,
      wsSecurity: {
        mode: 'username-token-digest',
        username: 'fixture-user',
        password: 'sample',
      },
    },
  ]) {
    const bytes = Buffer.from(JSON.stringify(bundle)),
      original = Buffer.from(bytes),
      configured = capture({
        ...settings,
        secretProvider: {
          async get(reference) {
            assert.equal(reference, 'auth');
            return { bytes, keyVersion: 'v1' };
          },
        },
      });
    const result = await credentials(configured, profile, { timeoutMs: 1000 });
    assert.equal(result.version, 'v1');
    if (bundle.httpAuth) assert.ok(result.material.authorization);
    else assert.equal(result.wsSecurity?.username, 'fixture-user');
    result.clear();
    assert.deepEqual(bytes, original);
  }
});
test('Malformed, expired, shared, unsupported or unavailable provider data never becomes credentials', async () => {
  const bundles = [
    { version: 2, httpAuth: {} },
    { version: 1 },
    { version: 1, httpAuth: { scheme: 'basic', username: 'x:y', password: 'sample' } },
    { version: 1, httpAuth: { scheme: 'bearer', token: 'line\nbreak' } },
    {
      version: 1,
      wsSecurity: { mode: 'password-text', username: 'fixture-user', password: 'sample' },
    },
    { version: 1, tls: { certificatePem: 'invalid-certificate', privateKeyPem: 'invalid-key' } },
  ];
  for (const bundle of bundles) {
    const configured = capture({
      ...settings,
      secretProvider: {
        async get() {
          return { bytes: Buffer.from(JSON.stringify(bundle)), keyVersion: 'v1' };
        },
      },
    });
    await assert.rejects(credentials(configured, profile, {}), code('EK_BACKEND_UNAVAILABLE'));
  }
  for (const result of [
    { bytes: new Uint8Array(new SharedArrayBuffer(10)), keyVersion: 'v1' },
    { bytes: Buffer.from('{}'), keyVersion: 'v1', expiresAt: '2000-01-01T00:00:00.000Z' },
    { bytes: Buffer.from('{}'), keyVersion: '' },
    { bytes: Buffer.from('{}'), keyVersion: 'v1', extra: true },
  ]) {
    const configured = capture({
      ...settings,
      secretProvider: {
        async get() {
          return result;
        },
      },
    });
    await assert.rejects(credentials(configured, profile, {}), code('EK_BACKEND_UNAVAILABLE'));
  }
  const configured = capture(settings);
  await assert.rejects(credentials(configured, profile, {}), (error: unknown) => {
    assert.ok(error instanceof KitError);
    assert.equal(error.code, 'EK_BACKEND_UNAVAILABLE');
    assert.ok(!error.message.includes('No provider'));
    return true;
  });
});
test('A timed-out provider retains its physical concurrency reservation until it actually settles', async () => {
  const calls = new Calls(capture(settings), new AbortController().signal, () => true);
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  await assert.rejects(
    calls.run({ timeoutMs: 10 }, async () => {
      await gate;
      return true;
    }),
    code('EK_TIMEOUT'),
  );
  assert.equal(calls.pending.size, 1);
  await assert.rejects(
    calls.run(undefined, async () => true),
    code('EK_BACKEND_UNAVAILABLE'),
  );
  release();
  await delay(0);
  assert.equal(calls.pending.size, 0);
  assert.equal(await calls.run(undefined, async () => true), true);
  await calls.close();
  await assert.rejects(
    calls.run(undefined, async () => true),
    code('EK_RESOURCE_CLOSED'),
  );
});

test('SOAP cannot replace a failing secret provider through custom binding metadata', async () => {
  let calls = 0,
    binds = 0;
  const provider = {
    async get(): Promise<never> {
      assert.equal(this, provider);
      calls++;
      throw new Error('private-provider-failure');
    },
  };
  Object.defineProperty(provider.get, 'bind', {
    value: () => {
      binds++;
      return async () => ({
        bytes: Buffer.from(
          JSON.stringify({
            version: 1,
            httpAuth: { scheme: 'basic', username: 'fixture-user', password: 'sample' },
          }),
        ),
        keyVersion: 'v1',
      });
    },
  });
  const configured = capture({ ...settings, secretProvider: provider });
  await assert.rejects(credentials(configured, profile, {}), code('EK_BACKEND_UNAVAILABLE'));
  assert.equal(calls, 1);
  assert.equal(binds, 0);
});

test('SOAP captures inherited provider methods without consulting mutable callable or prototype metadata', async () => {
  let metadataReads = 0,
    originalCalls = 0,
    replacementCalls = 0;
  class Provider {
    async get(reference: string): Promise<never> {
      originalCalls++;
      assert.ok(this instanceof Provider);
      assert.equal(reference, 'auth');
      throw new Error('private-provider-failure');
    }
  }
  const provider = new Provider();
  for (const name of ['bind', 'call', 'apply'])
    Object.defineProperty(provider.get, name, {
      get() {
        metadataReads++;
        throw new Error('Callable metadata must not execute');
      },
    });
  const configured = capture({ ...settings, secretProvider: provider });
  provider.get = async (): Promise<never> => {
    replacementCalls++;
    throw new Error('A replaced provider must not execute');
  };
  await assert.rejects(credentials(configured, profile, {}), code('EK_BACKEND_UNAVAILABLE'));
  assert.equal(originalCalls, 1);
  assert.equal(replacementCalls, 0);
  const trap = () => {
    metadataReads++;
    throw new Error('Provider metadata must not execute');
  };
  const invalid = [
    new Proxy(provider, { getOwnPropertyDescriptor: trap, get: trap }),
    Object.create(new Proxy(provider, { getOwnPropertyDescriptor: trap })),
    {
      get: new Proxy(async () => ({ bytes: Buffer.from('{}'), keyVersion: 'v1' }), { apply: trap }),
    },
    Object.defineProperty({}, 'get', { get: trap }),
  ];
  for (const value of invalid)
    assert.throws(
      () => capture({ ...settings, secretProvider: value as never }),
      code('EK_CONFIG_INVALID'),
    );
  assert.equal(metadataReads, 0);
});
