// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError, COMPONENTS } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { CRYPTO_CAPABILITY } from '@arkenivajs/security-crypto';
import { ciePlugin, CIE_CAPABILITY } from '../../dist/index.js';
import { SPID_CAPABILITY } from '@arkenivajs/identity-spid';
import { createItalianFederationPlugin } from '@arkenivajs/identity-spid/support';
import type { ItalianIdentitySystem } from '../../dist/index.js';
import { transactionFixture } from '../../../identity-spid/dist-test/fixtures/transactions.js';
import { runOidcWorker } from '../../../identity-spid/dist-test/fixtures/oidc-worker-process.js';

test('CIE production and development reject captured test-only providers before requiring or constructing authentication services', async () => {
  const f = await transactionFixture();
  try {
    for (const environment of ['production', 'development'] as const)
      for (const target of ['store', 'secrets', 'authority', 'mapper'] as const) {
        let providerWork = 0,
          requirements = 0;
        const unused = async (): Promise<never> => {
          providerWork++;
          throw new Error('The environment guard must precede provider work');
        };
        const store = { ...f.settings.stateStore.store },
          secrets = { get: unused },
          authority = { require: unused },
          mapper = { map: unused },
          labelled =
            target === 'store'
              ? store
              : target === 'secrets'
                ? secrets
                : target === 'authority'
                  ? authority
                  : mapper;
        Reflect.set(labelled, 'usage', 'test-only');
        const plugin = ciePlugin({
          ...f.settings,
          profiles: [{ ...f.profile, system: 'cie', allowedAssurance: ['cie-l2'] }],
          stateStore: { store, securityLevel: 'production', operationTimeoutMs: 1000 },
          secretProvider: secrets,
          authority,
          identityMappers: { [f.profile.tenantMappingId]: mapper },
        });
        Reflect.set(labelled, 'usage', 'production');
        const dependency = (id: string, key: symbol): Plugin => ({
          id,
          version: '1.0.0',
          capabilities: new Set(),
          init(context) {
            context.provide(key, Object.freeze({}));
          },
          close() {},
        });
        const guarded: Plugin = {
          ...plugin,
          async init(context) {
            const wrapped: typeof context = Object.create(context);
            Object.defineProperty(wrapped, 'require', {
              value: <T>(key: symbol): T => {
                requirements++;
                return context.require<T>(key);
              },
            });
            await plugin.init?.(wrapped);
          },
        };
        const app = await createApplication({
          service: { name: 'cie-environment-guard', version: '1.0.0', environment },
          plugins: [
            dependency('security', COMPONENTS.auth),
            dependency('crypto', CRYPTO_CAPABILITY),
            guarded,
          ],
        });
        try {
          await assert.rejects(
            app.start(),
            (error: unknown) =>
              error instanceof KitError &&
              error.code === 'EK_PLUGIN_FAILED' &&
              error.cause instanceof KitError &&
              error.cause.code === 'EK_EID_PROFILE',
          );
          assert.equal(
            requirements,
            0,
            'No inert service may be used as an authentication stand-in',
          );
          assert.equal(providerWork, 0);
        } finally {
          await app.stop();
        }
      }
  } finally {
    await f.close();
  }
});

test('CIE has an independent capability and rejects foreign systems, assurance and incomplete configuration before provider I/O', async () => {
  const f = await transactionFixture();
  try {
    let providerWork = 0;
    const unused = async (): Promise<never> => {
      providerWork++;
      throw new Error('Configuration capture must not call providers');
    };
    const profile = { ...f.profile, system: 'cie' as const, allowedAssurance: ['cie-l2' as const] },
      settings = {
        ...f.settings,
        profiles: [profile],
        secretProvider: { get: unused },
        authority: { require: unused },
        identityMappers: { [profile.tenantMappingId]: { map: unused } },
        stateStore: {
          ...f.settings.stateStore,
          store: {
            read: unused,
            claimOnce: unused,
            compareAndSet: unused,
            atomicBatch: unused,
            listByOwner: unused,
            bumpOwnerEpoch: unused,
            currentOwnerEpoch: unused,
          },
        },
      },
      plugin = ciePlugin(settings);
    assert.equal(plugin.id, 'cie');
    assert.deepEqual([...plugin.capabilities], ['cie']);
    assert.notEqual(CIE_CAPABILITY, SPID_CAPABILITY);
    assert.throws(
      () =>
        createItalianFederationPlugin('unknown' as ItalianIdentitySystem, CIE_CAPABILITY, settings),
      { code: 'EK_EID_PROFILE' },
    );
    assert.throws(
      () => createItalianFederationPlugin('cie', 'invalid' as unknown as symbol, settings),
      { code: 'EK_EID_PROFILE' },
    );
    for (const input of [
      null,
      { ...settings, unexpected: true },
      f.settings,
      { ...settings, profiles: [{ ...profile, allowedAssurance: ['spid-l2'] }] },
      { ...settings, profiles: [profile, { ...f.profile, profileId: 'foreign-profile' }] },
      { ...settings, identityMappers: {} },
      { ...settings, secretProvider: {} },
    ])
      assert.throws(
        () => ciePlugin(input as typeof settings),
        (error: unknown) => error instanceof KitError,
      );
    let executed = 0;
    assert.throws(
      () =>
        ciePlugin(
          new Proxy(settings, {
            get() {
              executed++;
              throw new Error('Proxy execution');
            },
          }),
        ),
      { code: 'EK_EID_PROFILE' },
    );
    assert.throws(
      () =>
        ciePlugin({
          ...settings,
          get profiles() {
            executed++;
            return [profile];
          },
        }),
      { code: 'EK_EID_PROFILE' },
    );
    assert.equal(executed, 0);
    await assert.rejects(
      createApplication({
        service: { name: 'cie-missing-owners', version: '1.0.0', environment: 'test' },
        plugins: [plugin],
      }),
      { code: 'EK_PLUGIN_DEPENDENCY' },
    );
    await assert.rejects(
      createApplication({
        service: { name: 'cie-duplicate-owner', version: '1.0.0', environment: 'test' },
        plugins: [plugin, ciePlugin(settings)],
      }),
      { code: 'EK_PLUGIN_DUPLICATE' },
    );
    assert.equal(providerWork, 0);
  } finally {
    await f.close();
  }
});

for (const mode of ['standard', 'detailed'] as const)
  test(
    `Actual public CIE HTTPS login, encrypted ID Token, canonical tenant mapping, revocation, replay and ${mode} SDK privacy`,
    { timeout: 30000 },
    () => runOidcWorker('public', mode, new URL('../fixtures/public-worker.js', import.meta.url)),
  );
