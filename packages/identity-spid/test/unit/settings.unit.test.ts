// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { COMPONENTS, createApplication, KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { CRYPTO_CAPABILITY } from '@arkenivajs/security-crypto';
import type { ItalianEidPluginSettings, FederationProfileV1 } from '../../dist/index.js';
import { SPID_CAPABILITY, spidPlugin } from '../../dist/index.js';
import { capture } from '../../dist/settings.js';

const publicKeyPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .publicKey.export({ format: 'pem', type: 'spki' })
  .toString();
function fixture() {
  let calls = 0;
  const unavailable = async (): Promise<never> => {
    calls++;
    throw new Error('The test provider is unavailable');
  };
  const profile: FederationProfileV1 = {
    schemaVersion: '1.0.0',
    profileId: 'service-profile',
    system: 'spid',
    protocol: 'oidc-federation',
    entityId: 'https://service.example.test',
    clientId: 'https://service.example.test',
    redirectUri: 'https://service.example.test/callback',
    signingKeyRef: 'signing-ref',
    expectedIssuers: ['https://idp.example.test'],
    allowedAssurance: ['spid-l2'],
    metadata: {
      trustAnchors: [
        {
          kid: 'public-root',
          issuer: 'https://anchor.example.test',
          publicKeyPem,
          validFrom: new Date(Date.now() - 60000).toISOString(),
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        },
      ],
      approvedMetadataEndpoints: [
        'https://idp.example.test/.well-known/openid-federation',
        'https://anchor.example.test/fetch',
      ],
      maxBytes: 65536,
      refreshIntervalSeconds: 60,
      maxChainDepth: 4,
      revocation: 'mandatory',
      stalePolicy: 'reject',
    },
    subjectClaim: 'sub',
    tenantMappingId: 'approved-accounts',
    identityMappingVersion: '2026-10',
    sessionTtlSeconds: 300,
  };
  const settings: ItalianEidPluginSettings = {
    profiles: [profile],
    identityMappers: { 'approved-accounts': { map: unavailable } },
    stateStore: {
      securityLevel: 'production',
      operationTimeoutMs: 1000,
      store: {
        read: unavailable,
        claimOnce: unavailable,
        compareAndSet: unavailable,
        atomicBatch: unavailable,
        listByOwner: unavailable,
        bumpOwnerEpoch: unavailable,
        currentOwnerEpoch: unavailable,
      },
    },
    secretProvider: { get: unavailable },
    authority: { require: unavailable },
    policy: { maxConcurrent: 8, timeoutMs: 5000, maxInputBytes: 65536, maxOutputBytes: 65536 },
  };
  return { settings, profile, calls: () => calls };
}
test('SPID exports a stable capability and captures immutable profiles without provider I/O', async () => {
  const f = fixture(),
    settings = capture(f.settings);
  assert.equal(typeof SPID_CAPABILITY, 'symbol');
  assert.equal(settings.profiles[0]!.identityMappingVersion, '2026-10');
  assert.equal(f.calls(), 0);
  assert.ok(Object.isFrozen(settings.profiles[0]!.metadata.trustAnchors));
  assert.ok(Object.isFrozen(settings.profiles[0]!.metadata.trustAnchors[0]));
  assert.ok(Object.isFrozen(settings.identityMappers));
  Reflect.set(f.profile, 'expectedIssuers', ['https://untrusted.example.test']);
  assert.deepEqual(settings.profiles[0]!.expectedIssuers, ['https://idp.example.test']);
  await assert.rejects(() => settings.secretProvider.get('signing-ref'));
  assert.equal(f.calls(), 1);
});
test('SPID rejects missing providers, partial stores, unknown fields and unmatched mappings', () => {
  const f = fixture();
  const mutations = [
    { secretProvider: undefined },
    { authority: undefined },
    { identityMappers: {} },
    {
      identityMappers: {
        ...f.settings.identityMappers,
        unused: {
          map: async () => {
            throw new Error('Unused mapper');
          },
        },
      },
    },
    {
      stateStore: {
        ...f.settings.stateStore,
        store: { ...f.settings.stateStore.store, atomicBatch: undefined },
      },
    },
    { stateStore: { ...f.settings.stateStore, securityLevel: 'test-only' } },
    { policy: { maxConcurrent: 0, timeoutMs: 1000 } },
    { policy: { maxConcurrent: 1, timeoutMs: Infinity } },
    { policy: { maxConcurrent: 1, timeoutMs: 1.5 } },
    { policy: { maxConcurrent: 1, timeoutMs: 1, maxInputBytes: -1 } },
    { trustAll: true },
  ];
  for (const mutation of mutations)
    assert.throws(() => capture({ ...f.settings, ...mutation } as ItalianEidPluginSettings), {
      code: 'EK_EID_PROFILE',
    });
  assert.equal(f.calls(), 0);
});
test('SPID rejects cross-system assurance, insecure endpoints, stale roots and invalid registration', () => {
  const f = fixture();
  const reject = (mutation: unknown, code = 'EK_EID_PROFILE') =>
    assert.throws(
      () => capture({ ...f.settings, profiles: [{ ...f.profile, ...(mutation as object) }] }),
      { code },
    );
  reject({ system: 'cie' });
  reject({ schemaVersion: '2.0.0' });
  reject({ protocol: 'openid' });
  reject({ clientId: undefined });
  reject({ allowedAssurance: ['cie-l2'] }, 'EK_EID_ASSURANCE');
  reject({ allowedAssurance: ['spid-l2', 'spid-l2'] });
  reject({ redirectUri: 'http://service.example.test/callback' });
  reject({ expectedIssuers: ['https://idp.example.test/#fragment'] });
  reject({ metadata: { ...f.profile.metadata, revocation: 'optional' } });
  reject({ metadata: { ...f.profile.metadata, stalePolicy: 'accept' } });
  reject({
    metadata: {
      ...f.profile.metadata,
      approvedMetadataEndpoints: ['https://name@idp.example.test/fetch'],
    },
  });
  reject({
    metadata: {
      ...f.profile.metadata,
      trustAnchors: [
        {
          ...f.profile.metadata.trustAnchors[0],
          expiresAt: new Date(Date.now() - 1000).toISOString(),
        },
      ],
    },
  });
  reject({
    metadata: {
      ...f.profile.metadata,
      trustAnchors: [{ ...f.profile.metadata.trustAnchors[0], publicKeyPem: 'invalid-public-key' }],
    },
  });
  reject({
    metadata: {
      ...f.profile.metadata,
      trustAnchors: [...f.profile.metadata.trustAnchors, ...f.profile.metadata.trustAnchors],
    },
  });
  assert.throws(() => capture({ ...f.settings, profiles: [f.profile, f.profile] }), {
    code: 'EK_EID_PROFILE',
  });
  assert.equal(f.calls(), 0);
});
test('SPID rejects executable/proxy policy without invoking traps or getters', () => {
  const f = fixture();
  let effects = 0;
  const dangerous = {
    ...f.settings,
    get profiles(): readonly FederationProfileV1[] {
      effects++;
      throw new Error('Executable profile');
    },
  };
  assert.throws(() => capture(dangerous), { code: 'EK_EID_PROFILE' });
  assert.throws(
    () =>
      capture(
        new Proxy(f.settings, {
          ownKeys() {
            effects++;
            return [];
          },
        }),
      ),
    { code: 'EK_EID_PROFILE' },
  );
  assert.throws(
    () =>
      capture({
        ...f.settings,
        secretProvider: {
          get get(): ItalianEidPluginSettings['secretProvider']['get'] {
            effects++;
            throw new Error('Executable provider');
          },
        },
      }),
    { code: 'EK_EID_PROFILE' },
  );
  assert.equal(effects, 0);
});
test('Test-only provider labels are rejected in production and development', () => {
  const f = fixture();
  for (const environment of ['production', 'development'] as const) {
    assert.throws(
      () =>
        capture(
          {
            ...f.settings,
            secretProvider: { ...f.settings.secretProvider, usage: 'test-only' },
          } as ItalianEidPluginSettings,
          environment,
        ),
      { code: 'EK_EID_PROFILE' },
    );
    assert.throws(
      () =>
        capture(
          { ...f.settings, stateStore: { ...f.settings.stateStore, securityLevel: 'test-only' } },
          environment,
        ),
      { code: 'EK_EID_PROFILE' },
    );
  }
  assert.ok(
    capture(
      { ...f.settings, stateStore: { ...f.settings.stateStore, securityLevel: 'test-only' } },
      'test',
    ),
  );
});

test('Native public-key parsing rejects private keys, weak RSA and unsupported key types', () => {
  const f = fixture();
  const check = (pem: string) =>
    capture({
      ...f.settings,
      profiles: [
        {
          ...f.profile,
          metadata: {
            ...f.profile.metadata,
            trustAnchors: [{ ...f.profile.metadata.trustAnchors[0]!, publicKeyPem: pem }],
          },
        },
      ],
    });
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 });
  assert.throws(() => check(rsa.publicKey.export({ type: 'spki', format: 'pem' }).toString()), {
    code: 'EK_EID_PROFILE',
  });
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  assert.throws(() => check(ec.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()), {
    code: 'EK_EID_PROFILE',
  });
  assert.ok(check(ec.publicKey.export({ type: 'spki', format: 'pem' }).toString()));
  const ed = generateKeyPairSync('ed25519');
  assert.throws(() => check(ed.publicKey.export({ type: 'spki', format: 'pem' }).toString()), {
    code: 'EK_EID_PROFILE',
  });
});

test('Captured provider prototype methods retain their receiver without reading later accessors', async () => {
  const f = fixture();
  class Secrets {
    calls = 0;
    async get(): Promise<never> {
      this.calls++;
      throw new Error('Unavailable test secret');
    }
  }
  const secrets = new Secrets(),
    settings = capture({ ...f.settings, secretProvider: secrets });
  let getters = 0;
  Object.defineProperty(secrets, 'get', {
    get() {
      getters++;
      throw new Error('Changed provider getter');
    },
  });
  await assert.rejects(() => settings.secretProvider.get('signing-ref'));
  assert.equal(secrets.calls, 1);
  assert.equal(getters, 0);
});

test('Actual application environment rejects captured test-only providers before any provider I/O', async () => {
  for (const environment of ['production', 'development'] as const) {
    for (const target of ['store', 'secrets', 'authority', 'mapper'] as const) {
      const f = fixture(),
        marker = { usage: 'test-only' },
        input: ItalianEidPluginSettings = {
          ...f.settings,
          ...(target === 'store'
            ? {
                stateStore: {
                  ...f.settings.stateStore,
                  store: { ...f.settings.stateStore.store, ...marker },
                },
              }
            : target === 'secrets'
              ? { secretProvider: { ...f.settings.secretProvider, ...marker } }
              : target === 'authority'
                ? { authority: { ...f.settings.authority, ...marker } }
                : {
                    identityMappers: {
                      'approved-accounts': {
                        ...f.settings.identityMappers['approved-accounts']!,
                        ...marker,
                      },
                    },
                  }),
        },
        plugin = spidPlugin(input),
        dependency = (id: string, capability: symbol): Plugin => ({
          id,
          version: '1.0.0',
          capabilities: new Set(),
          init(context) {
            // Deliberately inert dependencies prove that the environment guard runs before service construction.
            context.provide(capability, Object.freeze({}));
          },
          close() {},
        });
      const labelled =
        target === 'store'
          ? input.stateStore.store
          : target === 'secrets'
            ? input.secretProvider
            : target === 'authority'
              ? input.authority
              : input.identityMappers['approved-accounts']!;
      Reflect.set(labelled, 'usage', 'production');
      const app = await createApplication({
        service: { name: 'spid-environment-guard', version: '1.0.0', environment },
        plugins: [
          dependency('security', COMPONENTS.auth),
          dependency('crypto', CRYPTO_CAPABILITY),
          plugin,
        ],
      });
      try {
        await assert.rejects(
          () => app.start(),
          (error: unknown) => {
            assert.ok(error instanceof KitError);
            assert.equal(error.code, 'EK_PLUGIN_FAILED');
            assert.ok(error.cause instanceof KitError);
            assert.equal(error.cause.code, 'EK_EID_PROFILE');
            return true;
          },
        );
        assert.equal(f.calls(), 0);
      } finally {
        await app.stop();
      }
    }
  }
});
