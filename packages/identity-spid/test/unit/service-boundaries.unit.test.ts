// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, COMPONENTS, KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { CRYPTO_CAPABILITY } from '@arkenivajs/security-crypto';
import { spidPlugin } from '../../dist/index.js';
import { managed } from '../../dist/service.js';
import { capture } from '../../dist/settings.js';
import { transactionFixture } from '../fixtures/transactions.js';
import { registration } from '../fixtures/registration.js';
import { FederationHttp } from '../../dist/metadata-http.js';

const auth = {
  isVerifiedTenant: (value: unknown): value is never => {
    void value;
    return false;
  },
};
async function fixture() {
  const f = await transactionFixture(),
    registrationData = await registration(f.profile.entityId),
    input = {
      ...f.settings,
      profiles: [
        {
          ...f.profile,
          oidcRegistration: {
            ...registrationData,
            approvedProtocolEndpoints: [
              'https://idp.example.test/token',
              'https://idp.example.test/userinfo',
            ],
          },
        },
      ],
    };
  return { ...f, input, settings: capture(input, 'test') };
}

test('Protocol construction failure closes the actual metadata client without closing borrowed Crypto', async (context) => {
  const f = await fixture(),
    close = FederationHttp.prototype.close;
  let closed = 0;
  context.mock.method(
    FederationHttp.prototype,
    'close',
    async function (this: FederationHttp, ...args: Parameters<FederationHttp['close']>) {
      closed++;
      return Reflect.apply(close, this, args);
    },
  );
  try {
    const profile = f.settings.profiles[0]!;
    await assert.rejects(
      () =>
        managed(
          {
            ...f.settings,
            profiles: [
              {
                ...profile,
                oidcRegistration: { ...profile.oidcRegistration!, approvedProtocolEndpoints: [] },
              },
            ],
          },
          f.crypto,
          auth,
        ),
      { code: 'EK_EID_PROFILE' },
    );
    assert.equal(closed, 1);
    assert.equal(
      (
        await f.crypto.hmac(
          Buffer.from('The borrowed dependency remains available'),
          f.settings.macRefs[0]!,
        )
      ).length,
      32,
    );
    assert.equal(f.rows.size, 0);
    assert.equal(f.claims.size, 0);
  } finally {
    context.mock.restoreAll();
    await f.close();
  }
});

test('A native metadata close failure is reported after actual cleanup and remains stable on repeated close', async (context) => {
  const f = await fixture(),
    close = FederationHttp.prototype.close;
  let closed = 0;
  const instance = await managed(f.settings, f.crypto, auth);
  context.mock.method(
    FederationHttp.prototype,
    'close',
    async function (this: FederationHttp, ...args: Parameters<FederationHttp['close']>) {
      closed++;
      await Reflect.apply(close, this, args);
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'The disposable close acknowledgement was lost',
      });
    },
  );
  try {
    for (let count = 0; count < 2; count++)
      await assert.rejects(() => instance.close(), { code: 'EK_BACKEND_UNAVAILABLE' });
    assert.equal(closed, 1);
    await assert.rejects(() => instance.service.metadata(), { code: 'EK_RESOURCE_CLOSED' });
  } finally {
    context.mock.restoreAll();
    await f.close();
  }
});

test('Operational activation rejects absent protected state or incomplete protocol registration before secret/storage work', async () => {
  const f = await fixture();
  try {
    const withoutState = { ...f.input };
    Reflect.deleteProperty(withoutState, 'stateEncryptionKeyRefs');
    Reflect.deleteProperty(withoutState, 'stateMacKeyRefs');
    for (const input of [
      withoutState,
      { ...f.input, profiles: [f.profile] },
      { ...f.input, profiles: [{ ...f.profile, protocol: 'saml2' as const }] },
      {
        ...f.input,
        profiles: [{ ...f.profile, oidcRegistration: await registration(f.profile.entityId) }],
      },
    ]) {
      let reads = 0;
      const settings = capture(
        {
          ...input,
          secretProvider: {
            async get() {
              reads++;
              throw new Error('No secret access is permitted');
            },
          },
        },
        'test',
      );
      await assert.rejects(() => managed(settings, f.crypto, auth), {
        code: 'EK_EID_PROFILE',
      });
      assert.equal(reads, 0);
      assert.equal(f.rows.size, 0);
      assert.equal(f.claims.size, 0);
    }
  } finally {
    await f.close();
  }
});

test('A single-profile service preserves original selection and rejects missing/unknown issuer or assurance without network work', async () => {
  const f = await fixture();
  let calls = 0;
  const input = {
    ...f.input,
    authority: {
      async require() {
        calls++;
        throw new Error('The ceremony is denied');
      },
    },
  };
  const owner = await managed(capture(input, 'test'), f.crypto, auth);
  try {
    await assert.rejects(
      () => owner.service.beginAuthentication({ returnPath: '/private' }, 'spid-l2'),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(calls, 1);
    for (const context of [
      { returnPath: '/private', issuer: 'https://foreign.example.test' },
      { returnPath: '/private', issuer: 'not-a-url' },
    ])
      await assert.rejects(() => owner.service.beginAuthentication(context, 'spid-l2'));
    await assert.rejects(
      () => owner.service.beginAuthentication({ returnPath: '/private' }, 'spid-l3'),
      { code: 'EK_EID_ASSURANCE' },
    );
    assert.equal(calls, 1);
    await owner.close();
    assert.equal(await owner.health({ timeoutMs: 1000 }), false);
    await owner.close();
    assert.equal(
      (await f.crypto.hmac(Buffer.from('Still borrowed'), f.input.stateMacKeyRefs![0]!)).length,
      32,
    );
  } finally {
    await owner.close();
    await f.close();
  }
});

test('A failed real application bootstrap rolls back owned transports without closing borrowed Crypto', async () => {
  const f = await fixture();
  let secretReads = 0;
  const dependency = (id: string, capability: symbol, value: unknown): Plugin => ({
    id,
    version: '1.0.0',
    capabilities: new Set(),
    init(context) {
      context.provide(capability, value);
    },
    close() {},
  });
  const app = await createApplication({
    service: { name: 'failed-spid-bootstrap', version: '1.0.0', environment: 'test' },
    plugins: [
      dependency('security', COMPONENTS.auth, auth),
      dependency('crypto', CRYPTO_CAPABILITY, f.crypto),
      spidPlugin({
        ...f.input,
        secretProvider: {
          async get() {
            secretReads++;
            throw new Error('Bootstrap must probe storage first');
          },
        },
      }),
    ],
  });
  f.state.storage = false;
  try {
    await assert.rejects(
      () => app.start(),
      (error: unknown) => {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_PLUGIN_FAILED');
        assert.ok(error.cause instanceof KitError);
        assert.equal(error.cause.code, 'EK_EID_FEDERATION');
        return true;
      },
    );
    assert.equal(secretReads, 0);
    assert.equal(f.rows.size, 0);
    assert.equal(f.claims.size, 0);
    assert.equal(
      (
        await f.crypto.hmac(
          Buffer.from('The dependency remains owned by its application'),
          f.input.stateMacKeyRefs![0]!,
        )
      ).length,
      32,
    );
    await app.stop();
    await app.stop();
  } finally {
    await app.stop();
    await f.close();
  }
});
