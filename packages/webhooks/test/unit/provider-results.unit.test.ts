// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import type { IdentitySubject, SecretValue } from '../../dist/index.js';
import { fixture, fixtureSettings } from './fixture.js';

test('Malformed authoritative webhook subjects fail before key retrieval or nonce mutation', async () => {
  const base = fixtureSettings(),
    authority = base.settings.authority,
    original = authority.require;
  let transform: (value: IdentitySubject) => unknown = (value) => value;
  authority.require = async (...args) =>
    transform(await Reflect.apply(original, authority, args)) as IdentitySubject;
  const f = await fixture(base);
  try {
    const mutations: ((value: IdentitySubject) => unknown)[] = [
      () => null,
      () => ({}),
      (value) => ({ ...value, issuer: '' }),
      (value) => ({ ...value, subject: '' }),
      (value) => ({ ...value, extra: 'private-provider-data' }),
      (value) => ({ ...value, tenant: null }),
      (value) => ({ ...value, tenant: { ...value.tenant, tenantId: '' } }),
      (value) => ({ ...value, tenant: { ...value.tenant, source: 'untrusted' } }),
      (value) => ({
        ...value,
        tenant: { ...value.tenant, verifiedAt: new Date(Date.now() + 600000).toISOString() },
      }),
      (value) => ({
        ...value,
        tenant: {
          ...value.tenant,
          identity: { ...value.tenant!.identity, issuer: 'foreign-issuer' },
        },
      }),
      (value) => ({
        ...value,
        tenant: {
          ...value.tenant,
          identity: { ...value.tenant!.identity, subject: 'foreign-subject' },
        },
      }),
    ];
    for (const mutation of mutations) {
      transform = mutation;
      await assert.rejects(
        f.asTenant('tenant-a', () => f.service.sign(Buffer.from('owned'), 'current', f.context())),
        { code: 'EK_AUTH_FORBIDDEN' },
      );
      assert.equal(f.state.secretCalls, 0);
      assert.equal(f.state.claimCalls, 0);
    }
    transform = (value) => {
      const { tenant, ...global } = value;
      void tenant;
      return global;
    };
    const context = f.context(),
      raw = Buffer.from('owned'),
      signature = await f.asTenant('tenant-a', () => f.service.sign(raw, 'current', context));
    assert.equal(
      (await f.asTenant('tenant-a', () => f.service.verify(raw, signature, context))).eventId,
      context.eventId,
    );
    assert.equal(f.state.claimCalls, 1);
  } finally {
    await f.close();
  }
});

test('Malformed, expired and mismatched webhook key results cannot produce a signature or erase provider bytes', async () => {
  const base = fixtureSettings(),
    original = base.keys.get('current')!,
    before = Buffer.from(original.bytes);
  let supplied: unknown = original;
  base.settings.secretProvider.get = async () => supplied as SecretValue;
  const f = await fixture(base);
  let effects = 0;
  const accessor = Object.defineProperty({ ...original }, 'bytes', {
    get() {
      effects++;
      throw new Error('Private key accessor');
    },
  });
  try {
    for (const result of [
      null,
      {},
      accessor,
      { ...original, keyVersion: '' },
      { ...original, keyVersion: 'foreign' },
      { ...original, bytes: new Uint8Array(31) },
      { ...original, bytes: new Uint8Array(4097) },
      { ...original, bytes: new Uint8Array(new SharedArrayBuffer(32)) },
      { ...original, bytes: Object.create(Uint8Array.prototype) },
      { ...original, expiresAt: 'invalid' },
      { ...original, expiresAt: new Date(Date.now() - 1000).toISOString() },
    ]) {
      supplied = result;
      await assert.rejects(
        f.asTenant('tenant-a', () => f.service.sign(Buffer.from('owned'), 'current', f.context())),
        { code: 'EK_WEBHOOK_SIGNATURE' },
      );
      assert.deepEqual(original.bytes, before);
      assert.equal(f.state.claimCalls, 0);
    }
    supplied = { ...original, expiresAt: new Date(Date.now() + 60000).toISOString() };
    assert.equal(
      (
        await f.asTenant('tenant-a', () =>
          f.service.sign(Buffer.from('owned'), 'current', f.context()),
        )
      ).algorithm,
      'hmac-sha256',
    );
    assert.equal(effects, 0);
    assert.deepEqual(original.bytes, before);
  } finally {
    await f.close();
    before.fill(0);
  }
});

test('A nonboolean nonce acknowledgement never confirms verification and a committed claim remains single-use', async () => {
  const base = fixtureSettings(),
    store = base.settings.nonceStore.store,
    original = store.claimOnce;
  let corrupt = false,
    receipt: unknown;
  store.claimOnce = async (...args) => {
    const committed = await Reflect.apply(original, store, args);
    return corrupt ? (receipt as boolean) : committed;
  };
  const f = await fixture(base);
  try {
    for (const malformed of [undefined, null, {}, 1, 'true']) {
      const context = f.context(),
        raw = Buffer.from('owned'),
        signature = await f.asTenant('tenant-a', () => f.service.sign(raw, 'current', context));
      corrupt = true;
      receipt = malformed;
      await assert.rejects(
        f.asTenant('tenant-a', () => f.service.verify(raw, signature, context)),
        (error: unknown) => {
          assert.equal((error as { code: string }).code, 'EK_WEBHOOK_REPLAY');
          assert.equal((error as { details: { outcome?: string } }).details.outcome, 'unknown');
          return true;
        },
      );
      corrupt = false;
      await assert.rejects(
        f.asTenant('tenant-a', () => f.service.verify(raw, signature, context)),
        { code: 'EK_WEBHOOK_REPLAY' },
      );
    }
    assert.equal(f.claims.size, 5);
    assert.equal(f.state.claimCalls, 10);
  } finally {
    await f.close();
  }
});
