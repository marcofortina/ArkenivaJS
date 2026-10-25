// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { SqlProvider } from '@arkenivajs/core';
import { createPostgresWebAuthnStateStore } from '../../dist/webauthn-state-store.js';

const owner = {
  issuer: 'https://issuer.example.test',
  subject: 'synthetic-account',
  primarySessionId: 'session-a',
  authenticatedAt: '2026-10-26T00:00:00.000Z',
};
const schema = 'mfa_' + 'a'.repeat(24),
  rp = 'example.test';
const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
async function disposable(work: () => Promise<void>) {
  const old = process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  process.env.ARKENIVA_POSTGRES_DISPOSABLE = '1';
  try {
    await work();
  } finally {
    if (old === undefined) delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
    else process.env.ARKENIVA_POSTGRES_DISPOSABLE = old;
  }
}
const record = () => ({
  credentialId: randomBytes(32).toString('base64url'),
  rpId: rp,
  issuer: owner.issuer,
  subject: owner.subject,
  userHandle: randomBytes(32).toString('base64url'),
  stateVersion: 'candidate',
  publicKey: randomBytes(80),
  counter: 0,
  backupEligible: false,
  backedUp: false,
  registeredAt: owner.authenticatedAt,
});

test('WebAuthn reference rejects invalid bindings, typed-array bounds and accessors before SQL', () =>
  disposable(async () => {
    let calls = 0;
    const fail = async () => {
      calls++;
      throw new Error('Unexpected SQL');
    };
    const sql = {
      query: fail,
      queryOne: fail,
      execute: fail,
      transaction: fail,
    } as unknown as SqlProvider;
    const store = createPostgresWebAuthnStateStore(sql, 'main', schema),
      value = record();
    for (const altered of [
      { ...value, credentialId: 'a=' },
      { ...value, userHandle: 'a' },
      { ...value, counter: -1 },
      { ...value, counter: 0x100000000 },
      { ...value, publicKey: new Uint8Array() },
      { ...value, publicKey: new Uint8Array(16385) },
      { ...value, backedUp: true },
      { ...value, transports: ['usb', 'usb'] },
      { ...value, transports: Array.from({ length: 17 }, (_, i) => String(i)) },
      { ...value, registeredAt: 'invalid' },
      { ...value, unknown: true },
    ])
      await assert.rejects(store.insertCredentialIfAbsent(altered), hasCode('EK_MFA_POLICY'));
    let getter = 0;
    await assert.rejects(
      store.insertCredentialIfAbsent({
        ...value,
        get publicKey() {
          getter++;
          return value.publicKey;
        },
      }),
      hasCode('EK_MFA_POLICY'),
    );
    await assert.rejects(
      store.getOrCreateUserHandle({ ...owner, subject: '' }, rp),
      hasCode('EK_MFA_POLICY'),
    );
    await assert.rejects(store.getCredential('=', rp), hasCode('EK_MFA_POLICY'));
    await assert.rejects(
      store.verifyUserHandleBinding({
        credentialId: value.credentialId,
        rpId: rp,
        userHandle: 'invalid',
      }),
      hasCode('EK_MFA_POLICY'),
    );
    const input = { ...value, previousCounter: 1, newCounter: 1, expectedVersion: 'backend' };
    const {
      credentialId,
      rpId,
      issuer,
      subject,
      userHandle,
      previousCounter,
      newCounter,
      expectedVersion,
      backedUp,
    } = input;
    await assert.rejects(
      store.advanceCounter({
        credentialId,
        rpId,
        issuer,
        subject,
        userHandle,
        previousCounter,
        newCounter,
        expectedVersion,
        backedUp,
      }),
      hasCode('EK_MFA_POLICY'),
    );
    const clock = createPostgresWebAuthnStateStore(sql, 'main', schema, () => NaN);
    await assert.rejects(
      clock.revokeCredential(owner, rp, value.credentialId, 'backend'),
      hasCode('EK_MFA_POLICY'),
    );
    assert.equal(calls, 0);
    assert.equal(getter, 0);
  }));

test('WebAuthn reference does not acknowledge failed or ambiguous database operations', () =>
  disposable(async () => {
    const fail = async () => {
      throw new Error('Sensitive synthetic backend diagnostic');
    };
    const sql = {
      query: fail,
      queryOne: fail,
      execute: fail,
      transaction: fail,
    } as unknown as SqlProvider;
    const store = createPostgresWebAuthnStateStore(sql, 'main', schema),
      value = record();
    for (const work of [
      () => store.getOrCreateUserHandle(owner, rp),
      () => store.listCredentials(owner, rp),
      () => store.getCredential(value.credentialId, rp),
      () => store.verifyUserHandleBinding({ credentialId: value.credentialId, rpId: rp }),
      () => store.insertCredentialIfAbsent(value),
      () =>
        store.advanceCounter({
          credentialId: value.credentialId,
          rpId: rp,
          issuer: value.issuer,
          subject: value.subject,
          userHandle: value.userHandle,
          previousCounter: 0,
          newCounter: 0,
          expectedVersion: 'backend',
          backedUp: false,
        }),
      () => store.revokeCredential(owner, rp, value.credentialId, 'backend'),
    ])
      await assert.rejects(work(), (error) => {
        assert.ok(hasCode('EK_MFA_STORAGE')(error));
        assert.equal(JSON.stringify(error).includes('Sensitive synthetic'), false);
        return true;
      });
    const ambiguous = createPostgresWebAuthnStateStore(
      { execute: async () => ({ rowCount: null }) } as unknown as SqlProvider,
      'main',
      schema,
    );
    await assert.rejects(ambiguous.insertCredentialIfAbsent(value), hasCode('EK_MFA_STORAGE'));
  }));
