// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { MfaChallengeRecord, SqlProvider } from '@arkenivajs/core';
import { createPostgresMfaStateStore } from '../../dist/mfa-state-store.js';

const schema = 'mfa_' + 'a'.repeat(24);
const challenge: MfaChallengeRecord = {
  id: 'synthetic-challenge',
  purpose: 'webauthn-authenticate',
  issuer: 'https://issuer.example.test',
  subject: 'synthetic-account',
  tenantId: 'tenant-a',
  primarySessionId: 'session-a',
  rpId: 'example.test',
  challengeDigest: 'a'.repeat(64),
  createdAt: '2026-10-25T00:00:00.000Z',
  expiresAt: '2026-10-25T00:05:00.000Z',
};
function disposable(t: TestContext): void {
  const previous = process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  process.env.ARKENIVA_POSTGRES_DISPOSABLE = '1';
  t.after(() => {
    if (previous === undefined) delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
    else process.env.ARKENIVA_POSTGRES_DISPOSABLE = previous;
  });
}
function unavailable(failure: unknown = new Error('Private backend diagnostic')) {
  let calls = 0;
  const fail = async () => {
    calls++;
    throw failure;
  };
  const sql: SqlProvider = {
    query: fail,
    queryOne: fail,
    execute: fail,
    transaction: fail,
    ping: fail,
    stats: () => ({}),
    native: () => undefined,
  };
  return { sql, calls: () => calls };
}

test('MFA challenge reference rejects unsafe namespaces and malformed input before database work', async (t) => {
  disposable(t);
  const backend = unavailable();
  for (const name of ['public', '../mfa', schema + ';DROP TABLE users'])
    assert.throws(() => createPostgresMfaStateStore(backend.sql, 'main', name), KitError);
  const store = createPostgresMfaStateStore(backend.sql, 'main', schema);
  let accessorCalls = 0;
  for (const value of [
    { ...challenge, purpose: 'arbitrary' },
    { ...challenge, expiresAt: challenge.createdAt },
    { ...challenge, createdAt: '2026-02-30T00:00:00Z' },
    { ...challenge, subject: '' },
    { ...challenge, tenantId: undefined },
    { ...challenge, challengeDigest: 'raw challenge' },
    { ...challenge, submittedOtp: 'synthetic-proof-must-not-be-stored' },
    Object.defineProperty({}, 'issuer', {
      enumerable: true,
      get() {
        accessorCalls++;
        throw new Error('Accessor must not execute');
      },
    }),
  ])
    await assert.rejects(
      store.createChallenge(value as MfaChallengeRecord),
      (error) => error instanceof KitError && error.code === 'EK_MFA_POLICY',
    );
  assert.equal(backend.calls(), 0);
  assert.equal(accessorCalls, 0);
});

test('MFA challenge reference refuses an absent disposable authorization before opening a store', (t) => {
  disposable(t);
  delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  const backend = unavailable();
  assert.throws(
    () => createPostgresMfaStateStore(backend.sql, 'main', schema),
    (error) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
  );
  assert.equal(backend.calls(), 0);
});

test('MFA challenge storage failures never fabricate success or leak the backend cause', async (t) => {
  disposable(t);
  const backend = unavailable();
  const store = createPostgresMfaStateStore(backend.sql, 'main', schema);
  await assert.rejects(store.createChallenge(challenge), (error) => {
    assert.ok(error instanceof KitError);
    assert.equal(error.code, 'EK_MFA_STORAGE');
    assert.ok(!JSON.stringify(error.toSafeJSON()).includes('Private backend diagnostic'));
    return true;
  });
  assert.equal(backend.calls(), 1);
  const canceled = new KitError({ code: 'EK_ABORTED', message: 'Operation canceled' });
  const canceledStore = createPostgresMfaStateStore(unavailable(canceled).sql, 'main', schema);
  await assert.rejects(canceledStore.createChallenge(challenge), (error) => error === canceled);
});
