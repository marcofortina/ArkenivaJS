// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { SqlProvider } from '@arkenivajs/core';
import { createPostgresTotpStateStore } from '../../dist/totp-state-store.js';

const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
const subject = {
  issuer: 'https://issuer.example.test',
  subject: 'synthetic-account',
  primarySessionId: 'session-a',
  authenticatedAt: '2026-10-25T00:00:00.000Z',
};
const schema = 'mfa_' + 'a'.repeat(24);
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

test('TOTP store rejects malformed owner, CAS and recovery input before SQL', () =>
  disposable(async () => {
    let calls = 0;
    const fail = async () => {
      calls++;
      throw new Error('Unexpected SQL');
    };
    const sql = { queryOne: fail, execute: fail, transaction: fail } as unknown as SqlProvider;
    const store = createPostgresTotpStateStore(sql, 'main', schema);
    await assert.rejects(store.getFactor({ ...subject, subject: '' }), hasCode('EK_MFA_POLICY'));
    await assert.rejects(
      store.acceptStepIfGreater(subject, 'factor', 1, 0.5),
      hasCode('EK_MFA_POLICY'),
    );
    await assert.rejects(
      store.acceptStepIfGreater(subject, 'factor', 0, 1),
      hasCode('EK_MFA_POLICY'),
    );
    await assert.rejects(
      store.replaceRecoveryHashes(subject, ['same', 'same']),
      hasCode('EK_MFA_POLICY'),
    );
    await assert.rejects(
      store.replaceRecoveryHashes(
        subject,
        Array.from({ length: 101 }, (_, index) => String(index)),
      ),
      hasCode('EK_MFA_POLICY'),
    );
    await assert.rejects(store.consumeRecoveryHash(subject, ''), hasCode('EK_MFA_POLICY'));
    let invoked = false;
    const value = Object.defineProperty({}, 'id', {
      enumerable: true,
      get() {
        invoked = true;
        return 'factor';
      },
    });
    await assert.rejects(store.putPending(value as never), hasCode('EK_MFA_POLICY'));
    assert.equal(invoked, false);
    assert.equal(calls, 0);
  }));

test('TOTP store backend errors cannot fabricate state transitions or expose provider diagnostics', () =>
  disposable(async () => {
    const fail = async () => {
      throw new Error('Sensitive synthetic backend diagnostic');
    };
    const sql = { queryOne: fail, execute: fail, transaction: fail } as unknown as SqlProvider;
    const store = createPostgresTotpStateStore(sql, 'main', schema);
    for (const work of [
      () => store.getFactor(subject),
      () => store.getPending(subject, 'factor'),
      () => store.activatePending(subject, 'factor', 1, subject.authenticatedAt),
      () => store.acceptStepIfGreater(subject, 'factor', 1, 2),
      () => store.revokeFactor(subject, 'factor'),
      () => store.replaceRecoveryHashes(subject, ['synthetic-keyed-hash']),
      () => store.consumeRecoveryHash(subject, 'synthetic-keyed-hash'),
    ])
      await assert.rejects(work(), (error) => {
        assert.equal(hasCode('EK_MFA_STORAGE')(error), true);
        assert.equal(JSON.stringify(error).includes('Sensitive synthetic'), false);
        return true;
      });
  }));
