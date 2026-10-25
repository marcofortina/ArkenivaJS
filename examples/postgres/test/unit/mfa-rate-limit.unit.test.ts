// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { SqlProvider, MfaRateLimitStore } from '@arkenivajs/core';
import { createPostgresMfaRateLimitStore } from '../../dist/mfa-rate-limit-store.js';

const input = {
  scopeKey: 'synthetic-scope',
  operation: 'verify',
  maxAttempts: 3,
  windowMs: 1000,
  nowMs: 1000,
};

test('MFA limiter rejects coercion, unsafe integers, clock overflow and undeclared input before SQL', async (t) => {
  const before = process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  process.env.ARKENIVA_POSTGRES_DISPOSABLE = '1';
  t.after(() => {
    if (before === undefined) delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
    else process.env.ARKENIVA_POSTGRES_DISPOSABLE = before;
  });
  let calls = 0;
  const fail = async () => {
    calls++;
    throw new Error('SQL must not run');
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
  const store = createPostgresMfaRateLimitStore(sql, 'main', 'mfa_' + 'a'.repeat(24));
  for (const change of [
    { maxAttempts: '3' },
    { maxAttempts: 0 },
    { maxAttempts: 1.5 },
    { maxAttempts: Number.MAX_SAFE_INTEGER },
    { windowMs: 0 },
    { windowMs: Infinity },
    { nowMs: NaN },
    { nowMs: -1 },
    { nowMs: Number.MAX_SAFE_INTEGER },
    { operation: '' },
    { scopeKey: 'bad\nkey' },
    { extra: true },
  ])
    await assert.rejects(
      store.checkAndRecord({ ...input, ...change } as Parameters<
        MfaRateLimitStore['checkAndRecord']
      >[0]),
      (error) => error instanceof KitError && error.code === 'EK_MFA_POLICY',
    );
  assert.equal(calls, 0);
});

test('MFA limiter cannot grant an attempt on backend failure and preserves deadline errors', async (t) => {
  const before = process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  process.env.ARKENIVA_POSTGRES_DISPOSABLE = '1';
  t.after(() => {
    if (before === undefined) delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
    else process.env.ARKENIVA_POSTGRES_DISPOSABLE = before;
  });
  for (const failure of [
    new Error('Private backend cause'),
    new KitError({ code: 'EK_TIMEOUT', message: 'Operation timed out' }),
  ]) {
    const fail = async () => {
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
    const store = createPostgresMfaRateLimitStore(sql, 'main', 'mfa_' + 'a'.repeat(24));
    await assert.rejects(store.checkAndRecord(input), (error) => {
      assert.ok(error instanceof KitError);
      assert.equal(error.code, failure instanceof KitError ? 'EK_TIMEOUT' : 'EK_MFA_STORAGE');
      assert.ok(!JSON.stringify(error.toSafeJSON()).includes('Private backend cause'));
      return true;
    });
  }
});
