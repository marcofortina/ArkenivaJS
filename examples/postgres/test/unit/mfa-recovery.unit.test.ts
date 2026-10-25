// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { createDisposableRecoveryHmacProvider } from '../../dist/mfa-recovery-hmac.js';

test('The MAC reference rejects unsafe construction, invalid secret lengths and interrupted providers', async () => {
  const original = process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  const input = {
    issuer: 'issuer',
    subject: 'account',
    factorId: 'factor',
    code: 'synthetic-code',
  };
  const snapshot = async () => ({ current: 'first', allowed: ['first'] });
  const code = (value: string) => (error: unknown) =>
    error instanceof KitError && error.code === value;
  try {
    delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
    assert.throws(
      () => createDisposableRecoveryHmacProvider(snapshot, async () => new Uint8Array(32)),
      code('EK_MFA_POLICY'),
    );
    process.env.ARKENIVA_POSTGRES_DISPOSABLE = '1';
    assert.throws(
      () =>
        createDisposableRecoveryHmacProvider(undefined as never, async () => new Uint8Array(32)),
      code('EK_MFA_POLICY'),
    );
    assert.throws(
      () => createDisposableRecoveryHmacProvider(snapshot, undefined as never),
      code('EK_MFA_POLICY'),
    );
    for (const length of [0, 31, 65]) {
      const provider = createDisposableRecoveryHmacProvider(
        snapshot,
        async () => new Uint8Array(length),
      );
      await assert.rejects(provider.createVerifier(input), code('EK_MFA_STORAGE'));
    }
    let calls = 0;
    const provider = createDisposableRecoveryHmacProvider(snapshot, async () => {
      calls++;
      return new Promise<Uint8Array>(() => {});
    });
    await assert.rejects(
      provider.createVerifier(input, {
        signal: AbortSignal.abort(new Error('Sensitive synthetic abort')),
      }),
      code('EK_ABORTED'),
    );
    assert.equal(calls, 0);
    await assert.rejects(provider.createVerifier(input, { timeoutMs: 5 }), code('EK_TIMEOUT'));
    assert.equal(calls, 1);
    const valid = createDisposableRecoveryHmacProvider(snapshot, async () => new Uint8Array(32));
    for (const change of [
      { subject: '' },
      { factorId: 'bad\nvalue' },
      { code: 'x'.repeat(1025) },
      { tenantId: '' },
    ])
      await assert.rejects(valid.createVerifier({ ...input, ...change }), code('EK_MFA_STORAGE'));
  } finally {
    if (original === undefined) delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
    else process.env.ARKENIVA_POSTGRES_DISPOSABLE = original;
  }
});

test('The disposable MAC reference binds every owner and factor field and retains approved prior keys', async () => {
  const original = process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  process.env.ARKENIVA_POSTGRES_DISPOSABLE = '1';
  const keys = new Map([
    ['first', randomBytes(32)],
    ['second', randomBytes(32)],
  ]);
  let current = 'first',
    allowed = ['first'];
  const input = {
    issuer: 'https://issuer.example.test',
    subject: 'synthetic-account',
    tenantId: 'tenant-a',
    factorId: 'factor-a',
    code: 'synthetic-code',
  };
  try {
    const provider = createDisposableRecoveryHmacProvider(
      async () => ({ current, allowed }),
      async (id) => {
        const key = keys.get(id);
        if (!key) throw new Error('Sensitive synthetic key diagnostic');
        return key;
      },
    );
    assert.equal(provider.securityLevel, 'test-only');
    const old = await provider.createVerifier(input);
    assert.match(old, /^v1:first:[a-f0-9]{64}$/);
    for (const change of [
      { issuer: 'foreign' },
      { subject: 'other' },
      { tenantId: 'tenant-b' },
      { factorId: 'factor-b' },
      { code: 'other' },
    ])
      assert.notEqual(await provider.createVerifier({ ...input, ...change }), old);
    const { tenantId: _tenant, ...withoutTenant } = input;
    void _tenant;
    assert.notEqual(await provider.createVerifier(withoutTenant), old);
    current = 'second';
    allowed = ['second', 'first'];
    const candidates = await provider.candidateVerifiers(input);
    assert.equal(candidates.length, 2);
    assert.equal(candidates.includes(old), true);
    assert.notEqual(await provider.createVerifier(input), old);
    allowed = ['second'];
    assert.equal((await provider.candidateVerifiers(input)).includes(old), false);
    for (const invalid of [
      [],
      ['second', 'second'],
      Array(9).fill('second'),
      ['bad/key'],
      ['first'],
    ]) {
      allowed = invalid;
      await assert.rejects(
        provider.candidateVerifiers(input),
        (error) => error instanceof KitError && error.code === 'EK_MFA_STORAGE',
      );
    }
    allowed = ['second'];
    keys.get('second')!.fill(0);
    keys.delete('second');
    await assert.rejects(provider.createVerifier(input), (error) => {
      assert.equal(inspect(error).includes('Sensitive synthetic'), false);
      return error instanceof KitError && error.code === 'EK_MFA_STORAGE';
    });
  } finally {
    for (const key of keys.values()) key.fill(0);
    if (original === undefined) delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
    else process.env.ARKENIVA_POSTGRES_DISPOSABLE = original;
  }
});
