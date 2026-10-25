// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import { createDisposableMfaSecretProtector } from '../../dist/mfa-secret-protector.js';

const binding = {
  issuer: 'https://issuer.example.test',
  subject: 'synthetic-account',
  tenantId: 'tenant-a',
};
const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
async function disposable(work: () => Promise<void>) {
  const original = process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  process.env.ARKENIVA_POSTGRES_DISPOSABLE = '1';
  try {
    await work();
  } finally {
    if (original === undefined) delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
    else process.env.ARKENIVA_POSTGRES_DISPOSABLE = original;
  }
}

test('AEAD envelopes bind every owner field and key version, with fresh nonces and safe errors', () =>
  disposable(async () => {
    const key = randomBytes(32),
      plain = randomBytes(32);
    const protector = createDisposableMfaSecretProtector('first', async () => key);
    try {
      const first = await protector.seal(plain, binding),
        second = await protector.seal(plain, binding);
      assert.equal(Object.isFrozen(first), true);
      assert.notEqual(first.nonce, second.nonce);
      assert.notEqual(first.ciphertext, second.ciphertext);
      assert.deepEqual(await protector.open(first, binding), new Uint8Array(plain));
      for (const changed of [
        { issuer: 'https://foreign.example.test' },
        { subject: 'other-account' },
        { tenantId: 'tenant-b' },
      ])
        await assert.rejects(
          protector.open(first, { ...binding, ...changed }),
          hasCode('EK_MFA_STORAGE'),
        );
      await assert.rejects(
        protector.open(first, { issuer: binding.issuer, subject: binding.subject }),
        hasCode('EK_MFA_STORAGE'),
      );
      // Even an identical key under another version cannot authenticate rewritten metadata.
      await assert.rejects(
        protector.open({ ...first, keyId: 'second' }, binding),
        hasCode('EK_MFA_STORAGE'),
      );
      for (const field of ['ciphertext', 'nonce', 'tag'] as const) {
        const damaged = Buffer.from(first[field], 'base64');
        damaged[0] = damaged[0]! ^ 1;
        await assert.rejects(
          protector.open({ ...first, [field]: damaged.toString('base64') }, binding),
          (error) => {
            assert.equal(hasCode('EK_MFA_STORAGE')(error), true);
            const safe = JSON.stringify(error);
            for (const sensitive of [
              plain.toString('base64'),
              key.toString('base64'),
              first.ciphertext,
              binding.subject,
            ])
              assert.equal(safe.includes(sensitive), false);
            return true;
          },
        );
      }
    } finally {
      key.fill(0);
      plain.fill(0);
    }
  }));

test('Key rotation preserves old decryptability and missing/invalid keys fail closed', () =>
  disposable(async () => {
    const first = randomBytes(32),
      second = randomBytes(32),
      keys = new Map([
        ['first', first],
        ['second', second],
      ]);
    const lookup = async (id: string) => {
      const key = keys.get(id);
      if (!key) throw new Error('Synthetic key provider unavailable');
      return key;
    };
    const old = createDisposableMfaSecretProtector('first', lookup),
      rotated = createDisposableMfaSecretProtector('second', lookup);
    const plain = new Uint8Array([1, 2, 3, 4]);
    try {
      const envelope = await old.seal(plain, binding),
        current = await rotated.seal(plain, binding);
      assert.equal(current.keyId, 'second');
      assert.deepEqual(await rotated.open(envelope, binding), plain);
      keys.delete('first');
      await assert.rejects(rotated.open(envelope, binding), hasCode('EK_MFA_STORAGE'));
      assert.deepEqual(await rotated.open(current, binding), plain);
      const invalid = createDisposableMfaSecretProtector('first', async () => new Uint8Array(31));
      await assert.rejects(invalid.seal(plain, binding), hasCode('EK_MFA_STORAGE'));
    } finally {
      first.fill(0);
      second.fill(0);
    }
  }));

test('Secret operations honor cancellation/deadline and snapshot mutable inputs before key retrieval', () =>
  disposable(async () => {
    const key = randomBytes(32),
      plain = new Uint8Array([1, 2, 3, 4]),
      owner = { ...binding };
    let start!: () => void, release!: () => void;
    const started = new Promise<void>((resolve) => {
        start = resolve;
      }),
      wait = new Promise<void>((resolve) => {
        release = resolve;
      });
    const pending = createDisposableMfaSecretProtector('first', async () => {
      start();
      await wait;
      return key;
    });
    try {
      const result = pending.seal(plain, owner);
      await started;
      plain.fill(0);
      owner.subject = 'other-account';
      release();
      const envelope = await result;
      assert.deepEqual(await pending.open(envelope, binding), new Uint8Array([1, 2, 3, 4]));
      let calls = 0;
      const unavailable = createDisposableMfaSecretProtector('first', async () => {
        calls++;
        return new Promise<Uint8Array>(() => {});
      });
      await assert.rejects(
        unavailable.seal(plain, binding, { signal: AbortSignal.abort() }),
        hasCode('EK_ABORTED'),
      );
      assert.equal(calls, 0);
      await assert.rejects(
        unavailable.seal(plain, binding, { timeoutMs: 5 }),
        hasCode('EK_TIMEOUT'),
      );
      assert.equal(calls, 1);
      const controller = new AbortController(),
        cancelled = unavailable.open(envelope, binding, { signal: controller.signal });
      controller.abort();
      await assert.rejects(cancelled, hasCode('EK_ABORTED'));

      let finish!: (value: Uint8Array) => void;
      const late = createDisposableMfaSecretProtector(
        'first',
        () =>
          new Promise<Uint8Array>((resolve) => {
            finish = resolve;
          }),
      );
      await assert.rejects(late.open(envelope, binding, { timeoutMs: 5 }), hasCode('EK_TIMEOUT'));
      let accesses = 0;
      finish(
        new Proxy(key, {
          get(target, property) {
            if (property === 'byteLength') accesses++;
            return Reflect.get(target, property, target) as unknown;
          },
        }),
      );
      await new Promise<void>((resolve) => setImmediate(resolve));
      assert.equal(accesses, 0, 'Late key material must not be used after the caller deadline');
    } finally {
      release();
      key.fill(0);
    }
  }));

test('Disposable marker, envelope bounds and accessor rejection prevent unsafe secret configuration', async () => {
  const original = process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  try {
    assert.throws(
      () => createDisposableMfaSecretProtector('first', async () => randomBytes(32)),
      hasCode('EK_CONFIG_INVALID'),
    );
  } finally {
    if (original !== undefined) process.env.ARKENIVA_POSTGRES_DISPOSABLE = original;
  }
  await disposable(async () => {
    const key = randomBytes(32),
      protector = createDisposableMfaSecretProtector('first', async () => key);
    try {
      const envelope = await protector.seal(new Uint8Array([1]), binding);
      const maximum = new Uint8Array(4096).fill(7);
      assert.deepEqual(
        await protector.open(await protector.seal(maximum, binding), binding),
        maximum,
      );
      for (const plain of [new Uint8Array(), new Uint8Array(4097)])
        await assert.rejects(protector.seal(plain, binding), hasCode('EK_MFA_POLICY'));
      for (const changed of [
        { nonce: '' },
        { tag: 'AAAA' },
        { ciphertext: envelope.ciphertext + '\n' },
        { ciphertext: 'A'.repeat(5465) },
        { extra: 'undeclared' },
      ])
        await assert.rejects(
          protector.open({ ...envelope, ...changed }, binding),
          hasCode('EK_MFA_POLICY'),
        );
      let invoked = false;
      const accessor = Object.defineProperty({}, 'keyId', {
        enumerable: true,
        get() {
          invoked = true;
          return 'first';
        },
      });
      await assert.rejects(
        protector.open(accessor as typeof envelope, binding),
        hasCode('EK_MFA_POLICY'),
      );
      assert.equal(invoked, false);
      for (const id of ['', 'key\n', 'a'.repeat(65)])
        assert.throws(
          () => createDisposableMfaSecretProtector(id, async () => key),
          hasCode('EK_MFA_POLICY'),
        );
    } finally {
      key.fill(0);
    }
  });
});
