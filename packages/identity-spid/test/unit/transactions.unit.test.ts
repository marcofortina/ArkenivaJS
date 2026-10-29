// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { transactionFixture } from '../fixtures/transactions.js';
import { capture } from '../../dist/settings.js';
import { FederationTransactions } from '../../dist/transactions.js';
import type { ItalianEidPluginSettings } from '../../dist/index.js';

test('Actual framework cryptography protects nonce and PKCE state before shared persistence', async () => {
  const f = await transactionFixture();
  try {
    const created = await f.runtime.run((call) => f.first.create(call, f.input)),
      serialized = JSON.stringify([...f.rows]);
    for (const value of [
      created.transactionId,
      created.nonce,
      created.verifier,
      created.tenantHint!,
    ])
      assert.equal(serialized.includes(value), false);
    assert.equal(created.transactionId.length, 43);
    assert.equal(created.nonce.length, 43);
    assert.equal(created.verifier.length, 43);
    assert.notEqual(created.nonce, created.verifier);
    const consumed = await f.runtime.run((call) =>
      f.second.consume(call, created.transactionId, created.issuer),
    );
    assert.deepEqual(consumed, created);
    await assert.rejects(
      () => f.runtime.run((call) => f.first.consume(call, created.transactionId, created.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});
test('Concurrent independent instances release exactly one login transaction', async () => {
  const f = await transactionFixture();
  try {
    const created = await f.runtime.run((call) => f.first.create(call, f.input)),
      attempts = await Promise.allSettled(
        Array.from({ length: 8 }, (_, index) =>
          f.runtime.run((call) =>
            (index % 2 ? f.first : f.second).consume(call, created.transactionId, created.issuer),
          ),
        ),
      );
    assert.equal(attempts.filter((attempt) => attempt.status === 'fulfilled').length, 1);
    assert.equal(f.claims.size, 1);
  } finally {
    await f.close();
  }
});
test('Stored metadata and encrypted content cannot be swapped or tampered with', async () => {
  const f = await transactionFixture();
  try {
    const created = await f.runtime.run((call) => f.first.create(call, f.input)),
      [id, row] = [...f.rows][0]!;
    for (const mutation of [
      { issuer: 'https://foreign.example.test' },
      { ownerKey: 'f'.repeat(64) },
      { assurance: 'spid-l3' },
      { fingerprint: 'other-profile' },
      { expiresAt: new Date(Date.now() + 600000).toISOString() },
      { encRef: 'state-encryption-old' },
      { macRef: 'state-mac-old' },
      { version: '' },
      { sealed: { ...(row.sealed as object), tag: Buffer.alloc(16).toString('base64url') } },
    ]) {
      f.rows.set(id, { ...row, ...mutation });
      await assert.rejects(
        () =>
          f.runtime.run((call) => f.second.consume(call, created.transactionId, created.issuer)),
        { code: 'EK_EID_FEDERATION' },
      );
      assert.equal(f.claims.size, 0);
    }
    f.rows.set(id, row);
    assert.equal(
      (await f.runtime.run((call) => f.second.consume(call, created.transactionId, created.issuer)))
        .nonce,
      created.nonce,
    );
  } finally {
    await f.close();
  }
});
test('Retained old references permit rotation without admitting replay across key order changes', async () => {
  const f = await transactionFixture();
  try {
    const old = f.instance({
        ...f.settings,
        stateEncryptionKeyRefs: ['state-encryption-old'],
        stateMacKeyRefs: ['state-mac-old'],
      }),
      created = await f.runtime.run((call) => old.create(call, f.input)),
      rotated = await f.runtime.run((call) =>
        f.first.consume(call, created.transactionId, created.issuer),
      );
    assert.equal(rotated.verifier, created.verifier);
    await assert.rejects(
      () => f.runtime.run((call) => old.consume(call, created.transactionId, created.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});
test('Profile, mapping version, issuer and callback reference boundaries remain enforced', async () => {
  const f = await transactionFixture();
  try {
    const created = await f.runtime.run((call) => f.first.create(call, f.input));
    for (const transaction of [
      f.instance({ ...f.settings, profiles: [{ ...f.profile, identityMappingVersion: '2' }] }),
      f.instance({
        ...f.settings,
        profiles: [{ ...f.profile, redirectUri: 'https://service.example.test/other' }],
      }),
    ])
      await assert.rejects(
        () =>
          f.runtime.run((call) => transaction.consume(call, created.transactionId, created.issuer)),
        { code: 'EK_EID_FEDERATION' },
      );
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          f.first.consume(call, created.transactionId, 'https://foreign.example.test'),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
    await assert.rejects(
      () => f.runtime.run((call) => f.first.consume(call, 'invalid', created.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(f.claims.size, 0);
  } finally {
    await f.close();
  }
});
test('Missing, expired and ambiguous persistence cannot yield a consumed transaction', async (t) => {
  const f = await transactionFixture();
  try {
    f.state.ambiguousCreate = true;
    await assert.rejects(() => f.runtime.run((call) => f.first.create(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    f.state.ambiguousCreate = false;
    const created = await f.runtime.run((call) => f.first.create(call, f.input));
    f.state.ambiguousClaim = true;
    await assert.rejects(
      () => f.runtime.run((call) => f.first.consume(call, created.transactionId, created.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
    f.state.ambiguousClaim = false;
    await assert.rejects(
      () => f.runtime.run((call) => f.first.consume(call, created.transactionId, created.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    t.mock.timers.tick(301000);
    await assert.rejects(
      () => f.runtime.run((call) => f.first.consume(call, created.transactionId, created.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    t.mock.timers.reset();
    await f.close();
  }
});
test('Storage and secret-provider outages never bypass protected-state verification', async () => {
  const f = await transactionFixture();
  try {
    const created = await f.runtime.run((call) => f.first.create(call, f.input));
    f.state.storage = false;
    await assert.rejects(
      () => f.runtime.run((call) => f.first.consume(call, created.transactionId, created.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
    f.state.storage = true;
    f.state.secrets = false;
    await assert.rejects(
      () => f.runtime.run((call) => f.first.consume(call, created.transactionId, created.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(f.claims.size, 0);
  } finally {
    await f.close();
  }
});
test('Separate explicit key-reference catalogs are required for encrypted transaction operations', async () => {
  const f = await transactionFixture();
  try {
    const { stateEncryptionKeyRefs, stateMacKeyRefs, ...withoutKeys } = f.settings;
    void stateEncryptionKeyRefs;
    void stateMacKeyRefs;
    const noKeys = capture(withoutKeys, 'test');
    assert.throws(() => new FederationTransactions(noKeys, f.profile.profileId, f.crypto), {
      code: 'EK_EID_PROFILE',
    });
    for (const change of [
      { stateEncryptionKeyRefs: [] },
      { stateMacKeyRefs: [] },
      { stateEncryptionKeyRefs: ['state-mac-current'] },
      { stateMacKeyRefs: ['signing-ref'] },
      { stateMacKeyRefs: ['same', 'same'] },
      { stateMacKeyRefs: undefined },
      { stateMacKeyRefs: Array.from({ length: 9 }, (_, index) => 'ref-' + index) },
    ])
      assert.throws(
        () => capture({ ...f.settings, ...change } as unknown as ItalianEidPluginSettings, 'test'),
        {
          code: 'EK_EID_PROFILE',
        },
      );
    let effects = 0;
    assert.throws(
      () =>
        capture(
          {
            ...f.settings,
            get stateMacKeyRefs() {
              effects++;
              return ['unsafe'];
            },
          },
          'test',
        ),
      { code: 'EK_EID_PROFILE' },
    );
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});
test('Untrusted begin inputs cannot select another issuer, assurance or external return path', async () => {
  const f = await transactionFixture();
  try {
    for (const change of [
      { issuer: 'https://foreign.example.test' },
      { assurance: 'spid-l3' as const },
      { returnPath: '//foreign.example.test' },
      { returnPath: '/\\foreign.example.test' },
      { returnPath: '/private#fragment' },
      { returnPath: '/private\n' },
    ])
      await assert.rejects(
        () => f.runtime.run((call) => f.first.create(call, { ...f.input, ...change })),
        { code: 'EK_EID_FEDERATION' },
      );
    assert.equal(f.rows.size, 0);
  } finally {
    await f.close();
  }
});
test('Late decrypted plaintext is erased and retains physical admission after public timeout', async () => {
  const f = await transactionFixture();
  let release!: () => void, entered!: () => void, returned: Uint8Array | undefined;
  const pending = new Promise<void>((resolve) => {
      release = resolve;
    }),
    began = new Promise<void>((resolve) => {
      entered = resolve;
    });
  try {
    const created = await f.runtime.run((call) => f.first.create(call, f.input)),
      transaction = new FederationTransactions(capture(f.settings, 'test'), f.profile.profileId, {
        ...f.crypto,
        async decrypt(...args) {
          returned = await f.crypto.decrypt(...args);
          entered();
          await pending;
          return returned;
        },
      }),
      work = f.runtime.run(
        (call) => transaction.consume(call, created.transactionId, created.issuer),
        { timeoutMs: 250 },
      );
    const rejected = assert.rejects(work, { code: 'EK_TIMEOUT' });
    await began;
    assert.ok(returned?.some((value) => value !== 0));
    await rejected;
    assert.equal(f.runtime.stats().active, 1);
    assert.equal(f.claims.size, 0);
  } finally {
    release();
    await f.close();
  }
  assert.ok(returned?.every((value) => value === 0));
});
