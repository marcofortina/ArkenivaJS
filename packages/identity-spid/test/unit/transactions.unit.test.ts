// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { transactionFixture } from '../fixtures/transactions.js';
import { capture } from '../../dist/settings.js';
import { FederationTransactions } from '../../dist/transactions.js';
import type { ItalianEidPluginSettings } from '../../dist/index.js';
import type { SealedEnvelope } from '@arkenivajs/security-crypto';

test('SPID and CIE protected transactions cannot cross identity systems even with the same profile ID, store and external keys', async () => {
  const f = await transactionFixture();
  try {
    const profile = { ...f.profile, system: 'cie' as const, allowedAssurance: ['cie-l2' as const] },
      cie = new FederationTransactions(
        capture({ ...f.settings, profiles: [profile] }, 'test', 'cie'),
        profile.profileId,
        f.crypto,
      ),
      spidState = await f.runtime.run((call) => f.first.create(call, f.input)),
      cieState = await f.runtime.run((call) =>
        cie.create(call, { ...f.input, assurance: 'cie-l2' }),
      );
    await assert.rejects(
      () => f.runtime.run((call) => cie.consume(call, spidState.transactionId, spidState.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
    await assert.rejects(
      () => f.runtime.run((call) => f.first.consume(call, cieState.transactionId, cieState.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(f.claims.size, 0);
    const [first, second] = [...f.rows];
    assert.ok(first && second);
    assert.notEqual(JSON.parse(first[0])[0], JSON.parse(second[0])[0]);
    assert.notEqual(first[1].ownerKey, second[1].ownerKey);
    assert.notEqual(first[1].fingerprint, second[1].fingerprint);
    f.rows.set(first[0], second[1]);
    await assert.rejects(
      () =>
        f.runtime.run((call) => f.first.consume(call, spidState.transactionId, spidState.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(f.claims.size, 0);
    f.rows.set(first[0], first[1]);
    assert.equal(
      (
        await f.runtime.run((call) =>
          f.second.consume(call, spidState.transactionId, spidState.issuer),
        )
      ).assurance,
      'spid-l2',
    );
    assert.equal(
      (await f.runtime.run((call) => cie.consume(call, cieState.transactionId, cieState.issuer)))
        .assurance,
      'cie-l2',
    );
    assert.equal(f.claims.size, 2);
    await assert.rejects(
      () => f.runtime.run((call) => cie.consume(call, cieState.transactionId, cieState.issuer)),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});

test('Noncanonical state references are rejected before any cryptographic provider or storage work', async () => {
  const f = await transactionFixture();
  let work = 0;
  try {
    const instance = new FederationTransactions(
      capture(
        {
          ...f.settings,
          stateStore: {
            ...f.settings.stateStore,
            store: {
              ...f.settings.stateStore.store,
              async read() {
                work++;
                throw new Error('Malformed state must not reach storage');
              },
            },
          },
        },
        'test',
      ),
      f.profile.profileId,
      {
        ...f.crypto,
        async hmac() {
          work++;
          throw new Error('Malformed state must not reach key material');
        },
      },
    );
    for (const token of [
      'a'.repeat(64) + '\n',
      'a'.repeat(64) + '\r',
      'a'.repeat(64) + '\u2028',
      'a'.repeat(63),
      'a'.repeat(65),
      'A'.repeat(64),
    ]) {
      await assert.rejects(
        () => f.runtime.run((call) => instance.consume(call, token, f.input.issuer)),
        { code: 'EK_EID_FEDERATION' },
      );
      assert.equal(work, 0);
    }
  } finally {
    await f.close();
  }
});

test('Malformed cryptographic provider outputs cannot create protected state or retain shared byte buffers', async () => {
  const f = await transactionFixture();
  try {
    for (const value of [
      new Uint8Array(31),
      new Uint8Array(33),
      new Uint8Array(new SharedArrayBuffer(32)),
      'not-bytes',
    ]) {
      const instance = new FederationTransactions(
        capture(f.settings, 'test'),
        f.profile.profileId,
        {
          ...f.crypto,
          async hmac() {
            return value as Uint8Array;
          },
        },
      );
      await assert.rejects(() => f.runtime.run((call) => instance.create(call, f.input)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.equal(f.rows.size, 0);
    }
    const original = await f.crypto.encrypt(
      Buffer.from('Synthetic provider envelope'),
      f.settings.stateEncryptionKeyRefs![0]!,
    );
    for (const mutation of [
      { version: 2 },
      { algorithm: 'unsupported' },
      { keyId: '' },
      { nonce: new Uint8Array(11) },
      { tag: new Uint8Array(15) },
      { ciphertext: new Uint8Array(16385) },
      { tag: new Uint8Array(new SharedArrayBuffer(16)) },
    ]) {
      const instance = new FederationTransactions(
        capture(f.settings, 'test'),
        f.profile.profileId,
        {
          ...f.crypto,
          async encrypt() {
            return { ...original, ...mutation } as SealedEnvelope;
          },
        },
      );
      await assert.rejects(() => f.runtime.run((call) => instance.create(call, f.input)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.equal(f.rows.size, 0);
    }
  } finally {
    await f.close();
  }
});

test('Encoded state budgets and rejected or malformed persistence receipts never return a transaction', async () => {
  const f = await transactionFixture();
  let writes = 0;
  try {
    const limited = f.instance({
      ...f.settings,
      policy: { ...f.settings.policy, maxInputBytes: 100 },
      stateStore: {
        ...f.settings.stateStore,
        store: {
          ...f.settings.stateStore.store,
          async compareAndSet() {
            writes++;
            throw new Error('Oversized state must not reach persistence');
          },
        },
      },
    });
    await assert.rejects(() => f.runtime.run((call) => limited.create(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(writes, 0);
    assert.equal(f.rows.size, 0);
    for (const receipt of [
      { committed: false },
      { committed: true, version: '' },
      { committed: true, version: 42 },
    ]) {
      const instance = f.instance({
        ...f.settings,
        stateStore: {
          ...f.settings.stateStore,
          store: {
            ...f.settings.stateStore.store,
            async compareAndSet() {
              writes++;
              return receipt as { committed: boolean; version?: string };
            },
          },
        },
      });
      await assert.rejects(
        () =>
          f.runtime.run((call) =>
            instance.create(call, {
              issuer: f.input.issuer,
              assurance: f.input.assurance,
              returnPath: f.input.returnPath,
            }),
          ),
        { code: 'EK_EID_FEDERATION' },
      );
    }
    assert.equal(writes, 3);
    assert.equal(f.rows.size, 0);
    assert.equal(f.claims.size, 0);
  } finally {
    await f.close();
  }
});

test('An omitted pre-session tenant hint remains absent after actual encrypted single-use state consumption', async () => {
  const f = await transactionFixture();
  try {
    const created = await f.runtime.run((call) =>
        f.first.create(call, {
          issuer: f.input.issuer,
          assurance: f.input.assurance,
          returnPath: f.input.returnPath,
        }),
      ),
      consumed = await f.runtime.run((call) =>
        f.second.consume(call, created.transactionId, created.issuer),
      );
    assert.equal(Object.hasOwn(created, 'tenantHint'), false);
    assert.equal(Object.hasOwn(consumed, 'tenantHint'), false);
    assert.equal(consumed.verifier, created.verifier);
  } finally {
    await f.close();
  }
});

test('Persisted envelope type, byte bounds and canonical encoding fail before any one-use claim', async () => {
  const f = await transactionFixture();
  try {
    const created = await f.runtime.run((call) => f.first.create(call, f.input));
    for (const mutation of [
      { version: 2 },
      { algorithm: 'unsupported' },
      { nonce: '' },
      { nonce: 17 },
      { nonce: '='.repeat(16) },
      { nonce: 'x'.repeat(17) },
      { nonce: 'x'.repeat(15) },
      { tag: 'x'.repeat(21) },
      { ciphertext: 'x'.repeat(22000) },
      { ciphertext: 'not valid encoding' },
    ]) {
      const instance = f.instance({
        ...f.settings,
        stateStore: {
          ...f.settings.stateStore,
          store: {
            ...f.settings.stateStore.store,
            async read(...args) {
              const row = await f.settings.stateStore.store.read(...args);
              return row
                ? { ...row, sealed: { ...(row.sealed as Record<string, unknown>), ...mutation } }
                : null;
            },
          },
        },
      });
      await assert.rejects(
        () =>
          f.runtime.run((call) => instance.consume(call, created.transactionId, created.issuer)),
        { code: 'EK_EID_FEDERATION' },
      );
      assert.equal(f.claims.size, 0);
    }
    assert.equal(
      (await f.runtime.run((call) => f.second.consume(call, created.transactionId, created.issuer)))
        .verifier,
      created.verifier,
    );
  } finally {
    await f.close();
  }
});

test('A profile lifetime that overflows the trusted clock cannot create transaction state', async () => {
  const f = await transactionFixture();
  try {
    const instance = f.instance({
      ...f.settings,
      profiles: [{ ...f.profile, sessionTtlSeconds: Number.MAX_SAFE_INTEGER }],
    });
    await assert.rejects(() => f.runtime.run((call) => instance.create(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(f.rows.size, 0);
    assert.equal(f.claims.size, 0);
  } finally {
    await f.close();
  }
});

test('Readiness probes use independent absent records without creating or claiming authentication state', async () => {
  const f = await transactionFixture(),
    ids: string[] = [];
  try {
    const settings = {
      ...f.settings,
      stateStore: {
        ...f.settings.stateStore,
        store: {
          ...f.settings.stateStore.store,
          async read(namespace: string, id: string) {
            ids.push(id);
            assert.match(id, /^[a-f0-9]{64}$/u);
            return f.settings.stateStore.store.read(namespace, id);
          },
        },
      },
    };
    const instance = f.instance(settings);
    await f.runtime.run((call) => instance.probe(call));
    await f.runtime.run((call) => instance.probe(call));
    assert.equal(ids.length, 2);
    assert.notEqual(ids[0], ids[1]);
    assert.equal(f.rows.size, 0);
    assert.equal(f.claims.size, 0);
    f.state.storage = false;
    await assert.rejects(() => f.runtime.run((call) => instance.probe(call)), {
      code: 'EK_EID_FEDERATION',
    });
    const malformed = f.instance({
      ...settings,
      stateStore: {
        ...settings.stateStore,
        store: {
          ...settings.stateStore.store,
          async read() {
            return { version: 'unexpected' };
          },
        },
      },
    });
    await assert.rejects(() => f.runtime.run((call) => malformed.probe(call)), {
      code: 'EK_EID_FEDERATION',
    });
  } finally {
    await f.close();
  }
});

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
    assert.match(created.transactionId, /^[a-f0-9]{64}$/u);
    assert.match(created.nonce, /^[a-f0-9]{64}$/u);
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
