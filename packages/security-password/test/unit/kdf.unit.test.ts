// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';
import { KitError } from '@arkenivajs/core';
import { createKdf } from '../../dist/kdf.js';
import type { KdfCall } from '../../dist/kdf.js';
import { passwordPolicy } from '../../dist/validation.js';

const call: KdfCall = {
  check() {},
  async step(_code, work) {
    return work();
  },
};
const password = () => randomBytes(24).toString('base64url');

test('Native Argon2id uses independently salted PHC hashes and verifies without exposing plaintext', async () => {
  const policy = passwordPolicy({ blockBreachedPasswords: false }),
    kdf = createKdf(policy),
    plain = password();
  try {
    await kdf.bootstrap(call);
    const a = await kdf.hash(plain, undefined, call),
      b = await kdf.hash(plain, undefined, call);
    assert.notEqual(a.phc, b.phc);
    assert.ok(!a.phc.includes(plain));
    assert.equal(await argon2.verify(a.phc, plain), true);
    assert.deepEqual(await kdf.verify(plain, a, call), { valid: true, rehashRecommended: false });
    assert.deepEqual(await kdf.verify(password(), a, call), {
      valid: false,
      rehashRecommended: false,
    });
    assert.equal(kdf.needsRehash(a), false);
    const old = {
      scheme: 'argon2id' as const,
      phc: await argon2.hash(plain, {
        type: argon2.argon2id,
        memoryCost: 8192,
        timeCost: 1,
        parallelism: 1,
      }),
    };
    assert.equal(kdf.needsRehash(old), true);
    assert.deepEqual(await kdf.verify(plain, old, call), { valid: true, rehashRecommended: true });
  } finally {
    kdf.close();
  }
});

test('Malformed and hostile PHC allocation requests receive bounded dummy verification', async () => {
  const kdf = createKdf(passwordPolicy({ memoryCostKiB: 8192, timeCost: 1, parallelism: 1 }));
  try {
    await kdf.bootstrap(call);
    const plain = password(),
      stored = await kdf.hash(plain, undefined, call);
    for (const phc of [
      'invalid',
      stored.phc.replace('m=8192', 'm=4294967295'),
      stored.phc.replace('t=1', 't=999999'),
      stored.phc.replace('p=1', 'p=128'),
      stored.phc.replace('m=8192', 'm=0'),
      stored.phc.replace('m=8192', 'm=1'),
      stored.phc.replace('m=8192', 'm=8192,m=8192'),
      stored.phc.replace('argon2id', 'argon2d'),
      stored.phc.replace('v=19', 'v=99'),
    ]) {
      assert.deepEqual(await kdf.verify(plain, { scheme: 'argon2id', phc }, call), {
        valid: false,
        rehashRecommended: false,
      });
      assert.equal(kdf.needsRehash({ scheme: 'argon2id', phc }), true);
    }
    await assert.rejects(kdf.verify(plain, { scheme: 'argon2id', phc: 'x'.repeat(1025) }, call));
  } finally {
    kdf.close();
  }
});

test('KDF has two physical permits without a queue and preserves byte-exact passwords', async () => {
  const kdf = createKdf(passwordPolicy({ memoryCostKiB: 8192, timeCost: 1, parallelism: 1 }));
  let entered = 0,
    ready!: () => void,
    release!: () => void;
  const started = new Promise<void>((resolve) => {
      ready = resolve;
    }),
    held = new Promise<void>((resolve) => {
      release = resolve;
    });
  const blocked: KdfCall = {
    check() {},
    async step(_code, work) {
      if (++entered === 2) ready();
      await held;
      return work();
    },
  };
  try {
    await kdf.bootstrap(call);
    const outcomes = Promise.all([
      kdf.hash(password(), undefined, blocked),
      kdf.hash(password(), undefined, blocked),
    ]);
    await started;
    await assert.rejects(
      kdf.hash(password(), undefined, call),
      (error) => error instanceof KitError && error.code === 'EK_BACKEND_UNAVAILABLE',
    );
    release();
    await outcomes;
    const plain = 'Correct Unicode e\u0301 with spaces',
      stored = await kdf.hash(plain, undefined, call);
    assert.equal((await kdf.verify(plain, stored, call)).valid, true);
    assert.equal((await kdf.verify(plain.normalize('NFC'), stored, call)).valid, false);
    await assert.rejects(
      kdf.hash('short', undefined, call),
      (error) => error instanceof KitError && error.code === 'EK_PASSWORD_POLICY',
    );
    await assert.rejects(kdf.hash(password(), { timeCost: 0 }, call));
    kdf.close();
    await assert.rejects(kdf.hash(password(), undefined, call));
    assert.throws(() => kdf.needsRehash(stored));
  } finally {
    release();
    kdf.close();
  }
});
