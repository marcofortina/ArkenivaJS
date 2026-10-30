// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';

export const passwordPolicy = Object.freeze({
  minLength: 12,
  memoryCostKiB: 8192,
  timeCost: 1,
  parallelism: 1,
  blockBreachedPasswords: false,
});
const nativeOptions = Object.freeze({
  type: argon2.argon2id,
  version: 0x13,
  memoryCost: 8192,
  timeCost: 1,
  parallelism: 1,
  hashLength: 32,
});
/** This controlled policy is a bounded test workload, never target-hardware security calibration. */
export function nativePassword() {
  return {
    async hash(plain) {
      return { scheme: 'argon2id', phc: await argon2.hash(plain, nativeOptions) };
    },
    async verify(plain, stored) {
      const valid = await argon2.verify(stored.phc, plain);
      return { valid, rehashRecommended: valid && argon2.needsRehash(stored.phc, nativeOptions) };
    },
    needsRehash(stored) {
      return argon2.needsRehash(stored.phc, nativeOptions);
    },
  };
}
export function passwordSettings(fixture) {
  const secret = randomBytes(32),
    denied = async () => {
      throw new Error('Reset operations are unavailable in the KDF comparison');
    },
    request =
      (method) =>
      async (...input) => {
        const operation = input.pop(),
          response = await globalThis.fetch(fixture.endpoint, {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'x-owned-provider': fixture.bearer },
            body: JSON.stringify({ method, args: input }),
            signal: operation?.signal ?? AbortSignal.timeout(5000),
          });
        assert.equal(response.status, 200, 'The owned durable KDF budget provider failed');
        return (await response.json()).result;
      };
  return {
    resetStore: {
      securityLevel: 'production',
      operationTimeoutMs: 5000,
      store: {
        read: request('read'),
        compareAndSet: request('compareAndSet'),
        claimOnce: denied,
        atomicBatch: denied,
        listByOwner: denied,
        bumpOwnerEpoch: denied,
        currentOwnerEpoch: denied,
      },
    },
    secretProvider: {
      usage: 'test-only',
      async get() {
        return { bytes: secret, keyVersion: 'one' };
      },
    },
    resetHmacKeyRef: 'owned-comparison-key',
    authority: { usage: 'test-only', require: denied },
    resetCommitter: { usage: 'test-only', commitReset: denied },
    policy: passwordPolicy,
    resetTtlMs: 300000,
    maxResetAttemptsPerHour: 100,
  };
}
export async function verifyPassword(service, fixture) {
  const first = await service.hash(fixture.plain),
    second = await service.hash(fixture.plain);
  assert.notEqual(first.phc, second.phc);
  assert.equal(await argon2.verify(first.phc, fixture.plain), true);
  assert.deepEqual(await service.verify(fixture.plain, first), {
    valid: true,
    rehashRecommended: false,
  });
  assert.deepEqual(await service.verify(fixture.plain + 'x', first), {
    valid: false,
    rehashRecommended: false,
  });
  const legacy = { scheme: 'argon2id', phc: fixture.legacyPhc };
  assert.equal(service.needsRehash(first), false);
  assert.equal(service.needsRehash(legacy), true);
  assert.deepEqual(await service.verify(fixture.plain, legacy), {
    valid: true,
    rehashRecommended: true,
  });
  return {
    checkedHashes: 2,
    checkedVerifications: 3,
    independentSaltVerified: true,
    legacyRehashVerified: true,
  };
}
