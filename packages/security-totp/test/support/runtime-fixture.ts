// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { MfaSubjectContext, MfaManagementAuthorization } from '@arkenivajs/core';
import type { TotpServiceOptions } from '../../dist/index.js';

export function runtimeFixture() {
  let time = 1800000000000,
    active = 'first';
  const subject = Object.freeze({
    issuer: 'https://issuer.example.test',
    subject: 'synthetic-account',
    primarySessionId: 'session-a',
    authenticatedAt: new Date(time).toISOString(),
  });
  const owners = new WeakSet<MfaSubjectContext>([subject]);
  const grants = new WeakSet<MfaManagementAuthorization>();
  const strong = new WeakSet<MfaSubjectContext>();
  // Public test-vector key, restricted to a test-only secret provider.
  const keys = new Map([
    ['first', new Uint8Array(32).fill(11)],
    ['second', new Uint8Array(32).fill(12)],
  ]);
  const unavailable = async (): Promise<never> => {
    throw new Error('Unconfigured unit test storage');
  };
  const options: TotpServiceOptions = {
    issuer: 'Synthetic Company',
    environment: 'test',
    clock: () => time,
    stateStore: {
      usage: 'test-only',
      createChallenge: unavailable,
      claimChallenge: unavailable,
      discardChallenge: unavailable,
      putPending: unavailable,
      getPending: unavailable,
      activatePending: unavailable,
      getFactor: unavailable,
      acceptStepIfGreater: unavailable,
      revokeFactor: unavailable,
      replaceRecoveryHashes: unavailable,
      consumeRecoveryHash: unavailable,
    },
    rateLimitStore: { usage: 'test-only', checkAndRecord: unavailable },
    secretProtector: { usage: 'test-only', seal: unavailable, open: unavailable },
    evidenceStore: { usage: 'test-only', recordOnce: unavailable, consume: unavailable },
    trustPolicy: {
      usage: 'test-only',
      async resolveSubject(value) {
        return owners.has(value) ? value : null;
      },
      async authorize(value, input) {
        return (
          owners.has(value) &&
          (input.authorization === undefined ? strong.has(value) : grants.has(input.authorization))
        );
      },
    },
    recoveryCodeHmac: {
      algorithm: 'HMAC-SHA256',
      keyProvider: {
        usage: 'test-only',
        async currentKeyId() {
          return active;
        },
        async resolveKey(id) {
          const value = keys.get(id);
          if (!value) throw new Error('Synthetic missing key');
          return value;
        },
      },
    },
  };
  return {
    options,
    subject,
    owners,
    grants,
    strong,
    keys,
    setTime(value: number) {
      time = value;
    },
    rotate() {
      active = 'second';
    },
  };
}
