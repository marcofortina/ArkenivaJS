// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { MfaSubjectContext, MfaManagementAuthorization } from '@arkenivajs/core';
import { createHmac } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { TotpServiceOptions, TotpRecoveryProofInput } from '../../dist/index.js';

export function runtimeFixture() {
  let time = 1800000000000,
    active = 'first';
  const subject = Object.freeze({
    issuer: 'https://issuer.example.test',
    subject: 'synthetic-account',
    primarySessionId: 'session-a',
    authenticatedAt: new Date(time).toISOString(),
  });
  const denied = new Set<string>();
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
  const mac = (version: string, input: TotpRecoveryProofInput) => {
    const key = keys.get(version);
    if (!key || key.byteLength < 32 || key.byteLength > 64)
      throw new Error('Synthetic missing key');
    return (
      'v1:' +
      version +
      ':' +
      createHmac('sha256', key)
        .update(
          JSON.stringify([
            'v1',
            'arkenivajs-totp-recovery',
            version,
            input.issuer,
            input.tenantId ?? null,
            input.subject,
            input.factorId,
            input.code,
          ]),
        )
        .digest('hex')
    );
  };
  const options: TotpServiceOptions = {
    issuer: 'Synthetic Company',
    environment: 'test',
    clock: { nowEpochMs: () => time },
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
    subjectAuthority: {
      usage: 'test-only',
      async resolveSubject(value) {
        if (!owners.has(value))
          throw new KitError({ code: 'EK_AUTH_FORBIDDEN', message: 'Unknown synthetic session' });
        return value;
      },
      async authorize({ subject: value, action, authorization }) {
        if (!owners.has(value) || denied.has(action))
          throw new KitError({ code: 'EK_AUTH_FORBIDDEN', message: 'Synthetic action denied' });
        const sensitive = ['begin-enrollment', 'read-enrollment-qr', 'confirm-enrollment'].includes(
          action,
        );
        if (
          (sensitive && !strong.has(value)) ||
          (authorization !== undefined && !grants.delete(authorization))
        )
          throw new KitError({
            code: 'EK_MFA_POLICY',
            message: 'Synthetic reauthentication required',
          });
      },
    },
    recoveryHmac: {
      algorithm: 'HMAC-SHA256',
      securityLevel: 'test-only',
      async createVerifier(input) {
        return mac(active, input);
      },
      async candidateVerifiers(input) {
        if (!keys.has(active)) throw new Error('Synthetic missing key');
        return [...keys.keys()]
          .filter((id) => id === active || id === 'first')
          .map((id) => mac(id, input));
      },
    },
  };
  return {
    options,
    denied,
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
