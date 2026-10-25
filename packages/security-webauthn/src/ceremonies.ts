// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { MfaChallengeRecord, MfaSubjectContext } from '@arkenivajs/core';
import { copyData, freezeData } from '@arkenivajs/core/support';
import type { WebAuthnCeremony, WebAuthnOptionsJSON } from './index.js';
import { data, instant, policyError, storageError } from './runtime.js';
import type { createWebAuthnRuntime, WebAuthnCall } from './runtime.js';

type Runtime = ReturnType<typeof createWebAuthnRuntime>;
type Purpose = Exclude<MfaChallengeRecord['purpose'], 'totp-enroll'>;
type BrowserOptions =
  | Awaited<ReturnType<Runtime['driver']['registrationOptions']>>
  | Awaited<ReturnType<Runtime['driver']['authenticationOptions']>>;

function binding(runtime: Runtime, purpose: Purpose, subject: MfaSubjectContext | undefined) {
  if ((purpose === 'webauthn-passwordless') !== (subject === undefined)) throw policyError();
  return {
    purpose,
    rpId: runtime.rpId,
    issuer: subject?.issuer ?? 'urn:arkenivajs:webauthn:passwordless:' + runtime.rpId,
    ...(subject === undefined
      ? {}
      : {
          subject: subject.subject,
          primarySessionId: subject.primarySessionId,
          ...(subject.tenant === undefined ? {} : { tenantId: subject.tenant.tenantId }),
        }),
  };
}

function challenge(value: unknown): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length !== 43 ||
    !/^[A-Za-z0-9_-]+$/.test(value) ||
    Buffer.from(value, 'base64url').length !== 32 ||
    Buffer.from(value, 'base64url').toString('base64url') !== value
  )
    throw new KitError({ code: 'EK_MFA_INVALID', message: 'Invalid WebAuthn ceremony' });
}

function digest(runtime: Runtime, value: string) {
  challenge(value);
  return createHash('sha256')
    .update(JSON.stringify(['arkenivajs-webauthn-challenge-v1', runtime.ceremonyContext, value]))
    .digest('hex');
}

/** Persist only a domain-separated challenge digest and exact server-owned ceremony binding. */
export async function issueCeremony(
  runtime: Runtime,
  purpose: Purpose,
  subject: MfaSubjectContext | undefined,
  optionsJSON: BrowserOptions,
  call: WebAuthnCall,
): Promise<WebAuthnCeremony> {
  const owner = binding(runtime, purpose, subject);
  const at = call.now();
  if (at + runtime.challengeTtlMs > 253402300799999) throw policyError();
  const expiresAt = new Date(at + runtime.challengeTtlMs).toISOString();
  const captured: WebAuthnOptionsJSON = freezeData({
    ...copyData(optionsJSON),
    timeout: runtime.challengeTtlMs,
  });
  const record: MfaChallengeRecord = Object.freeze({
    id: randomBytes(32).toString('base64url'),
    ...owner,
    challengeDigest: digest(runtime, captured.challenge as string),
    expiresAt,
    createdAt: new Date(at).toISOString(),
  });
  await call.call(async () => {
    if ((await runtime.state.createChallenge(record, call.options)) !== undefined)
      throw storageError();
  });
  return Object.freeze({ ceremonyId: record.id, expiresAt, optionsJSON: captured });
}

/** Claim exactly once before proof verification; an invalid response still consumes the challenge. */
export async function claimCeremony(
  runtime: Runtime,
  purpose: Purpose,
  subject: MfaSubjectContext | undefined,
  id: string,
  call: WebAuthnCall,
): Promise<MfaChallengeRecord> {
  challenge(id);
  const expected = binding(runtime, purpose, subject),
    at = call.now();
  const result = await call.call(() =>
    runtime.state.claimChallenge(
      { id, ...expected, now: new Date(at).toISOString() },
      call.options,
    ),
  );
  if (result === null)
    throw new KitError({
      code: 'EK_MFA_CHALLENGE_EXPIRED',
      message: 'WebAuthn ceremony is unavailable',
    });
  const record = await call.call(async () => {
    const record = data(result, [
      'id',
      'purpose',
      'rpId',
      'issuer',
      'subject',
      'tenantId',
      'primarySessionId',
      'challengeDigest',
      'expiresAt',
      'createdAt',
    ]);
    for (const key of [
      'purpose',
      'rpId',
      'issuer',
      'subject',
      'tenantId',
      'primarySessionId',
    ] as const)
      if (record[key] !== expected[key]) throw storageError();
    if (
      record.id !== id ||
      typeof record.challengeDigest !== 'string' ||
      !/^[a-f0-9]{64}$/.test(record.challengeDigest)
    )
      throw storageError();
    const createdAt = instant(record.createdAt),
      expiresAt = instant(record.expiresAt);
    if (createdAt > at || expiresAt <= createdAt || expiresAt - createdAt > runtime.challengeTtlMs)
      throw storageError();
    return Object.freeze(record) as unknown as MfaChallengeRecord;
  });
  if (instant(record.expiresAt) <= call.now())
    throw new KitError({
      code: 'EK_MFA_CHALLENGE_EXPIRED',
      message: 'WebAuthn ceremony is unavailable',
    });
  return record;
}

/** A matching digest binds the browser challenge to the exact RP/origin/UV/TTL policy snapshot. */
export function requireChallenge(
  runtime: Runtime,
  record: MfaChallengeRecord,
  value: string,
): void {
  const expected = digest(runtime, value);
  if (
    !/^[a-f0-9]{64}$/.test(record.challengeDigest) ||
    !timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(record.challengeDigest, 'hex'))
  )
    throw new KitError({ code: 'EK_MFA_INVALID', message: 'Invalid WebAuthn ceremony' });
}
