// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { verify as verifyOtp } from 'otplib';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';

// Benchmark-only reference: direct upstream verification with the same application-owned backing providers.
// Public applications use the factor services; this reference measures the valid-fixture workload only.
const fail = () => new Error('Native MFA benchmark reference rejected its fixture');
const digest = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const ownerBinding = (owner) => ({
  issuer: owner.issuer,
  subject: owner.subject,
  ...(owner.tenant ? { tenantId: owner.tenant.tenantId } : {}),
});
function owned(record, owner) {
  if (
    !record ||
    record.issuer !== owner.issuer ||
    record.subject !== owner.subject ||
    record.tenantId !== owner.tenant?.tenantId
  )
    throw fail();
}
async function resolve(settings, owner) {
  const current = await settings.subjectAuthority.resolveSubject(owner);
  owned(ownerBinding(current), owner);
  if (
    current.primarySessionId !== owner.primarySessionId ||
    current.authenticatedAt !== owner.authenticatedAt
  )
    throw fail();
  return current;
}
async function limit(settings, owner, action, now, webAuthn) {
  const scopeKey = digest(
    webAuthn
      ? [
          'arkenivajs-webauthn-limit-v1',
          settings.rpId,
          owner.issuer,
          owner.subject,
          owner.tenant?.tenantId ?? null,
        ]
      : ['arkenivajs-totp-limit-v1', owner.issuer, owner.subject, owner.tenant?.tenantId ?? null],
  );
  const result = await settings.rateLimitStore.checkAndRecord({
    scopeKey,
    operation: action,
    maxAttempts: 5,
    windowMs: 60000,
    nowMs: now,
  });
  if (result?.allowed !== true) throw fail();
}
async function evidence(settings, owner, method, now) {
  const result = Object.freeze({
    evidenceId: randomBytes(32).toString('base64url'),
    method,
    assurance: method === 'webauthn' ? 'phishing-resistant' : 'mfa',
    subject: owner.subject,
    verifiedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 60000).toISOString(),
  });
  if (
    (await settings.evidenceStore.recordOnce({
      ...result,
      ...ownerBinding(owner),
      primarySessionId: owner.primarySessionId,
    })) !== undefined
  )
    throw fail();
  return result;
}

/** Direct otplib positive-path reference with real decryption, authority, shared quota, replay CAS and evidence. */
export async function nativeTotpVerification(fixture, candidate, code) {
  const settings = fixture.settings,
    owner = await resolve(settings, candidate),
    at = fixture.clock();
  await settings.subjectAuthority.authorize({ subject: owner, action: 'verify' });
  await limit(settings, owner, 'verify', at, false);
  const factor = await settings.stateStore.getFactor(owner);
  owned(factor, owner);
  const bytes = await settings.secretProtector.open(factor.secret, ownerBinding(owner));
  let secret;
  try {
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) throw fail();
    secret = Buffer.from(bytes).toString('ascii');
    if (!/^[A-Z2-7]{32}$/.test(secret)) throw fail();
  } finally {
    bytes.fill(0);
  }
  const verified = await verifyOtp({
    strategy: 'totp',
    secret,
    token: code,
    algorithm: 'sha1',
    digits: 6,
    period: 30,
    epoch: Math.floor(at / 1000),
    epochTolerance: 30,
  });
  if (
    !verified.valid ||
    !Number.isSafeInteger(verified.timeStep) ||
    Math.abs(verified.timeStep - Math.floor(at / 30000)) > 1 ||
    (factor.lastAcceptedStep !== null && verified.timeStep <= factor.lastAcceptedStep)
  )
    throw fail();
  if (
    (await settings.stateStore.acceptStepIfGreater(
      owner,
      factor.id,
      factor.generation,
      verified.timeStep,
    )) !== true
  )
    throw fail();
  return evidence(settings, owner, 'totp', fixture.clock());
}

/** Direct upstream WebAuthn positive-path reference; SQL calls and one-use state match the service workload. */
export async function nativeWebAuthnVerification(fixture, candidate, ceremony, response) {
  const settings = fixture.settings,
    owner = await resolve(settings, candidate),
    at = fixture.clock();
  await settings.subjectAuthority.authorize({ subject: owner, action: 'finish-authentication' });
  await limit(settings, owner, 'finish-authentication', at, true);
  const claimed = await settings.stateStore.claimChallenge({
    id: ceremony.ceremonyId,
    purpose: 'webauthn-authenticate',
    ...ownerBinding(owner),
    primarySessionId: owner.primarySessionId,
    rpId: settings.rpId,
    now: new Date(at).toISOString(),
  });
  owned(claimed, owner);
  const live = () => {
    if (
      claimed.rpId !== settings.rpId ||
      claimed.primarySessionId !== owner.primarySessionId ||
      claimed.purpose !== 'webauthn-authenticate' ||
      Date.parse(claimed.expiresAt) <= fixture.clock()
    )
      throw fail();
  };
  live();
  // Pin this benchmark reference to the measured source policy; changes fail rather than omit digest checks.
  const policy = digest([
    'arkenivajs-webauthn-policy-v1',
    settings.rpId,
    [...settings.expectedOrigins].sort(),
    'required',
    settings.attestation ?? 'none',
    settings.challengeTtlMs ?? 300000,
  ]);
  const expected = digest([
    'arkenivajs-webauthn-challenge-v1',
    policy,
    ceremony.optionsJSON.challenge,
  ]);
  if (
    typeof claimed.challengeDigest !== 'string' ||
    !/^[a-f0-9]{64}$/.test(claimed.challengeDigest) ||
    !timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(claimed.challengeDigest, 'hex'))
  )
    throw fail();
  const first = await settings.stateStore.getCredential(response.id, settings.rpId);
  owned(first, owner);
  if (first.revokedAt !== undefined) throw fail();
  const verified = await verifyAuthenticationResponse({
    response,
    expectedChallenge: ceremony.optionsJSON.challenge,
    expectedOrigin: [...settings.expectedOrigins],
    expectedRPID: settings.rpId,
    requireUserVerification: true,
    credential: { id: first.credentialId, publicKey: Uint8Array.from(first.publicKey), counter: 0 },
  });
  if (!verified.verified || !verified.authenticationInfo.userVerified) throw fail();
  live();
  const current = await settings.stateStore.getCredential(response.id, settings.rpId);
  owned(current, owner);
  if (
    current.revokedAt !== undefined ||
    current.userHandle !== first.userHandle ||
    current.backupEligible !== first.backupEligible ||
    !Buffer.from(current.publicKey).equals(Buffer.from(first.publicKey))
  )
    throw fail();
  const handle = response.response.userHandle;
  if (handle !== undefined && handle !== null && handle !== current.userHandle) throw fail();
  if (
    (await settings.stateStore.verifyUserHandleBinding({
      credentialId: response.id,
      rpId: settings.rpId,
      ...(handle === undefined ? {} : { userHandle: handle }),
    })) !== true
  )
    throw fail();
  await resolve(settings, owner);
  const info = verified.authenticationInfo;
  if (
    (info.credentialDeviceType === 'multiDevice') !== current.backupEligible ||
    ((current.counter !== 0 || info.newCounter !== 0) && info.newCounter <= current.counter)
  )
    throw fail();
  const updated = await settings.stateStore.advanceCounter({
    credentialId: current.credentialId,
    rpId: settings.rpId,
    ...ownerBinding(owner),
    userHandle: current.userHandle,
    expectedVersion: current.stateVersion,
    previousCounter: current.counter,
    newCounter: info.newCounter,
    backedUp: info.credentialBackedUp,
  });
  if (
    updated.status !== 'updated' ||
    typeof updated.newVersion !== 'string' ||
    !updated.newVersion ||
    updated.newVersion === current.stateVersion
  )
    throw fail();
  const result = await evidence(settings, owner, 'webauthn', fixture.clock());
  const persisted = await settings.stateStore.getCredential(response.id, settings.rpId);
  owned(persisted, owner);
  if (persisted.revokedAt !== undefined || persisted.stateVersion !== updated.newVersion)
    throw fail();
  live();
  return result;
}
