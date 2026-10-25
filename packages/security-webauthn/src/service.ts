// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type {
  MfaSubjectContext,
  MfaManagementAuthorization,
  MfaEvidence,
  MfaEvidenceRecord,
  OperationOptions,
} from '@arkenivajs/core';
import type {
  WebAuthnServiceOptions,
  WebAuthnService,
  WebAuthnPolicyAction,
  WebAuthnCredentialRecord,
  WebAuthnCredentialSummary,
} from './contracts.js';
import { createWebAuthnRuntime, policyError, storageError, data, instant } from './runtime.js';
import type { WebAuthnCall } from './runtime.js';
import { readUnverifiedResponse } from './browser-response.js';
import { issueCeremony, claimCeremony, requireChallenge } from './ceremonies.js';
import {
  credentialRecord,
  requireOwner,
  loadCredential,
  verifyHandleBinding,
  advanceCredential,
  revokeCredential,
} from './credentials.js';

const invalid = () =>
  new KitError({ code: 'EK_MFA_INVALID', message: 'WebAuthn factor is unavailable' });
const conflict = () =>
  new KitError({
    code: 'EK_MFA_CREDENTIAL_CONFLICT',
    message: 'WebAuthn credential state changed',
  });
const token = () => randomBytes(32).toString('base64url');

function accountHandle(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length !== 43 ||
    !/^[A-Za-z0-9_-]+$/.test(value) ||
    Buffer.from(value, 'base64url').length !== 32 ||
    Buffer.from(value, 'base64url').toString('base64url') !== value
  )
    throw storageError();
  return value;
}

function summary(record: WebAuthnCredentialRecord): WebAuthnCredentialSummary {
  return Object.freeze({
    credentialId: record.credentialId,
    registeredAt: record.registeredAt,
    backedUp: record.backedUp,
  });
}

function sameCredential(before: WebAuthnCredentialRecord, after: WebAuthnCredentialRecord): void {
  for (const field of [
    'credentialId',
    'rpId',
    'issuer',
    'subject',
    'tenantId',
    'userHandle',
    'backupEligible',
  ] as const)
    if (before[field] !== after[field]) throw conflict();
  if (!Buffer.from(before.publicKey).equals(Buffer.from(after.publicKey))) throw conflict();
}

/**
 * Construct the optional factor service with caller-owned trust/state providers.
 *
 * @param options - Stable RP policy and independent authority, shared state, limiter and evidence providers.
 * @returns The eight factor operations; the application consumes evidence and owns session issuance.
 * @throws An EK_MFA_POLICY error when required configuration or production/test isolation is invalid.
 * @remarks EK-R12-MFA-001 and EK-R12-MFA-002 require immutable account handles and versioned durable writes.
 */
export function createWebAuthnService(options: WebAuthnServiceOptions): WebAuthnService {
  const runtime = createWebAuthnRuntime(options);
  let activeCalls = 0;
  const run = async <T>(
    operation: OperationOptions | undefined,
    work: (call: WebAuthnCall) => Promise<T>,
  ): Promise<T> => {
    if (activeCalls >= 32)
      throw new KitError({
        code: 'EK_MFA_RATE_LIMIT',
        message: 'WebAuthn operation capacity reached',
      });
    activeCalls++;
    let entered = false,
      released = false;
    const release = () => {
      if (!released) {
        released = true;
        activeCalls--;
      }
    };
    try {
      return await runtime.run(operation, async (call) => {
        entered = true;
        try {
          call.check();
          return await work(call);
        } finally {
          release();
        }
      });
    } finally {
      if (!entered) release();
    }
  };
  const ownerFor = async (
    candidate: MfaSubjectContext,
    action: WebAuthnPolicyAction,
    call: WebAuthnCall,
    authorization?: MfaManagementAuthorization,
  ) => {
    const owner = await runtime.resolve(candidate, call);
    await runtime.authorize(owner, action, authorization, call);
    return owner;
  };
  const list = async (owner: MfaSubjectContext, call: WebAuthnCall) => {
    const result = await call.call(() =>
      runtime.state.listCredentials(owner, runtime.rpId, call.options),
    );
    if (!Array.isArray(result)) throw storageError();
    const length = result.length;
    if (!Number.isSafeInteger(length) || length < 0 || length > 100) throw storageError();
    const records: WebAuthnCredentialRecord[] = [],
      ids = new Set<string>();
    for (let index = 0; index < length; index++) {
      const field = Object.getOwnPropertyDescriptor(result, String(index));
      if (!field || !('value' in field)) throw storageError();
      const record = credentialRecord(field.value, runtime.rpId, call.now());
      requireOwner(record, owner);
      if (ids.has(record.credentialId)) throw storageError();
      ids.add(record.credentialId);
      if (record.revokedAt === undefined) records.push(record);
    }
    return records;
  };
  const freshOwner = async (
    owner: MfaSubjectContext,
    call: WebAuthnCall,
    sensitive = false,
    authorizedAt?: number,
  ) => {
    const current = await runtime.resolve(owner, call),
      at = call.now();
    if (
      (sensitive && at - instant(current.authenticatedAt) > 300000) ||
      (authorizedAt !== undefined && (authorizedAt > at || at - authorizedAt > 60000))
    )
      throw policyError();
  };
  const expires = (at: number, duration: number) => {
    if (at + duration > 253402300799999) throw policyError();
    return new Date(at + duration).toISOString();
  };
  const evidence = async (
    owner: { issuer: string; subject: string; tenantId?: string },
    binding: string,
    call: WebAuthnCall,
  ): Promise<MfaEvidence> => {
    const at = call.now();
    const result: MfaEvidence = Object.freeze({
      evidenceId: token(),
      method: 'webauthn',
      assurance: 'phishing-resistant',
      subject: owner.subject,
      verifiedAt: new Date(at).toISOString(),
      expiresAt: expires(at, 60000),
    });
    const record: MfaEvidenceRecord = Object.freeze({
      ...result,
      ...owner,
      primarySessionId: binding,
    });
    await call.call(async () => {
      if ((await runtime.evidence.recordOnce(record, call.options)) !== undefined)
        throw storageError();
    });
    return result;
  };
  const liveCeremony = (record: { expiresAt: string }, call: WebAuthnCall) => {
    if (Date.parse(record.expiresAt) <= call.now())
      throw new KitError({
        code: 'EK_MFA_CHALLENGE_EXPIRED',
        message: 'WebAuthn ceremony is unavailable',
      });
  };
  const assertion = async (
    ceremony: Awaited<ReturnType<typeof claimCeremony>>,
    responseJSON: unknown,
    call: WebAuthnCall,
    owner?: MfaSubjectContext,
  ) => {
    const parsed = readUnverifiedResponse(responseJSON, false);
    requireChallenge(runtime, ceremony, parsed.challenge);
    const initial = await loadCredential(runtime, parsed.credentialId, call, owner);
    call.check();
    // The signed result is checked against the fresh durable counter below, with a version CAS even at zero.
    const verified = await runtime.driver.verifyAuthentication(
      parsed.serialized,
      parsed.challenge,
      { id: initial.credentialId, publicKey: Uint8Array.from(initial.publicKey), counter: 0 },
    );
    call.check();
    liveCeremony(ceremony, call);
    const fresh = await loadCredential(runtime, parsed.credentialId, call, owner);
    sameCredential(initial, fresh);
    await verifyHandleBinding(runtime, fresh, parsed.userHandle, call);
    return { parsed, verified, fresh };
  };
  const checkPersisted = async (
    record: WebAuthnCredentialRecord,
    version: string,
    call: WebAuthnCall,
  ) => {
    const current = await loadCredential(runtime, record.credentialId, call);
    sameCredential(record, current);
    if (current.stateVersion !== version) throw conflict();
  };

  return Object.freeze<WebAuthnService>({
    beginRegistration(subject, operation) {
      return run(operation, async (call) => {
        const owner = await ownerFor(subject, 'begin-registration', call);
        await runtime.limit('begin-registration', owner, call);
        const records = await list(owner, call);
        if (records.length >= 100) throw policyError();
        const handle = accountHandle(
          await call.call(() =>
            runtime.state.getOrCreateUserHandle(owner, runtime.rpId, call.options),
          ),
        );
        const browser = await runtime.driver.registrationOptions(
          Buffer.from(handle, 'base64url'),
          records.map((record) => record.credentialId),
        );
        call.check();
        return issueCeremony(runtime, 'webauthn-register', owner, browser, call);
      });
    },
    finishRegistration(subject, ceremonyId, responseJSON, operation) {
      return run(operation, async (call) => {
        const owner = await ownerFor(subject, 'finish-registration', call);
        await runtime.limit('finish-registration', owner, call);
        const ceremony = await claimCeremony(runtime, 'webauthn-register', owner, ceremonyId, call);
        const parsed = readUnverifiedResponse(responseJSON, true);
        requireChallenge(runtime, ceremony, parsed.challenge);
        call.check();
        const verified = await runtime.driver.verifyRegistration(
          parsed.serialized,
          parsed.challenge,
        );
        call.check();
        liveCeremony(ceremony, call);
        await freshOwner(owner, call, true);
        const handle = accountHandle(
          await call.call(() =>
            runtime.state.getOrCreateUserHandle(owner, runtime.rpId, call.options),
          ),
        );
        // The backend initializes the persisted revision; the candidate marker is never accepted as stored state.
        const candidateVersion = token();
        const record = credentialRecord(
          {
            credentialId: verified.credential.id,
            rpId: runtime.rpId,
            issuer: owner.issuer,
            subject: owner.subject,
            ...(owner.tenant === undefined ? {} : { tenantId: owner.tenant.tenantId }),
            userHandle: handle,
            stateVersion: candidateVersion,
            publicKey: verified.credential.publicKey,
            counter: verified.credential.counter,
            backupEligible: verified.backupEligible,
            backedUp: verified.backedUp,
            ...(verified.credential.transports === undefined
              ? {}
              : { transports: verified.credential.transports }),
            registeredAt: new Date(call.now()).toISOString(),
          },
          runtime.rpId,
          call.now(),
        );
        const inserted = await call.call(() =>
          runtime.state.insertCredentialIfAbsent(record, call.options),
        );
        if (inserted === false) throw conflict();
        if (inserted !== true) throw storageError();
        const saved = await loadCredential(runtime, record.credentialId, call, owner);
        sameCredential(record, saved);
        if (
          saved.stateVersion === candidateVersion ||
          saved.counter !== record.counter ||
          saved.backedUp !== record.backedUp
        )
          throw storageError();
        await verifyHandleBinding(runtime, saved, handle, call);
        liveCeremony(ceremony, call);
        return summary(saved);
      });
    },
    beginAuthentication(subject, operation) {
      return run(operation, async (call) => {
        const owner = await ownerFor(subject, 'begin-authentication', call);
        await runtime.limit('begin-authentication', owner, call);
        const records = await list(owner, call);
        if (records.length === 0) throw invalid();
        const browser = await runtime.driver.authenticationOptions(
          records.map((record) => record.credentialId),
        );
        call.check();
        return issueCeremony(runtime, 'webauthn-authenticate', owner, browser, call);
      });
    },
    finishAuthentication(subject, ceremonyId, responseJSON, operation) {
      return run(operation, async (call) => {
        const owner = await ownerFor(subject, 'finish-authentication', call);
        await runtime.limit('finish-authentication', owner, call);
        const ceremony = await claimCeremony(
          runtime,
          'webauthn-authenticate',
          owner,
          ceremonyId,
          call,
        );
        const { fresh, verified } = await assertion(ceremony, responseJSON, call, owner);
        await freshOwner(owner, call);
        const version = await advanceCredential(runtime, fresh, verified, call);
        const result = await evidence(
          {
            issuer: owner.issuer,
            subject: owner.subject,
            ...(owner.tenant === undefined ? {} : { tenantId: owner.tenant.tenantId }),
          },
          owner.primarySessionId,
          call,
        );
        await checkPersisted(fresh, version, call);
        liveCeremony(ceremony, call);
        return result;
      });
    },
    beginPasswordless(operation) {
      return run(operation, async (call) => {
        if (!runtime.passwordlessEnabled) throw policyError();
        await runtime.limit('begin-passwordless', undefined, call);
        const browser = await runtime.driver.authenticationOptions();
        call.check();
        return issueCeremony(runtime, 'webauthn-passwordless', undefined, browser, call);
      });
    },
    finishPasswordless(ceremonyId, responseJSON, operation) {
      return run(operation, async (call) => {
        if (!runtime.passwordlessEnabled) throw policyError();
        await runtime.limit('finish-passwordless', undefined, call);
        const ceremony = await claimCeremony(
          runtime,
          'webauthn-passwordless',
          undefined,
          ceremonyId,
          call,
        );
        const { fresh, verified, parsed } = await assertion(ceremony, responseJSON, call);
        const owner = await runtime.passwordlessOwner(
          {
            rpId: runtime.rpId,
            credentialId: fresh.credentialId,
            issuer: fresh.issuer,
            subject: fresh.subject,
            ...(fresh.tenantId === undefined ? {} : { tenantId: fresh.tenantId }),
            ...(parsed.userHandle === undefined ? {} : { userHandle: parsed.userHandle }),
          },
          call,
        );
        const version = await advanceCredential(runtime, fresh, verified, call);
        // Pre-session evidence is bound to this consumed authentication transaction, never to caller session data.
        const result = await evidence(owner, ceremonyId, call);
        await checkPersisted(fresh, version, call);
        liveCeremony(ceremony, call);
        return Object.freeze({ ...owner, evidence: result });
      });
    },
    listCredentials(subject) {
      return run(undefined, async (call) => {
        const owner = await ownerFor(subject, 'list-credentials', call);
        await runtime.limit('list-credentials', owner, call);
        return Object.freeze((await list(owner, call)).map(summary));
      });
    },
    revokeCredential(subject, credentialId, authorization, operation) {
      return run(operation, async (call) => {
        const authorizedAt = instant(
          data(authorization, ['action', 'subject', 'trustedSessionId', 'verifiedAt']).verifiedAt,
        );
        const owner = await ownerFor(subject, 'revoke-credential', call, authorization);
        await runtime.limit('revoke-credential', owner, call);
        const record = await loadCredential(runtime, credentialId, call, owner);
        await freshOwner(owner, call, true, authorizedAt);
        await revokeCredential(runtime, record, owner, call);
      });
    },
  });
}
