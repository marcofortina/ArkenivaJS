// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext } from '@arkenivajs/core';
import type { WebAuthnCredentialRecord, WebAuthnStateMutationResult } from './contracts.js';
import { data, instant, text, storageError } from './runtime.js';
import type { createWebAuthnRuntime, WebAuthnCall } from './runtime.js';

type Runtime = ReturnType<typeof createWebAuthnRuntime>;
const invalid = () =>
  new KitError({ code: 'EK_MFA_INVALID', message: 'WebAuthn credential is unavailable' });
const conflict = () =>
  new KitError({
    code: 'EK_MFA_CREDENTIAL_CONFLICT',
    message: 'WebAuthn credential state changed',
  });
const byteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength',
)!.get!;

function base64(value: unknown, maximum: number, exact?: number): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > Math.ceil((maximum * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  )
    throw invalid();
  const decoded = Buffer.from(value, 'base64url');
  if (
    decoded.length > maximum ||
    (exact !== undefined && decoded.length !== exact) ||
    decoded.toString('base64url') !== value
  )
    throw invalid();
}

function counter(value: unknown): asserts value is number {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xffffffff)
    throw invalid();
}

/** Snapshot bounded stored metadata without using a provider's mutable public-key view or iterator. */
export function credentialRecord(
  value: unknown,
  rpId: string,
  now: number,
): WebAuthnCredentialRecord {
  try {
    const record = data(value, [
      'credentialId',
      'rpId',
      'issuer',
      'subject',
      'tenantId',
      'userHandle',
      'stateVersion',
      'publicKey',
      'counter',
      'backupEligible',
      'backedUp',
      'transports',
      'registeredAt',
      'revokedAt',
    ]);
    base64(record.credentialId, 1024);
    base64(record.userHandle, 32, 32);
    for (const key of ['issuer', 'subject', 'stateVersion']) text(record[key]);
    if (record.tenantId !== undefined) text(record.tenantId, 128);
    if (
      record.rpId !== rpId ||
      typeof record.backupEligible !== 'boolean' ||
      typeof record.backedUp !== 'boolean' ||
      (record.backedUp && !record.backupEligible)
    )
      throw storageError();
    counter(record.counter);
    const registered = instant(record.registeredAt);
    if (
      registered > now ||
      (record.revokedAt !== undefined &&
        (instant(record.revokedAt) < registered || instant(record.revokedAt) > now))
    )
      throw storageError();
    if (!(record.publicKey instanceof Uint8Array)) throw storageError();
    const size: number = byteLength.call(record.publicKey);
    if (size < 1 || size > 16384) throw storageError();
    const publicKey = new Uint8Array(size);
    Uint8Array.prototype.set.call(publicKey, record.publicKey);
    record.publicKey = publicKey;
    if (record.transports !== undefined) {
      if (!Array.isArray(record.transports) || record.transports.length > 16) throw storageError();
      const transports: string[] = [];
      const fields = Object.getOwnPropertyDescriptors(record.transports);
      if (Reflect.ownKeys(fields).length !== record.transports.length + 1) throw storageError();
      for (let index = 0; index < record.transports.length; index++) {
        const field = fields[String(index)];
        if (!field || !('value' in field)) throw storageError();
        text(field.value, 32);
        transports.push(field.value);
      }
      if (new Set(transports).size !== transports.length) throw storageError();
      record.transports = Object.freeze(transports);
    }
    return Object.freeze(record) as unknown as WebAuthnCredentialRecord;
  } catch {
    throw storageError();
  }
}

export function requireOwner(record: WebAuthnCredentialRecord, subject: MfaSubjectContext): void {
  if (
    record.issuer !== subject.issuer ||
    record.subject !== subject.subject ||
    record.tenantId !== subject.tenant?.tenantId
  )
    throw invalid();
}

/** A global credential lookup does not itself establish account identity. */
export async function loadCredential(
  runtime: Runtime,
  credentialId: string,
  call: WebAuthnCall,
  owner?: MfaSubjectContext,
): Promise<WebAuthnCredentialRecord> {
  base64(credentialId, 1024);
  const value = await call.call(() =>
    runtime.state.getCredential(credentialId, runtime.rpId, call.options),
  );
  if (value === null) throw invalid();
  const record = credentialRecord(value, runtime.rpId, call.now());
  if (record.credentialId !== credentialId) throw storageError();
  if (record.revokedAt !== undefined) throw invalid();
  if (owner !== undefined) requireOwner(record, owner);
  return record;
}

/** An omitted handle uses credential ownership; a supplied handle must match exactly. */
export async function verifyHandleBinding(
  runtime: Runtime,
  record: WebAuthnCredentialRecord,
  userHandle: string | null | undefined,
  call: WebAuthnCall,
): Promise<void> {
  if (userHandle !== undefined && userHandle !== null) {
    base64(userHandle, 32, 32);
    if (userHandle !== record.userHandle) throw invalid();
  }
  if (
    (await call.call(() =>
      runtime.state.verifyUserHandleBinding(
        {
          credentialId: record.credentialId,
          rpId: record.rpId,
          ...(userHandle === undefined ? {} : { userHandle }),
        },
        call.options,
      ),
    )) !== true
  )
    throw invalid();
}

async function mutation(
  call: WebAuthnCall,
  previousVersion: string,
  work: () => Promise<WebAuthnStateMutationResult>,
): Promise<string> {
  const result = await call.call(async () => {
    const receipt = data(await work(), ['status', 'newVersion']);
    if (!['updated', 'conflict', 'revoked', 'not-found'].includes(receipt.status as string))
      throw storageError();
    if (receipt.status === 'updated') {
      text(receipt.newVersion);
      if (receipt.newVersion === previousVersion) throw storageError();
    } else if (receipt.newVersion !== undefined) throw storageError();
    return receipt;
  });
  if (result.status === 'conflict') throw conflict();
  if (result.status !== 'updated') throw invalid();
  return result.newVersion as string;
}

/** Called only with an upstream-verified assertion; every accepted write changes the backend version. */
export async function advanceCredential(
  runtime: Runtime,
  record: WebAuthnCredentialRecord,
  verified: { newCounter: number; backupEligible: boolean; backedUp: boolean },
  call: WebAuthnCall,
): Promise<string> {
  if (record.revokedAt !== undefined) throw invalid();
  counter(verified.newCounter);
  if (
    typeof verified.backupEligible !== 'boolean' ||
    typeof verified.backedUp !== 'boolean' ||
    verified.backupEligible !== record.backupEligible ||
    (verified.backedUp && !verified.backupEligible)
  )
    throw invalid();
  if ((record.counter !== 0 || verified.newCounter !== 0) && verified.newCounter <= record.counter)
    throw new KitError({
      code: 'EK_MFA_COUNTER_REGRESSION',
      message: 'WebAuthn counter did not advance',
    });
  return mutation(call, record.stateVersion, () =>
    runtime.state.advanceCounter(
      Object.freeze({
        credentialId: record.credentialId,
        rpId: record.rpId,
        issuer: record.issuer,
        subject: record.subject,
        ...(record.tenantId === undefined ? {} : { tenantId: record.tenantId }),
        userHandle: record.userHandle,
        expectedVersion: record.stateVersion,
        previousCounter: record.counter,
        newCounter: verified.newCounter,
        backedUp: verified.backedUp,
      }),
      call.options,
    ),
  );
}

/** Revocation competes on the same active credential revision as authentication. */
export async function revokeCredential(
  runtime: Runtime,
  record: WebAuthnCredentialRecord,
  owner: MfaSubjectContext,
  call: WebAuthnCall,
): Promise<void> {
  requireOwner(record, owner);
  if (record.revokedAt !== undefined) throw invalid();
  await mutation(call, record.stateVersion, () =>
    runtime.state.revokeCredential(
      owner,
      runtime.rpId,
      record.credentialId,
      record.stateVersion,
      call.options,
    ),
  );
}
