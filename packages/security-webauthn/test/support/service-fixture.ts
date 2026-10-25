// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes } from 'node:crypto';
import type { MfaChallengeRecord, MfaEvidenceRecord, MfaSubjectContext } from '@arkenivajs/core';
import type {
  WebAuthnCredentialRecord,
  WebAuthnStateMutationResult,
  WebAuthnServiceOptions,
} from '../../dist/contracts.js';
import { runtimeFixture } from './runtime-fixture.js';

/** Shared atomic simulator for service tests; this is not a durable adapter. */
export function serviceFixture() {
  const f = runtimeFixture(),
    challenges = new Map<string, MfaChallengeRecord>(),
    credentials = new Map<string, WebAuthnCredentialRecord>(),
    handles = new Map<string, string>(),
    evidence = new Map<string, MfaEvidenceRecord>();
  const issuedChallenges = new Set<string>(),
    issuedEvidence = new Set<string>();
  let version = 0;
  const account = (rpId: string, issuer: string, subject: string, tenantId?: string) =>
    JSON.stringify([rpId, issuer, subject, tenantId ?? null]);
  const sameOwner = (
    record: { issuer: string; subject?: string; tenantId?: string },
    owner: MfaSubjectContext,
  ) =>
    record.issuer === owner.issuer &&
    record.subject === owner.subject &&
    record.tenantId === owner.tenant?.tenantId;
  const stateStore: WebAuthnServiceOptions['stateStore'] = {
    ...{ usage: 'test-only' },
    async createChallenge(record) {
      if (issuedChallenges.has(record.id)) throw new Error('Synthetic challenge already exists');
      issuedChallenges.add(record.id);
      challenges.set(record.id, structuredClone(record));
    },
    async claimChallenge(input) {
      const record = challenges.get(input.id);
      if (
        !record ||
        ['purpose', 'rpId', 'issuer', 'subject', 'tenantId', 'primarySessionId'].some(
          (key) => record[key as keyof MfaChallengeRecord] !== input[key as keyof typeof input],
        )
      )
        return null;
      challenges.delete(input.id);
      return Date.parse(record.expiresAt) <= Date.parse(input.now) ? null : structuredClone(record);
    },
    async discardChallenge(id) {
      challenges.delete(id);
    },
    async listCredentials(owner, rpId) {
      return [...credentials.values()]
        .filter(
          (record) =>
            record.rpId === rpId && sameOwner(record, owner) && record.revokedAt === undefined,
        )
        .map((record) => structuredClone(record));
    },
    async getCredential(id, rpId) {
      const record = credentials.get(id);
      return record?.rpId === rpId ? structuredClone(record) : null;
    },
    async getOrCreateUserHandle(owner, rpId) {
      const key = account(rpId, owner.issuer, owner.subject, owner.tenant?.tenantId);
      let handle = handles.get(key);
      if (!handle) {
        handle = randomBytes(32).toString('base64url');
        handles.set(key, handle);
      }
      return handle;
    },
    async verifyUserHandleBinding(input) {
      const record = credentials.get(input.credentialId);
      return (
        record?.rpId === input.rpId &&
        handles.get(account(record.rpId, record.issuer, record.subject, record.tenantId)) ===
          record.userHandle &&
        (input.userHandle == null || input.userHandle === record.userHandle)
      );
    },
    async insertCredentialIfAbsent(record) {
      if (credentials.has(record.credentialId)) return false;
      if (
        handles.get(account(record.rpId, record.issuer, record.subject, record.tenantId)) !==
        record.userHandle
      )
        throw new Error('Synthetic account binding is unavailable');
      credentials.set(
        record.credentialId,
        structuredClone({ ...record, stateVersion: 'backend-' + ++version }),
      );
      return true;
    },
    async advanceCounter(input): Promise<WebAuthnStateMutationResult> {
      const record = credentials.get(input.credentialId);
      if (!record || record.rpId !== input.rpId) return { status: 'not-found' };
      if (record.revokedAt !== undefined) return { status: 'revoked' };
      if (
        record.stateVersion !== input.expectedVersion ||
        record.counter !== input.previousCounter ||
        record.issuer !== input.issuer ||
        record.subject !== input.subject ||
        record.tenantId !== input.tenantId ||
        record.userHandle !== input.userHandle
      )
        return { status: 'conflict' };
      const newVersion = 'backend-' + ++version;
      credentials.set(record.credentialId, {
        ...record,
        stateVersion: newVersion,
        counter: input.newCounter,
        backedUp: input.backedUp,
      });
      return { status: 'updated', newVersion };
    },
    async revokeCredential(owner, rpId, id, expectedVersion): Promise<WebAuthnStateMutationResult> {
      const record = credentials.get(id);
      if (!record || record.rpId !== rpId) return { status: 'not-found' };
      if (record.revokedAt !== undefined) return { status: 'revoked' };
      if (record.stateVersion !== expectedVersion || !sameOwner(record, owner))
        return { status: 'conflict' };
      const newVersion = 'backend-' + ++version;
      credentials.set(id, {
        ...record,
        stateVersion: newVersion,
        revokedAt: new Date(f.now()).toISOString(),
      });
      for (const [key, ceremony] of challenges)
        if (ceremony.rpId === rpId && sameOwner(ceremony, owner)) challenges.delete(key);
      return { status: 'updated', newVersion };
    },
  };
  const evidenceStore: WebAuthnServiceOptions['evidenceStore'] = {
    ...{ usage: 'test-only' },
    async recordOnce(record) {
      if (issuedEvidence.has(record.evidenceId))
        throw new Error('Synthetic evidence already exists');
      issuedEvidence.add(record.evidenceId);
      evidence.set(record.evidenceId, structuredClone(record));
    },
    async consume(input) {
      const record = evidence.get(input.evidenceId);
      if (
        !record ||
        record.issuer !== input.issuer ||
        record.subject !== input.subject ||
        record.tenantId !== input.tenantId ||
        record.primarySessionId !== input.primarySessionId ||
        Date.parse(record.expiresAt) <= Date.parse(input.now)
      )
        return null;
      evidence.delete(input.evidenceId);
      return structuredClone(record);
    },
  };
  const options: WebAuthnServiceOptions = { ...f.options, stateStore, evidenceStore };
  return { ...f, options, challenges, credentials, handles, evidence };
}
