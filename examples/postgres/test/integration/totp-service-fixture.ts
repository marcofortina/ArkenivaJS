// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext, MfaManagementAuthorization } from '@arkenivajs/core';
import { createTotpService } from '@arkenivajs/security-totp';
import type { TotpServiceOptions } from '@arkenivajs/security-totp';
import { totpFixture } from './totp-fixture.js';

/** Independent application authority using actual OIDC provenance and durable evidence consumption. */
export async function totpServiceFixture() {
  const f = await totpFixture(),
    permitted = new WeakMap<MfaSubjectContext, Set<string>>(),
    grants = new WeakMap<MfaManagementAuthorization, MfaSubjectContext>(),
    keys = new Map([['first', randomBytes(32)]]);
  let active = 'first';
  const resolve = (subject: MfaSubjectContext) => {
    const identity = f.owners.get(subject);
    if (!identity) return null;
    try {
      f.auth.requireScope(identity, 'mfa:manage');
      if (
        (subject.tenant
          ? f.auth.tenantFrom(identity) !== subject.tenant
          : identity.claims.tenant_id !== undefined) ||
        identity.subject !== subject.subject ||
        identity.issuer !== subject.issuer ||
        identity.claims.sid !== subject.primarySessionId
      )
        return null;
      return subject;
    } catch {
      return null;
    }
  };
  const settings: TotpServiceOptions = {
    issuer: 'Synthetic Company',
    environment: 'test',
    clock: f.clock,
    stateStore: f.state,
    rateLimitStore: Object.freeze({ ...f.limiter, usage: 'test-only' }),
    secretProtector: Object.freeze({ ...f.protector, usage: 'test-only' }),
    evidenceStore: Object.freeze({ ...f.evidence, usage: 'test-only' }),
    trustPolicy: {
      usage: 'test-only',
      async resolveSubject(subject) {
        return resolve(subject);
      },
      async authorize(subject, input) {
        if (!resolve(subject)) return false;
        return input.authorization === undefined
          ? permitted.get(subject)?.has(input.action) === true
          : grants.get(input.authorization) === subject &&
              input.authorization.action === input.action;
      },
    },
    recoveryCodeHmac: {
      algorithm: 'HMAC-SHA256',
      keyProvider: {
        usage: 'test-only',
        async currentKeyId() {
          return active;
        },
        async resolveKey(version) {
          const key = keys.get(version);
          if (!key) throw new Error('Synthetic external key unavailable');
          return key;
        },
      },
    },
  };
  return {
    ...f,
    settings,
    service: createTotpService(settings),
    approveReauthentication(subject: MfaSubjectContext, action: 'enroll' | 'replace') {
      const identity = f.owners.get(subject);
      // Only this verified fixture issuer's exact signed reauthentication policy is recognized.
      if (
        !resolve(subject) ||
        identity?.claims.acr !== 'urn:fixture:reauthenticated' ||
        f.clock() - Date.parse(subject.authenticatedAt) > 60000
      )
        throw new KitError({
          code: 'EK_MFA_POLICY',
          message: 'Trusted reauthentication is required',
        });
      const actions = permitted.get(subject) ?? new Set<string>();
      actions.add(action);
      permitted.set(subject, actions);
    },
    async management(
      subject: MfaSubjectContext,
      action: 'disable' | 'recovery-codes',
      evidenceId: string,
    ) {
      if (!resolve(subject)) throw new Error('Verified fixture owner required');
      const proof = await f.evidence.consume({
        evidenceId,
        issuer: subject.issuer,
        subject: subject.subject,
        ...(subject.tenant ? { tenantId: subject.tenant.tenantId } : {}),
        primarySessionId: subject.primarySessionId,
        now: new Date(f.clock()).toISOString(),
      });
      if (!proof || proof.assurance !== 'mfa')
        throw new Error('Consumed factor evidence is required');
      const grant = Object.freeze({
        action,
        subject: subject.subject,
        trustedSessionId: subject.primarySessionId,
        verifiedAt: new Date(f.clock()).toISOString(),
      });
      grants.set(grant, subject);
      return grant;
    },
    rotateRecoveryKey() {
      active = 'second';
      keys.set(active, randomBytes(32));
    },
    workerRecoveryKey(version: string) {
      const key = keys.get(version);
      if (!key) throw new Error('Synthetic worker key unavailable');
      return new Uint8Array(key);
    },
    removeRecoveryKey(version: string) {
      keys.get(version)?.fill(0);
      keys.delete(version);
    },
    async close() {
      try {
        await f.close();
      } finally {
        for (const key of keys.values()) key.fill(0);
        keys.clear();
      }
    },
  };
}
