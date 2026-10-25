// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext, MfaManagementAuthorization } from '@arkenivajs/core';
import type { WebAuthnServiceOptions, WebAuthnPolicyAction } from '../../dist/contracts.js';

/** Authority fault fixture; no production authentication or durable store is implemented here. */
export function runtimeFixture() {
  let at = 1792929600000;
  const subject: MfaSubjectContext = Object.freeze({
    issuer: 'https://identity.example.test',
    subject: 'synthetic-account',
    primarySessionId: 'synthetic-session',
    authenticatedAt: new Date(at).toISOString(),
  });
  const authenticated = new WeakSet<object>([subject]);
  const grants = new WeakSet<object>();
  const denied = new Set<WebAuthnPolicyAction>();
  const strong = new WeakSet<object>([subject]);
  const observed: {
    resolutions: number;
    authorizations: WebAuthnPolicyAction[];
    anonymous: number;
    limits: Array<{
      scopeKey: string;
      operation: string;
      maxAttempts: number;
      windowMs: number;
      nowMs: number;
    }>;
  } = {
    resolutions: 0,
    authorizations: [],
    anonymous: 0,
    limits: [],
  };
  const unused = async (): Promise<never> => {
    throw new Error('Synthetic storage is not configured');
  };
  const options: WebAuthnServiceOptions = {
    rpId: 'example.test',
    rpName: 'Synthetic application',
    expectedOrigins: ['https://example.test'],
    environment: 'test',
    clock: { nowEpochMs: () => at },
    stateStore: {
      ...{ usage: 'test-only' },
      createChallenge: unused,
      claimChallenge: unused,
      discardChallenge: unused,
      listCredentials: unused,
      getCredential: unused,
      getOrCreateUserHandle: unused,
      verifyUserHandleBinding: unused,
      insertCredentialIfAbsent: unused,
      advanceCounter: unused,
      revokeCredential: unused,
    },
    rateLimitStore: {
      ...{ usage: 'test-only' },
      async checkAndRecord(input) {
        observed.limits.push(input);
        return { allowed: true };
      },
    },
    evidenceStore: { ...{ usage: 'test-only' }, recordOnce: unused, consume: unused },
    subjectAuthority: {
      ...{ usage: 'test-only' },
      async resolveSubject(candidate) {
        observed.resolutions++;
        if (!authenticated.has(candidate))
          throw new KitError({
            code: 'EK_AUTH_FORBIDDEN',
            message: 'Synthetic session is not authenticated',
          });
        return candidate;
      },
      async authorize(input) {
        observed.authorizations.push(input.action);
        if (denied.has(input.action))
          throw new KitError({ code: 'EK_AUTH_FORBIDDEN', message: 'Synthetic action is denied' });
        if (
          ['begin-registration', 'finish-registration', 'revoke-credential'].includes(
            input.action,
          ) &&
          !strong.has(input.subject)
        )
          throw new KitError({
            code: 'EK_MFA_ASSURANCE_REQUIRED',
            message: 'Synthetic session needs step-up',
          });
        if (input.action === 'revoke-credential' && !grants.has(input.authorization!))
          throw new KitError({
            code: 'EK_AUTH_FORBIDDEN',
            message: 'Synthetic grant is not trusted',
          });
      },
      async resolvePasswordlessSubject(input) {
        observed.anonymous++;
        return {
          issuer: input.issuer,
          subject: input.subject,
          ...(input.tenantId === undefined ? {} : { tenantId: input.tenantId }),
        };
      },
    },
  };
  const grant: MfaManagementAuthorization = Object.freeze({
    action: 'revoke',
    subject: subject.subject,
    trustedSessionId: subject.primarySessionId,
    verifiedAt: subject.authenticatedAt,
  });
  grants.add(grant);
  return {
    options,
    subject,
    observed,
    authenticated,
    grants,
    grant,
    denied,
    strong,
    now: () => at,
    setTime(value: number) {
      at = value;
    },
  };
}
