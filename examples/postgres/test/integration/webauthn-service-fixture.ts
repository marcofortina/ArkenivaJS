// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext, MfaManagementAuthorization } from '@arkenivajs/core';
import { createWebAuthnService } from '@arkenivajs/security-webauthn';
import type { WebAuthnServiceOptions } from '@arkenivajs/security-webauthn';
import {
  createPostgresWebAuthnTables,
  createPostgresWebAuthnStateStore,
} from '../../dist/webauthn-state-store.js';
import { totpFixture } from './totp-fixture.js';

/** Application-owned OIDC session authority and disposable SQL, never a production identity provider. */
export async function webAuthnServiceFixture(origin: string) {
  const f = await totpFixture(),
    sessions = new WeakMap<MfaSubjectContext, number>(),
    enrollment = new WeakSet<MfaSubjectContext>(),
    grants = new WeakMap<MfaManagementAuthorization, MfaSubjectContext>(),
    accounts = new Map<string, boolean>();
  const account = (value: { issuer: string; subject: string; tenantId?: string }) =>
    JSON.stringify([value.issuer, value.subject, value.tenantId ?? null]);
  const forbidden = () =>
    new KitError({ code: 'EK_AUTH_FORBIDDEN', message: 'Verified application authority required' });
  const resolve = (subject: MfaSubjectContext) => {
    const identity = f.owners.get(subject);
    if (!identity || (sessions.get(subject) ?? 0) <= f.clock()) throw forbidden();
    f.auth.requireScope(identity, 'mfa:manage');
    if (
      identity.subject !== subject.subject ||
      identity.issuer !== subject.issuer ||
      identity.claims.sid !== subject.primarySessionId ||
      (subject.tenant
        ? f.auth.tenantFrom(identity) !== subject.tenant
        : identity.claims.tenant_id !== undefined)
    )
      throw forbidden();
    return subject;
  };
  try {
    await createPostgresWebAuthnTables(f.app.sql, 'main', f.schema);
    const state = createPostgresWebAuthnStateStore(f.app.sql, 'main', f.schema, f.clock);
    const settings: WebAuthnServiceOptions = {
      rpId: new URL(origin).hostname,
      rpName: 'Disposable application',
      expectedOrigins: [origin],
      environment: 'test',
      clock: { nowEpochMs: f.clock },
      stateStore: state,
      rateLimitStore: Object.freeze({ ...f.limiter, usage: 'test-only' }),
      evidenceStore: Object.freeze({ ...f.evidence, usage: 'test-only' }),
      passwordlessEnabled: true,
      subjectAuthority: Object.freeze({
        usage: 'test-only',
        async resolveSubject(subject: MfaSubjectContext) {
          return resolve(subject);
        },
        async authorize(
          input: Parameters<WebAuthnServiceOptions['subjectAuthority']['authorize']>[0],
        ) {
          resolve(input.subject);
          if (
            ['begin-registration', 'finish-registration'].includes(input.action) &&
            !enrollment.has(input.subject)
          )
            throw forbidden();
          if (input.action === 'revoke-credential') {
            if (!input.authorization || grants.get(input.authorization) !== input.subject)
              throw forbidden();
            grants.delete(input.authorization);
          }
        },
        async resolvePasswordlessSubject(
          input: Parameters<
            WebAuthnServiceOptions['subjectAuthority']['resolvePasswordlessSubject']
          >[0],
        ) {
          if (accounts.get(account(input)) !== true) throw forbidden();
          return {
            issuer: input.issuer,
            subject: input.subject,
            ...(input.tenantId === undefined ? {} : { tenantId: input.tenantId }),
          };
        },
      }),
    };
    return {
      ...f,
      state,
      settings,
      service: createWebAuthnService(settings),
      async subject(claims: Record<string, unknown> = {}) {
        const subject = await f.subject(claims);
        sessions.set(subject, f.clock() + 600000);
        accounts.set(
          account({
            issuer: subject.issuer,
            subject: subject.subject,
            ...(subject.tenant ? { tenantId: subject.tenant.tenantId } : {}),
          }),
          true,
        );
        return subject;
      },
      approveEnrollment(subject: MfaSubjectContext) {
        resolve(subject);
        if (f.owners.get(subject)?.claims.acr !== 'urn:fixture:reauthenticated') throw forbidden();
        enrollment.add(subject);
      },
      revokeSession(subject: MfaSubjectContext) {
        sessions.delete(subject);
      },
      disableAccount(subject: MfaSubjectContext) {
        accounts.set(
          account({
            issuer: subject.issuer,
            subject: subject.subject,
            ...(subject.tenant ? { tenantId: subject.tenant.tenantId } : {}),
          }),
          false,
        );
      },
      async management(
        subject: MfaSubjectContext,
        evidenceId: string,
      ): Promise<MfaManagementAuthorization> {
        resolve(subject);
        const proof = await f.evidence.consume({
          evidenceId,
          issuer: subject.issuer,
          subject: subject.subject,
          ...(subject.tenant ? { tenantId: subject.tenant.tenantId } : {}),
          primarySessionId: subject.primarySessionId,
          now: new Date(f.clock()).toISOString(),
        });
        if (!proof || proof.assurance !== 'phishing-resistant') throw forbidden();
        const grant: MfaManagementAuthorization = Object.freeze({
          action: 'revoke',
          subject: subject.subject,
          trustedSessionId: subject.primarySessionId,
          verifiedAt: new Date(f.clock()).toISOString(),
        });
        grants.set(grant, subject);
        return grant;
      },
    };
  } catch (error) {
    await f.close();
    throw error;
  }
}
