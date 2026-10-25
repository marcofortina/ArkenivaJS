// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createApplication, KitError } from '@arkenivajs/core';
import type {
  Identity,
  MfaEvidenceRecord,
  MfaManagementAuthorization,
  MfaSubjectContext,
} from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { createAuthService } from '@arkenivajs/security';
import {
  createPostgresMfaEvidenceStore,
  createPostgresMfaEvidenceTable,
} from '../../dist/mfa-evidence-store.js';
import { startMfaIssuer } from './mfa-issuer.js';

const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
const invalid = () => new KitError({ code: 'EK_MFA_INVALID', message: 'MFA handoff rejected' });
const recent = (seconds: unknown, maxAgeMs: number) =>
  typeof seconds === 'number' &&
  Number.isSafeInteger(seconds) &&
  seconds > 0 &&
  seconds * 1000 <= Date.now() &&
  Date.now() - seconds * 1000 <= maxAgeMs;

test(
  'Only an application authority consuming bound evidence can issue accepted step-up proof',
  { timeout: 20000 },
  async () => {
    assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
    assert.ok(process.env.DATABASE_URL, 'DATABASE_URL is required');
    const issuer = await startMfaIssuer();
    let auth: Awaited<ReturnType<typeof createAuthService>> | undefined;
    let app: Awaited<ReturnType<typeof createApplication>> | undefined;
    const schema = 'mfa_' + randomBytes(12).toString('hex');
    let created = false;
    try {
      const verifier = await createAuthService({
        issuer: issuer.authority,
        audience: 'api://mfa-fixture',
        algorithms: ['RS256'],
        environment: 'test',
        allowInsecureLoopback: true,
        // This fixture issuer alone controls this exact signed policy claim.
        assuranceResolver(identity) {
          return identity.issuer === issuer.authority &&
            identity.claims.acr === 'urn:example:local-mfa' &&
            recent(identity.claims.factor_verified_at, 60000)
            ? 'mfa'
            : 'single-factor';
        },
      });
      auth = verifier;
      app = await createApplication({
        service: { name: 'mfa-authority-example', version: '1.0.0', environment: 'test' },
        plugins: [postgresPlugin()],
        databases: {
          main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 2 },
        },
      });
      await app.start();
      await app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
      created = true;
      await createPostgresMfaEvidenceTable(app.sql, 'main', schema);
      const store = createPostgresMfaEvidenceStore(app.sql, 'main', schema);

      // This application requires a tenant and primary authentication within five minutes.
      const subjectFrom = (identity: Identity): MfaSubjectContext => {
        const tenant = verifier.tenantFrom(identity);
        const session = identity.claims.sid;
        if (
          typeof session !== 'string' ||
          !/^[A-Za-z0-9._:-]{1,128}$/.test(session) ||
          !recent(identity.claims.auth_time, 300000)
        )
          throw invalid();
        return Object.freeze({
          issuer: identity.issuer,
          subject: identity.subject,
          tenant,
          primarySessionId: session,
          authenticatedAt: new Date((identity.claims.auth_time as number) * 1000).toISOString(),
        });
      };
      const primaryBearer = await issuer.bearer();
      const primary = await verifier.verifyBearer(primaryBearer);
      const subject = subjectFrom(primary);
      assert.equal(verifier.isVerifiedTenant(subject.tenant), true);
      assert.throws(() => subjectFrom({ ...primary }), code('EK_TENANT_UNVERIFIED'));
      assert.throws(
        () => verifier.requireAssurance(primary, 'mfa'),
        code('EK_MFA_ASSURANCE_REQUIRED'),
      );

      // A trusted factor producer is simulated here; no OTP or assertion is verified.
      const proof: MfaEvidenceRecord = {
        evidenceId: 'authority-handoff',
        method: 'totp',
        assurance: 'mfa',
        issuer: subject.issuer,
        subject: subject.subject,
        tenantId: subject.tenant!.tenantId,
        primarySessionId: subject.primarySessionId,
        verifiedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60000).toISOString(),
      };
      await store.recordOnce(proof);
      const consume = async (identity: Identity) => {
        const owner = subjectFrom(identity);
        const record = await store.consume({
          evidenceId: proof.evidenceId,
          issuer: owner.issuer,
          subject: owner.subject,
          tenantId: owner.tenant!.tenantId,
          primarySessionId: owner.primarySessionId,
          now: new Date().toISOString(),
        });
        if (!record) throw invalid();
        return record;
      };
      for (const claims of [
        { sub: 'other-account' },
        { tenant_id: 'tenant-b' },
        { sid: 'session-b' },
        { sid: '' },
        { auth_time: Math.floor(Date.now() / 1000) - 301 },
        { auth_time: Math.floor(Date.now() / 1000) + 60 },
      ]) {
        const foreign = await verifier.verifyBearer(await issuer.bearer(claims));
        await assert.rejects(consume(foreign), code('EK_MFA_INVALID'));
      }
      await assert.rejects(consume({ ...primary }), code('EK_TENANT_UNVERIFIED'));
      await assert.rejects(verifier.verifyBearer(undefined), code('EK_AUTH_REQUIRED'));
      await assert.rejects(
        verifier.verifyBearer(await issuer.bearer({ aud: 'api://foreign' })),
        code('EK_AUTH_INVALID'),
      );

      const consumed = await consume(primary);
      assert.deepEqual(consumed, proof);
      await assert.rejects(consume(primary), code('EK_MFA_INVALID'));
      assert.throws(
        () => verifier.requireAssurance(primary, 'mfa'),
        code('EK_MFA_ASSURANCE_REQUIRED'),
      );
      // Only the independent application issuer creates this new token after durable consumption.
      const upgradedBearer = await issuer.bearer({
        sub: consumed.subject,
        tenant_id: consumed.tenantId,
        sid: consumed.primarySessionId,
        auth_time: primary.claims.auth_time as number,
        acr: 'urn:example:local-mfa',
        factor_verified_at: Math.floor(Date.parse(consumed.verifiedAt) / 1000),
      });
      const upgraded = await verifier.verifyBearer(upgradedBearer);
      verifier.requireAssurance(upgraded, 'mfa');
      assert.throws(
        () => verifier.requireAssurance(upgraded, 'phishing-resistant'),
        code('EK_MFA_ASSURANCE_REQUIRED'),
      );
      assert.throws(
        () => verifier.requireAssurance({ ...upgraded }, 'mfa'),
        code('EK_MFA_ASSURANCE_REQUIRED'),
      );

      const manage = (
        identity: Identity,
        action: MfaManagementAuthorization['action'],
      ): MfaManagementAuthorization => {
        const owner = subjectFrom(identity);
        verifier.requireScope(identity, 'mfa:manage');
        verifier.requireAssurance(identity, 'mfa');
        return Object.freeze({
          action,
          subject: owner.subject,
          trustedSessionId: owner.primarySessionId,
          verifiedAt: new Date().toISOString(),
        });
      };
      for (const action of ['enroll', 'replace', 'disable', 'recovery-codes', 'revoke'] as const) {
        assert.throws(() => manage(primary, action), code('EK_MFA_ASSURANCE_REQUIRED'));
        const decision = manage(upgraded, action);
        assert.equal(decision.action, action);
        assert.equal(decision.subject, proof.subject);
        assert.equal(decision.trustedSessionId, proof.primarySessionId);
        assert.ok(Date.now() - Date.parse(decision.verifiedAt) < 1000);
        assert.equal(Object.isFrozen(decision), true);
      }
      const noScope = await verifier.verifyBearer(
        await issuer.bearer({
          acr: 'urn:example:local-mfa',
          factor_verified_at: Math.floor(Date.now() / 1000),
          scope: '',
        }),
      );
      assert.throws(() => manage(noScope, 'disable'), code('EK_AUTH_FORBIDDEN'));
      for (const claims of [
        { mfa: true, amr: ['mfa', 'otp'] },
        { acr: 'unrecognized', factor_verified_at: Math.floor(Date.now() / 1000) },
        { acr: 'urn:example:local-mfa', factor_verified_at: Math.floor(Date.now() / 1000) - 61 },
        { acr: 'urn:example:local-mfa', factor_verified_at: Math.floor(Date.now() / 1000) + 60 },
      ]) {
        const untrusted = await verifier.verifyBearer(await issuer.bearer(claims));
        assert.throws(() => manage(untrusted, 'disable'), code('EK_MFA_ASSURANCE_REQUIRED'));
      }
      assert.equal((await verifier.verifyBearer(primaryBearer)).assurance, 'single-factor');
    } finally {
      try {
        if (created) await app!.sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
      } finally {
        try {
          await app?.stop();
        } finally {
          try {
            await auth?.close();
          } finally {
            await issuer.close();
          }
        }
      }
    }
  },
);
