// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSamlService } from '@arkenivajs/security-saml';
import { createAuthService } from '@arkenivajs/security';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { Identity } from '@arkenivajs/core';
import { securityStateFixture } from './security-state-fixture.js';
import { startMfaIssuer } from './mfa-issuer.js';
import { fixture } from './saml-fixture.js';

for (const requestProfile of [false, true])
  for (const binding of ['redirect', 'post'] as const)
    test(
      `Real PostgreSQL SAML ${binding} ${requestProfile ? 'SPID request profile' : 'generic'} correlation has one winner and canonical tenant mapping ignores asserted tenant hints`,
      { timeout: 20000 },
      async () => {
        const backend = await securityStateFixture(),
          f = await fixture(binding, backend.store),
          issuer = await startMfaIssuer();
        const auth = await createAuthService({
          issuer: issuer.authority,
          audience: 'api://mfa-fixture',
          environment: 'test',
          allowInsecureLoopback: true,
          algorithms: ['RS256'],
          authorizeTenant: (_identity, tenant) => ['tenant-a', 'tenant-b'].includes(tenant),
        });
        const current = new AsyncLocalStorage<Identity>();
        try {
          const local = await auth.verifyBearer(await issuer.bearer({ scope: 'saml:logout' })),
            canonicalTenant = auth.tenantFrom(local);
          await backend.app.sql.execute('main', {
            text: `CREATE TABLE ${backend.schema}.saml_accounts(upstream_issuer TEXT NOT NULL,upstream_subject TEXT NOT NULL,local_issuer TEXT NOT NULL,local_subject TEXT NOT NULL,tenant_id TEXT NOT NULL,PRIMARY KEY(upstream_issuer,upstream_subject,tenant_id))`,
          });
          await backend.app.sql.execute('main', {
            text: `INSERT INTO ${backend.schema}.saml_accounts VALUES(:issuer,:subject,:localIssuer,:localSubject,:tenant)`,
            bindings: {
              issuer: 'https://idp.fixture.invalid/entity',
              subject: 'synthetic-account',
              localIssuer: local.issuer,
              localSubject: local.subject,
              tenant: canonicalTenant.tenantId,
            },
          });
          const authority: NonNullable<typeof f.settings.authority> = {
            async require(action, hint, _context, options) {
              const identity = current.getStore();
              if (!identity || !hint || action !== 'saml.logout')
                throw new Error('An authenticated local logout session is required');
              auth.requireScope(identity, 'saml:logout');
              const tenant = auth.tenantFrom(identity);
              const account = await backend.app.sql.queryOne<{ tenant_id: string }>(
                'main',
                {
                  text: `SELECT tenant_id FROM ${backend.schema}.saml_accounts WHERE upstream_issuer=:issuer AND upstream_subject=:subject AND local_issuer=:localIssuer AND local_subject=:localSubject AND tenant_id=:tenant`,
                  bindings: {
                    issuer: hint.issuer,
                    subject: hint.subject,
                    localIssuer: identity.issuer,
                    localSubject: identity.subject,
                    tenant: tenant.tenantId,
                  },
                },
                options,
              );
              if (!account)
                throw new Error('The current account cannot log out another federated subject');
              return { issuer: hint.issuer, subject: hint.subject, tenant };
            },
          };
          const settings = {
              ...f.settings,
              ...(requestProfile
                ? {
                    authenticationRequestProfile: {
                      kind: 'spid' as const,
                      attributeConsumingServiceIndex: 1,
                    },
                    requestedAuthnContext: {
                      classReferences: ['https://www.spid.gov.it/SpidL2'],
                      comparison: 'exact' as const,
                      acceptedClassReferences: ['https://www.spid.gov.it/SpidL2'],
                    },
                  }
                : {}),
            },
            respond = (id: string) =>
              f.response(id, {
                transformAssertion: (xml) =>
                  requestProfile
                    ? xml
                        .replace(
                          'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
                          'https://www.spid.gov.it/SpidL2',
                        )
                        .replace(
                          'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                          'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                        )
                    : xml,
              }),
            first = createSamlService({ ...settings, authority }),
            second = createSamlService({ ...settings, replayStore: backend.peer, authority });
          const request = await first.beginLogin({ returnPath: '/app' }),
            response = respond(request.requestId),
            expected = { inResponseTo: request.requestId, relayState: request.requestId };
          const outcomes = await Promise.allSettled([
            first.consumeResponse(expected, response),
            second.consumeResponse(expected, response),
          ]);
          const accepted = outcomes.filter((outcome) => outcome.status === 'fulfilled');
          assert.equal(accepted.length, 1);
          assert.equal(outcomes.filter((outcome) => outcome.status === 'rejected').length, 1);
          const identity = accepted[0]!.status === 'fulfilled' ? accepted[0]!.value : undefined;
          assert.ok(identity);
          assert.deepEqual(identity.attributes.tenant_id, ['untrusted-tenant-hint']);
          const mapped = await backend.app.sql.queryOne<{ tenant_id: string }>('main', {
            text: `SELECT tenant_id FROM ${backend.schema}.saml_accounts WHERE upstream_issuer=:issuer AND upstream_subject=:subject`,
            bindings: { issuer: identity.issuer, subject: identity.subject },
          });
          assert.equal(mapped!.tenant_id, 'tenant-a');
          assert.equal(identity.claims.tenant_id, undefined);
          assert.throws(() => auth.tenantFrom(identity));
          await assert.rejects(second.beginLogout({ ...identity }), { code: 'EK_SAML_ASSERTION' });
          const logout = await current.run(local, () =>
            second.beginLogout(structuredClone(identity)),
          );
          const result = await f.logoutResponse(logout.requestId);
          await first.consumeLogoutResponse(result);
          await assert.rejects(second.consumeLogoutResponse(result), { code: 'EK_SAML_REPLAY' });
          const stored = await backend.app.sql.query<{ body: string }>('main', {
            text: `SELECT body FROM ${backend.schema}.security_records`,
          });
          const serialized = JSON.stringify(stored.rows);
          for (const sensitive of [
            response,
            'synthetic-account',
            'private-session-index',
            'Fixture account',
            'BEGIN PRIVATE KEY',
          ])
            assert.ok(
              !serialized.includes(sensitive),
              'Protocol secrets and PII must stay out of replay records',
            );
          const attempt = await first.beginLogin({ returnPath: '/persist-failure' }),
            failed = createSamlService({
              ...settings,
              replayStore: {
                ...backend.peer,
                async compareAndSet() {
                  throw new Error('private-persistence-detail');
                },
              },
            });
          await assert.rejects(
            failed.consumeResponse(
              { inResponseTo: attempt.requestId, relayState: attempt.requestId },
              respond(attempt.requestId),
            ),
            { code: 'EK_BACKEND_UNAVAILABLE' },
          );
          await assert.rejects(
            first.consumeResponse(
              { inResponseTo: attempt.requestId, relayState: attempt.requestId },
              respond(attempt.requestId),
            ),
            { code: 'EK_SAML_REPLAY' },
          );
        } finally {
          await auth.close();
          await issuer.close();
          await f.close();
          await backend.close();
        }
      },
    );
