// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import type { Identity, MfaAssurance, OperationOptions } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { sessionsPlugin, SESSIONS_CAPABILITY } from '@arkenivajs/security-sessions';
import type {
  SessionsPluginSettings,
  SessionService,
  SessionIdentityAuthority,
  IdentitySubject,
  SessionAuthentication,
} from '@arkenivajs/security-sessions';
import { apiKeyFixture } from './api-key-fixture.js';

/** Signed primary identities, durable authentication events and shared PostgreSQL session state. */
export async function sessionFixture(maxSessions = 4) {
  const base = await apiKeyFixture(),
    accounts = new Map<string, { identity: Identity; subject: IdentitySubject; sid: string }>(),
    logoutContext = new AsyncLocalStorage<IdentitySubject>();
  const state = { enabled: true, authorityAvailable: true },
    applications: Awaited<ReturnType<typeof createApplication>>[] = [];
  const binding = (owner: IdentitySubject) =>
    JSON.stringify([owner.issuer, owner.subject, owner.tenant?.tenantId ?? null]);
  const ownerKey = async (owner: IdentitySubject) =>
    createHash('sha256')
      .update(
        await base.settings.hmac.digest(
          'arkenivajs.sessions.owner.v1',
          [owner.issuer, owner.subject, owner.tenant?.tenantId ?? ''],
          base.settings.hmacKeyRef,
        ),
      )
      .digest('hex');
  const accountFor = (identity: Identity) => {
    const tenant = base.auth.tenantFrom(identity);
    if (!base.auth.isVerifiedTenant(tenant) || !state.enabled || !state.authorityAvailable)
      throw new Error('Verified live fixture tenant required');
    return {
      identity,
      subject: { issuer: identity.issuer, subject: identity.subject, tenant },
      sid: String(identity.claims.sid),
    };
  };
  const primaryKey = async (subject: IdentitySubject, sid: string) =>
    createHash('sha256')
      .update(JSON.stringify([await ownerKey(subject), sid]))
      .digest('hex');
  const checkPrimary = async (
    subject: IdentitySubject,
    sid: string,
    options?: OperationOptions,
  ) => {
    if (
      await base.settings.store.store.read(
        'sessions.primary-revoked.v1',
        await primaryKey(subject, sid),
        options,
      )
    )
      throw new Error('Primary session revoked');
  };
  const primary = async (options?: OperationOptions) => {
    const identity = base.currentIdentity();
    if (!identity) throw new Error('Independent primary session required');
    base.auth.requireScope(identity, 'sessions:manage');
    if (
      typeof identity.claims.auth_time !== 'number' ||
      !Number.isSafeInteger(identity.claims.auth_time) ||
      identity.claims.auth_time > Date.now() / 1000 ||
      Date.now() / 1000 - identity.claims.auth_time > 60 ||
      typeof identity.claims.sid !== 'string' ||
      !identity.claims.sid ||
      identity.claims.sid.length > 128
    )
      throw new Error('Recent signed authentication required');
    const account = accountFor(identity);
    await checkPrimary(account.subject, account.sid, options);
    return account;
  };
  const authority: SessionIdentityAuthority & { usage: 'test-only' } = {
    usage: 'test-only',
    async resolveIdentity(input, context, options) {
      if (!state.enabled || !state.authorityAvailable)
        throw new Error('Fixture account unavailable');
      let account: { identity: Identity; subject: IdentitySubject; sid: string },
        event: Readonly<Record<string, unknown>>;
      if (context.operation === 'create') {
        account = await primary(options);
        if (input.issuer !== account.identity.issuer || input.subject !== account.identity.subject)
          throw new Error('Primary identity mismatch');
        const assurance: MfaAssurance =
          account.identity.claims.acr === 'urn:fixture:mfa'
            ? 'mfa'
            : account.identity.claims.acr === 'urn:fixture:phishing-resistant'
              ? 'phishing-resistant'
              : 'single-factor';
        const authenticatedAt = new Date(
          Number(account.identity.claims.auth_time) * 1000,
        ).toISOString();
        event = {
          ownerKey: await ownerKey(account.subject),
          issuer: account.identity.issuer,
          subject: account.identity.subject,
          tenantId: account.subject.tenant?.tenantId,
          sid: account.sid,
          authenticatedAt,
          assurance,
          ...(assurance === 'single-factor' ? {} : { assuredAt: authenticatedAt }),
          expiresAt: new Date(Date.now() + 600000).toISOString(),
        };
        if (
          !(
            await base.settings.store.store.compareAndSet(
              'sessions.authority.v1',
              context.sessionId,
              null,
              event,
              options,
            )
          ).committed
        )
          throw new Error('Authentication event conflict');
      } else {
        const persisted = await base.settings.store.store.read(
          'sessions.authority.v1',
          context.previousSessionId ?? context.sessionId,
          options,
        );
        if (!persisted || persisted.issuer !== input.issuer || persisted.subject !== input.subject)
          throw new Error('Trusted durable authentication event missing');
        event = persisted;
        account = accounts.get(
          JSON.stringify([event.issuer, event.subject, event.tenantId ?? null]),
        )!;
        if (!account || !base.auth.isVerifiedTenant(account.subject.tenant))
          throw new Error('Account session binding changed');
        if (typeof event.sid !== 'string') throw new Error('Primary session binding missing');
        await checkPrimary(account.subject, event.sid, options);
        if (context.operation === 'renew') {
          const { version: _version, ...next } = persisted;
          void _version;
          if (
            !(
              await base.settings.store.store.compareAndSet(
                'sessions.authority.v1',
                context.sessionId,
                null,
                next,
                options,
              )
            ).committed
          )
            throw new Error('Replacement event conflict');
        }
      }
      const claims = Object.fromEntries(
        Object.entries(account.identity.claims).filter(
          ([name]) => !['auth_time', 'acr', 'amr', 'sid'].includes(name),
        ),
      );
      return {
        identity: { ...account.identity, claims, assurance: event.assurance as MfaAssurance },
        subject: account.subject,
        authenticatedAt: String(event.authenticatedAt),
        ...(event.assuredAt ? { assuredAt: String(event.assuredAt) } : {}),
      } satisfies SessionAuthentication;
    },
    async require(action, hint, context, options) {
      if (!state.enabled || !state.authorityAvailable)
        throw new Error('Fixture authority unavailable');
      if (
        context.sessionPolicy &&
        (context.sessionPolicy.absoluteTtlMs > 600000 ||
          context.sessionPolicy.cookieSameSite === 'none')
      )
        throw new Error('Session policy denied');
      if (['sessions.validate', 'sessions.renew'].includes(action)) {
        if (!hint) throw new Error('Verified session owner required');
        const account = accounts.get(binding(hint));
        if (!account || !base.auth.isVerifiedTenant(account.subject.tenant))
          throw new Error('Account policy denied');
        return account.subject;
      }
      if (action === 'sessions.revoke_all' && logoutContext.getStore()) {
        const owner = logoutContext.getStore()!;
        if (!hint || binding(owner) !== binding(hint)) throw new Error('Logout owner mismatch');
        return owner;
      }
      const account = await primary(options);
      if (hint && binding(account.subject) !== binding(hint))
        throw new Error('Management owner mismatch');
      return account.subject;
    },
  };
  const settings: SessionsPluginSettings = {
    store: base.settings.store,
    hmac: base.settings.hmac,
    hmacKeyRef: base.settings.hmacKeyRef,
    authority,
    maxSessionsPerSubject: maxSessions,
    defaultPolicy: { absoluteTtlMs: 60000, idleTtlMs: 30000, cookieSameSite: 'lax' },
  };
  const instance = async () => {
    const app = await createApplication({
      service: { name: 'session-postgres-fixture', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      plugins: [loggingPlugin(), sessionsPlugin(settings)],
    });
    applications.push(app);
    await app.start();
    return { app, sessions: app.resolve<SessionService>(SESSIONS_CAPABILITY) };
  };
  try {
    const first = await instance(),
      second = await instance();
    return {
      base,
      settings,
      state,
      first,
      second,
      async revokePrimary(subject: IdentitySubject, sid: string) {
        if (
          !(
            await settings.store.store.compareAndSet(
              'sessions.primary-revoked.v1',
              await primaryKey(subject, sid),
              null,
              {
                kind: 'primary-revoked-v1',
                ownerKey: await ownerKey(subject),
                expiresAt: new Date(Date.now() + 600000).toISOString(),
              },
            )
          ).committed
        )
          throw new Error('Primary session already revoked');
      },
      async session(claims: Record<string, unknown> = {}) {
        const session = await base.session({ scope: 'sessions:manage orders.read', ...claims }),
          account = accountFor(session.identity);
        accounts.set(binding(account.subject), account);
        return session;
      },
      async logout(bearer: string) {
        const identity = await base.auth.verifyBearer(bearer),
          account = accountFor(identity),
          events = identity.claims.events;
        if (
          !events ||
          typeof events !== 'object' ||
          Array.isArray(events) ||
          Object.keys(events).length !== 1 ||
          !Object.hasOwn(events, 'http://schemas.openid.net/event/backchannel-logout') ||
          identity.claims.nonce !== undefined ||
          typeof identity.claims.jti !== 'string' ||
          !identity.claims.jti ||
          identity.claims.jti.length > 128 ||
          typeof identity.claims.sid !== 'string'
        )
          throw new Error('Invalid signed logout event');
        const event = (events as Record<string, unknown>)[
          'http://schemas.openid.net/event/backchannel-logout'
        ];
        if (
          !event ||
          typeof event !== 'object' ||
          Array.isArray(event) ||
          Object.keys(event).length
        )
          throw new Error('Invalid signed logout event value');
        const known = accounts.get(binding(account.subject));
        if (!known) throw new Error('Logout owner mismatch');
        const bindings = await settings.store.store.listByOwner(
          'sessions.authority.v1',
          await ownerKey(known.subject),
          1000,
        );
        if (
          !bindings.some(
            (row) =>
              row.fields.sid === identity.claims.sid &&
              row.fields.issuer === identity.issuer &&
              row.fields.subject === identity.subject &&
              row.fields.tenantId === known.subject.tenant?.tenantId,
          )
        )
          throw new Error('Logout issuer, subject, tenant or session mismatch');
        const replay = await settings.hmac.digest(
          'arkenivajs.sessions.logout-owner.v1',
          [
            identity.issuer,
            identity.subject,
            known.subject.tenant?.tenantId ?? '',
            identity.claims.sid,
            identity.claims.jti,
          ],
          settings.hmacKeyRef,
        );
        if (
          !(await settings.store.store.claimOnce(
            'sessions.logout.v1',
            replay,
            new Date(Number(identity.claims.exp) * 1000).toISOString(),
          ))
        )
          throw new Error('Logout replay rejected');
        return logoutContext.run(known.subject, () => second.sessions.revokeAll(known.subject));
      },
      async close() {
        try {
          await Promise.all(applications.map((app) => app.stop()));
        } finally {
          logoutContext.disable();
          await base.close();
        }
      },
    };
  } catch (error) {
    try {
      await Promise.all(applications.map((app) => app.stop()));
    } finally {
      logoutContext.disable();
      await base.close();
    }
    throw error;
  }
}
