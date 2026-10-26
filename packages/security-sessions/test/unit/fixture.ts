// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import type { Identity, TenantId } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { sessionsPlugin, SESSIONS_CAPABILITY } from '../../dist/index.js';
import type {
  SessionsPluginSettings,
  SessionService,
  SessionAuthentication,
  SecurityTransactionalStore,
  IdentitySubject,
} from '../../dist/index.js';

/** Unit-only state model. Real PostgreSQL conformance is exercised separately. */
export function fixtureSettings() {
  const rows = new Map<string, Readonly<Record<string, unknown>>>(),
    epochs = new Map<string, number>(),
    events = new Map<string, SessionAuthentication>(),
    key = (ns: string, id: string) => JSON.stringify([ns, id]);
  const state = {
    primary: true,
    enabled: true,
    fail: false,
    tenant: undefined as string | undefined,
    scopes: ['orders.read'],
    assurance: 'single-factor' as 'single-factor' | 'mfa' | 'phishing-resistant',
  };
  const issuer = 'https://identity.fixture.invalid',
    account = randomUUID();
  const canonical = (): Identity =>
    Object.freeze({
      issuer,
      subject: account,
      audience: ['fixture'],
      scopes: [...state.scopes],
      claims: { private: 'Original private account claims' },
      assurance: state.assurance,
    });
  const owner = (): IdentitySubject => {
    const identity = canonical();
    return {
      issuer,
      subject: account,
      ...(state.tenant
        ? {
            tenant: {
              tenantId: state.tenant as TenantId,
              identity,
              verifiedAt: new Date().toISOString(),
              source: 'oidc' as const,
            },
          }
        : {}),
    };
  };
  const live = (ns: string, id: string) => {
    if (state.fail) throw new Error('Private storage diagnostic');
    const row = rows.get(key(ns, id));
    return row && (row.expiresAt === undefined || Date.parse(String(row.expiresAt)) > Date.now())
      ? row
      : null;
  };
  const store: SecurityTransactionalStore & { securityLevel: 'test-only' } = {
    securityLevel: 'test-only',
    async read(ns, id) {
      return live(ns, id);
    },
    async claimOnce(ns, id, expiresAt) {
      if (live(ns, id)) return false;
      rows.set(key(ns, id), { expiresAt });
      return true;
    },
    async compareAndSet(ns, id, expected, next) {
      const row = live(ns, id);
      if ((row?.version ?? null) !== expected) return { committed: false };
      const version = randomUUID();
      if (next === null) rows.delete(key(ns, id));
      else rows.set(key(ns, id), Object.freeze({ ...next, version }));
      return { committed: true, version };
    },
    async atomicBatch(mutations) {
      if (state.fail) throw new Error('Private transaction diagnostic');
      if (
        mutations.some((m) => {
          const row = live(m.namespace, m.id);
          return (
            (row?.version ?? null) !== m.expectedVersion || (row && row.ownerKey !== m.ownerKey)
          );
        })
      )
        return { committed: false };
      const version = randomUUID();
      for (const mutation of mutations) {
        if (mutation.next === null) rows.delete(key(mutation.namespace, mutation.id));
        else
          rows.set(
            key(mutation.namespace, mutation.id),
            Object.freeze({ ...mutation.next, ownerKey: mutation.ownerKey, version }),
          );
      }
      return { committed: true, version };
    },
    async listByOwner(ns, ownerKey, limit) {
      if (state.fail) throw new Error('Private index diagnostic');
      const result = [...rows.entries()]
        .filter(
          ([entry, row]) =>
            JSON.parse(entry)[0] === ns &&
            row.ownerKey === ownerKey &&
            (row.expiresAt === undefined || Date.parse(String(row.expiresAt)) > Date.now()),
        )
        .map(([entry, row]) => {
          const { version, ...fields } = row;
          return {
            id: JSON.parse(entry)[1] as string,
            ownerKey,
            version: String(version),
            ...(row.expiresAt === undefined ? {} : { expiresAt: String(row.expiresAt) }),
            fields,
          };
        });
      if (result.length > limit) throw new Error('Owner overflow');
      return result;
    },
    async currentOwnerEpoch(ns, ownerKey) {
      if (state.fail) throw new Error('Private epoch diagnostic');
      return epochs.get(key(ns, ownerKey)) ?? 0;
    },
    async bumpOwnerEpoch(ns, ownerKey) {
      if (state.fail) throw new Error('Private epoch diagnostic');
      const next = (epochs.get(key(ns, ownerKey)) ?? 0) + 1;
      if (!Number.isSafeInteger(next)) throw new Error('Epoch overflow');
      epochs.set(key(ns, ownerKey), next);
      return next;
    },
  };
  let active = randomUUID();
  const keys = new Map<string, Buffer>([[active, randomBytes(32)]]),
    blind = randomBytes(32);
  const mac = (domain: string, parts: readonly string[], secret: Buffer) =>
    createHmac('sha256', secret)
      .update(JSON.stringify([domain, parts]))
      .digest();
  const hmac = {
    usage: 'test-only' as const,
    algorithm: 'HMAC-SHA256' as const,
    async digest(domain: string, parts: readonly string[], ref: string) {
      if (ref !== 'fixture/sessions') throw new Error('Unknown external reference');
      if (domain.includes('.owner.') || domain.includes('.rate-owner.'))
        return mac(domain, parts, blind).toString('hex');
      return active + ':' + mac(domain, parts, keys.get(active)!).toString('hex');
    },
    async verify(domain: string, parts: readonly string[], expected: string, ref: string) {
      if (ref !== 'fixture/sessions') throw new Error('Unknown external reference');
      const [version, encoded] = expected.split(':'),
        secret = keys.get(version!),
        actual = mac(domain, parts, secret ?? blind),
        claimed =
          encoded && /^[a-f0-9]{64}$/.test(encoded)
            ? Buffer.from(encoded, 'hex')
            : Buffer.alloc(32);
      return timingSafeEqual(actual, claimed) && secret !== undefined;
    },
  };
  const settings: SessionsPluginSettings = {
    store: { store, securityLevel: 'test-only', operationTimeoutMs: 5000 },
    hmac,
    hmacKeyRef: 'fixture/sessions',
    maxSessionsPerSubject: 4,
    defaultPolicy: { absoluteTtlMs: 60000, idleTtlMs: 10000, cookieSameSite: 'lax' },
    authority: {
      async resolveIdentity(input, context) {
        if (!state.enabled || input.issuer !== issuer || input.subject !== account)
          throw new Error('Unknown account');
        const identity = canonical(),
          subject = owner();
        if (context.operation === 'create') {
          if (!state.primary) throw new Error('Independent primary authentication required');
          const event = {
            identity,
            subject,
            authenticatedAt: new Date().toISOString(),
            ...(state.assurance !== 'single-factor' ? { assuredAt: new Date().toISOString() } : {}),
          };
          events.set(context.sessionId, event);
          return event;
        }
        const event = events.get(context.previousSessionId ?? context.sessionId);
        if (!event) throw new Error('Missing trusted authentication event');
        if (context.operation === 'renew') events.set(context.sessionId, event);
        return { ...event, identity, subject };
      },
      async require(action, hint, context) {
        const current = owner();
        if (
          !state.enabled ||
          (!['sessions.validate', 'sessions.renew'].includes(action) && !state.primary) ||
          (hint &&
            (hint.issuer !== issuer ||
              hint.subject !== account ||
              hint.tenant?.tenantId !== state.tenant)) ||
          (context.sessionPolicy && context.sessionPolicy.absoluteTtlMs > 600000)
        )
          throw new Error('Private session policy denial');
        return current;
      },
    },
  };
  return {
    settings,
    state,
    store,
    rows,
    events,
    epochs,
    identity: canonical,
    owner,
    rotateHmac() {
      active = randomUUID();
      keys.set(active, randomBytes(32));
    },
  };
}
export async function application(settings: SessionsPluginSettings) {
  const app = await createApplication({
    service: { name: 'sessions-unit', version: '1.0.0', environment: 'test' },
    logging: { level: 'silent' },
    plugins: [loggingPlugin(), sessionsPlugin(settings)],
  });
  await app.start();
  return { app, sessions: app.resolve<SessionService>(SESSIONS_CAPABILITY) };
}
