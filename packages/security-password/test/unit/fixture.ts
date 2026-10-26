// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes, randomUUID } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import type { TenantId } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { passwordPlugin, PASSWORD_CAPABILITY } from '../../dist/index.js';
import type {
  PasswordPluginSettings,
  PasswordService,
  PasswordHash,
  IdentitySubject,
  SecurityTransactionalStore,
} from '../../dist/index.js';

/** Unit-only atomic state model; real durability is verified through a separate SQL committer. */
export function fixtureSettings() {
  const rows = new Map<string, Readonly<Record<string, unknown>>>(),
    claims = new Map<string, number>(),
    epochs = new Map<string, number>(),
    credentials = new Map<string, PasswordHash>(),
    prefixes: string[] = [],
    breachRows = new Map<string, readonly Readonly<{ suffix: string; count: number }>[]>();
  const state = {
    primary: true,
    enabled: true,
    storeAvailable: true,
    secretAvailable: true,
    authorityAvailable: true,
    commitAvailable: true,
    tenant: undefined as string | undefined,
  };
  const account = randomUUID(),
    issuer = 'https://password.fixture.invalid',
    key = (ns: string, id: string) => JSON.stringify([ns, id]),
    binding = (subject: IdentitySubject) =>
      JSON.stringify([subject.issuer, subject.subject, subject.tenant?.tenantId ?? null]);
  let version = randomUUID();
  const secret = randomBytes(32);
  const owner = (): IdentitySubject => ({
    issuer,
    subject: account,
    ...(state.tenant
      ? {
          tenant: {
            tenantId: state.tenant as TenantId,
            verifiedAt: new Date().toISOString(),
            source: 'oidc' as const,
            identity: { issuer, subject: account, audience: [], scopes: [], claims: {} },
          },
        }
      : {}),
  });
  const live = (ns: string, id: string) => {
    if (!state.storeAvailable) throw new Error('Private fixture storage diagnostic');
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
    async compareAndSet(ns, id, expected, next) {
      const before = live(ns, id);
      if ((before?.version ?? null) !== expected) return { committed: false };
      const revision = randomUUID();
      if (next === null) rows.delete(key(ns, id));
      else rows.set(key(ns, id), Object.freeze({ ...next, version: revision }));
      return { committed: true, version: revision };
    },
    async atomicBatch(mutations) {
      if (
        mutations.some((m) => {
          const row = live(m.namespace, m.id);
          return (
            (row?.version ?? null) !== m.expectedVersion || (row && row.ownerKey !== m.ownerKey)
          );
        })
      )
        return { committed: false };
      const revision = randomUUID();
      for (const m of mutations) {
        if (m.next === null) rows.delete(key(m.namespace, m.id));
        else
          rows.set(
            key(m.namespace, m.id),
            Object.freeze({ ...m.next, ownerKey: m.ownerKey, version: revision }),
          );
      }
      return { committed: true, version: revision };
    },
    async claimOnce(ns, id, expiry) {
      if (!state.storeAvailable) throw new Error('Private fixture claim failure');
      const k = key(ns, id);
      if ((claims.get(k) ?? 0) > Date.now()) return false;
      claims.set(k, Date.parse(expiry));
      return true;
    },
    async listByOwner(ns, ownerKey, limit) {
      const found = [...rows]
        .filter(
          ([k, row]) =>
            JSON.parse(k)[0] === ns && row.ownerKey === ownerKey && live(ns, JSON.parse(k)[1]),
        )
        .map(([k, row]) => {
          const { version, ...fields } = row;
          return {
            id: JSON.parse(k)[1] as string,
            ownerKey,
            version: String(version),
            fields,
            ...(row.expiresAt ? { expiresAt: String(row.expiresAt) } : {}),
          };
        });
      if (found.length > limit) throw new Error('Fixture owner index overflow');
      return found;
    },
    async currentOwnerEpoch(ns, id) {
      if (!state.storeAvailable) throw new Error('Private epoch diagnostic');
      return epochs.get(key(ns, id)) ?? 0;
    },
    async bumpOwnerEpoch(ns, id) {
      if (!state.storeAvailable) throw new Error('Private epoch diagnostic');
      const next = (epochs.get(key(ns, id)) ?? 0) + 1;
      epochs.set(key(ns, id), next);
      return next;
    },
  };
  const settings: PasswordPluginSettings = {
    resetStore: { store, securityLevel: 'test-only', operationTimeoutMs: 5000 },
    secretProvider: {
      async get(reference) {
        if (!state.secretAvailable || reference !== 'fixture/password-reset')
          throw new Error('Private secret failure');
        return { bytes: secret, keyVersion: version };
      },
    },
    resetHmacKeyRef: 'fixture/password-reset',
    resetTtlMs: 300000,
    maxResetAttemptsPerHour: 1000,
    policy: {
      minLength: 12,
      memoryCostKiB: 8192,
      timeCost: 1,
      parallelism: 1,
      blockBreachedPasswords: false,
    },
    authority: {
      async require(action, hint, context) {
        const current = owner();
        if (
          !state.enabled ||
          !state.authorityAvailable ||
          !hint ||
          binding(hint) !== binding(current) ||
          (action !== 'password.consume_reset' && !state.primary) ||
          (action === 'password.create_reset' &&
            (!context.authorization || binding(context.authorization) !== binding(current)))
        )
          throw new Error('Private runtime authority denial');
        return current;
      },
    },
    breaches: {
      async lookup(prefix) {
        prefixes.push(prefix);
        return breachRows.get(prefix) ?? [];
      },
    },
    resetCommitter: {
      async commitReset(input) {
        if (!state.commitAvailable) throw new Error('Private credential transaction failure');
        const row = live(input.reset.namespace, input.reset.id);
        if (
          !row ||
          row.version !== input.reset.version ||
          row.ownerKey !== input.reset.ownerKey ||
          binding(input.subject) !== binding(owner())
        )
          return { committed: false };
        // All three changes are synchronous only in this explicitly unit-only state model.
        rows.delete(key(input.reset.namespace, input.reset.id));
        const accountKey = binding(input.subject);
        credentials.set(accountKey, input.replacement);
        epochs.set(accountKey, (epochs.get(accountKey) ?? 0) + 1);
        return { committed: true, version: randomUUID() };
      },
    },
  };
  return {
    settings,
    state,
    store,
    rows,
    epochs,
    credentials,
    owner,
    binding,
    prefixes,
    breachRows,
    rotateSecret() {
      version = randomUUID();
      randomBytes(32).copy(secret);
    },
    close() {
      secret.fill(0);
    },
  };
}
export async function application(settings: PasswordPluginSettings) {
  const app = await createApplication({
    service: { name: 'password-unit', version: '1.0.0', environment: 'test' },
    logging: { level: 'silent' },
    plugins: [loggingPlugin(), passwordPlugin(settings)],
  });
  await app.start();
  return { app, passwords: app.resolve<PasswordService>(PASSWORD_CAPABILITY) };
}
