// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import type { ApplicationOptions } from '@arkenivajs/core';
import { APIKEY_CAPABILITY, apiKeyPlugin } from '../../dist/index.js';
import type {
  ApiKeyPluginSettings,
  ApiKeyService,
  IdentitySubject,
  SecurityTransactionalStore,
} from '../../dist/index.js';

/** Unit-only state model. Live PostgreSQL conformance is a separate required suite. */
export function fixtureSettings() {
  const rows = new Map<string, Readonly<Record<string, unknown>>>(),
    key = (ns: string, id: string) => JSON.stringify([ns, id]);
  const state = {
    authenticated: true,
    enabled: true,
    fail: false,
    deniedScope: 'admin',
    calls: [] as string[],
    hmacChecks: 0,
  };
  const owner: IdentitySubject = Object.freeze({
    issuer: 'https://identity.fixture.invalid',
    subject: randomUUID(),
  });
  const live = (ns: string, id: string) => {
    if (state.fail) throw new Error('Private durable state diagnostic');
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
    async claimOnce(ns, digest, expiresAt) {
      if (live(ns, digest)) return false;
      rows.set(key(ns, digest), { expiresAt });
      return true;
    },
    async compareAndSet(ns, id, expected, next) {
      const previous = live(ns, id);
      if ((previous?.version ?? null) !== expected) return { committed: false };
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
      if (state.fail) throw new Error('Private owner index diagnostic');
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
      if (result.length > limit) throw new Error('Owner list overflow');
      return result;
    },
    async currentOwnerEpoch() {
      throw new Error('Unit fixture does not exercise epochs');
    },
    async bumpOwnerEpoch() {
      throw new Error('Unit fixture does not exercise epochs');
    },
  };
  let active = randomUUID();
  const keys = new Map<string, Buffer>([[active, randomBytes(32)]]),
    stable = randomBytes(32);
  const mac = (domain: string, parts: readonly string[], secret: Buffer) =>
    createHmac('sha256', secret)
      .update(JSON.stringify([domain, parts]))
      .digest();
  const hmac = {
    usage: 'test-only' as const,
    algorithm: 'HMAC-SHA256' as const,
    async digest(domain: string, parts: readonly string[], ref: string) {
      if (ref !== 'secrets/apikey') throw new Error('Unknown secret reference');
      if (domain.includes('.owner.') || domain.includes('.rate-owner.'))
        return mac(domain, parts, stable).toString('hex');
      return active + ':' + mac(domain, parts, keys.get(active)!).toString('hex');
    },
    async verify(domain: string, parts: readonly string[], expected: string, ref: string) {
      state.hmacChecks++;
      if (ref !== 'secrets/apikey') throw new Error('Unknown secret reference');
      const [version, encoded] = expected.split(':'),
        secret = keys.get(version!);
      const actual = mac(domain, parts, secret ?? stable),
        claimed =
          typeof encoded === 'string' && /^[a-f0-9]{64}$/.test(encoded)
            ? Buffer.from(encoded, 'hex')
            : Buffer.alloc(32);
      return timingSafeEqual(actual, claimed) && secret !== undefined;
    },
  };
  const settings: ApiKeyPluginSettings = {
    store: { store, securityLevel: 'test-only', operationTimeoutMs: 5000 },
    hmac,
    hmacKeyRef: 'secrets/apikey',
    authority: {
      async require(action, hint, context) {
        state.calls.push(action);
        if (
          !state.enabled ||
          (action !== 'apikey.verify' && !state.authenticated) ||
          hint?.issuer !== owner.issuer ||
          hint.subject !== owner.subject ||
          hint.tenant !== undefined ||
          context.apiKeyPolicy?.scopes.includes(state.deniedScope)
        )
          throw new Error('Private authority denial');
        return owner;
      },
    },
    maxActiveKeysPerSubject: 4,
    maxVerifyAttemptsPerMinute: 100000,
  };
  return {
    settings,
    store,
    owner,
    state,
    rows,
    rotateHmac() {
      active = randomUUID();
      keys.set(active, randomBytes(32));
    },
  };
}
export async function application(
  settings: ApiKeyPluginSettings,
  options: Partial<ApplicationOptions> = {},
) {
  const plugin = apiKeyPlugin(settings),
    app = await createApplication({
      service: { name: 'apikey-fixture', version: '1.0.0', environment: 'test' },
      plugins: [loggingPlugin(), plugin],
      logging: { level: 'silent' },
      ...options,
    });
  await app.start();
  return { app, keys: app.resolve<ApiKeyService>(APIKEY_CAPABILITY) };
}
export const grant = (scopes: readonly string[] = ['orders.read']) => ({
  scopes,
  expiresAt: new Date(Date.now() + 60000).toISOString(),
});
