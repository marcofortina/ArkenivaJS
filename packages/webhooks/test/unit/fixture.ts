// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomBytes, randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import type { TenantId } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { webhooksPlugin, WEBHOOKS_CAPABILITY } from '../../dist/index.js';
import type {
  WebhookService,
  WebhooksPluginSettings,
  WebhookContext,
  SecurityTransactionalStore,
} from '../../dist/index.js';

/** Test-only state model and server-owned authentication map; SQL durability is a separate gate. */
export function fixtureSettings(origin = 'http://127.0.0.1:9') {
  const auth = new AsyncLocalStorage<string>(),
    credentials = new Map<string, string>(),
    claims = new Map<string, number>(),
    rows = new Map<string, Readonly<Record<string, unknown>>>(),
    keys = new Map([['current', { bytes: randomBytes(32), keyVersion: 'one' }]]),
    logs: string[] = [];
  const state = {
    authorityAvailable: true,
    secretsAvailable: true,
    storeAvailable: true,
    authorityCalls: 0,
    secretCalls: 0,
    claimCalls: 0,
    holdKey: undefined as Promise<void> | undefined,
  };
  const subject = (tenantId: string) => {
    const identity = Object.freeze({
      issuer: 'https://webhooks.fixture.invalid',
      subject: 'fixture-subject',
      audience: ['webhooks'],
      scopes: ['webhooks:use'],
      claims: {},
    });
    return Object.freeze({
      issuer: identity.issuer,
      subject: identity.subject,
      tenant: Object.freeze({
        tenantId: tenantId as TenantId,
        identity,
        verifiedAt: new Date().toISOString(),
        source: 'oidc' as const,
      }),
    });
  };
  const available = () => {
    if (!state.storeAvailable) throw new Error('Private fixture storage diagnostic');
  };
  const store: SecurityTransactionalStore & { securityLevel: 'test-only' } = {
    securityLevel: 'test-only',
    async claimOnce(namespace, id, expiry) {
      available();
      state.claimCalls++;
      const key = namespace + ':' + id;
      if ((claims.get(key) ?? 0) > Date.now()) return false;
      claims.set(key, Date.parse(expiry));
      return true;
    },
    async read(namespace, id) {
      available();
      return rows.get(namespace + ':' + id) ?? null;
    },
    async compareAndSet(namespace, id, expected, next) {
      available();
      const key = namespace + ':' + id,
        previous = rows.get(key);
      if ((previous?.version ?? null) !== expected) return { committed: false };
      const version = randomUUID();
      if (next === null) rows.delete(key);
      else rows.set(key, { ...next, version });
      return { committed: true, version };
    },
    async atomicBatch() {
      available();
      throw new Error('This fixture does not use transactional batches');
    },
    async listByOwner() {
      available();
      return [];
    },
    async bumpOwnerEpoch() {
      available();
      return 1;
    },
    async currentOwnerEpoch() {
      available();
      return 0;
    },
  };
  const settings: WebhooksPluginSettings = {
    destinations: [
      {
        name: 'receiver',
        origin,
        hmacKeyRef: 'current',
        allowedCidrs: ['127.0.0.0/8', '::1/128'],
        maxRetries: 0,
        timeoutMs: 2000,
      },
    ],
    nonceStore: { store, securityLevel: 'test-only', operationTimeoutMs: 2000 },
    secretProvider: {
      async get(reference) {
        state.secretCalls++;
        if (state.holdKey) await state.holdKey;
        if (!state.secretsAvailable || !keys.has(reference))
          throw new Error('Private fixture secret diagnostic');
        return keys.get(reference)!;
      },
    },
    authority: {
      async require(_action, _subject, context) {
        if (context.destinationId !== 'receiver')
          throw new Error('Fixture destination policy denied');
        state.authorityCalls++;
        const credential = auth.getStore(),
          tenant = credential === undefined ? undefined : credentials.get(credential);
        if (!state.authorityAvailable || !tenant)
          throw new Error('Private fixture authentication diagnostic');
        return subject(tenant);
      },
    },
    policy: { maxConcurrent: 4, timeoutMs: 2000, maxInputBytes: 65536, maxOutputBytes: 65536 },
  };
  const asTenant = <T>(tenantId: string, work: () => T): T => {
    const credential = randomBytes(32).toString('base64url');
    credentials.set(credential, tenantId);
    return auth.run(credential, work);
  };
  return {
    settings,
    state,
    keys,
    claims,
    logs,
    asTenant,
    context: (change: Partial<WebhookContext> = {}): WebhookContext => ({
      destinationId: 'receiver',
      eventId: 'event-one',
      timestamp: new Date().toISOString(),
      nonce: randomBytes(24).toString('base64url'),
      keyId: keys.get('current')!.keyVersion,
      ...change,
    }),
  };
}
export async function fixture(input?: ReturnType<typeof fixtureSettings>) {
  const f = input ?? fixtureSettings(),
    destination = new Writable({
      write(chunk: Buffer, _encoding, done) {
        f.logs.push(chunk.toString());
        done();
      },
    });
  const app = await createApplication({
    service: { name: 'webhooks-fixture', version: '1.0.0', environment: 'test' },
    logging: { level: 'debug' },
    plugins: [loggingPlugin({ destination }), webhooksPlugin(f.settings)],
  });
  try {
    await app.start();
  } catch (cause) {
    destination.destroy();
    throw cause;
  }
  return {
    ...f,
    app,
    service: app.resolve<WebhookService>(WEBHOOKS_CAPABILITY),
    async close() {
      try {
        await app.stop();
      } finally {
        destination.destroy();
        for (const key of f.keys.values()) key.bytes.fill(0);
      }
    },
  };
}
