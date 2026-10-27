// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncLocalStorage } from 'node:async_hooks';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { loggingPlugin } from '@arkenivajs/logging';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { securityHttpPlugin, SECURITY_HTTP_CAPABILITY } from '@arkenivajs/security-http';
import type {
  SecurityHttpPluginSettings,
  SecurityHttpService,
  SecurityTransactionalStore,
} from '@arkenivajs/security-http';
import {
  createPostgresSecurityStateStore,
  createPostgresSecurityStateTables,
} from '../../dist/security-state-store.js';
import { sessionFixture } from './session-fixture.js';
import { cookieSecuritySettings } from '../../dist/http-security.js';

/** Actual signed primary identities, durable sessions and CSRF records on independent PostgreSQL pools. */
export async function httpSecurityFixture() {
  const primary = await sessionFixture(),
    secret = randomBytes(32),
    ambient = new AsyncLocalStorage<string>();
  const applications: Awaited<ReturnType<typeof createApplication>>[] = [],
    owners = new Map<string, Awaited<ReturnType<typeof primary.session>>>();
  const base = primary.base.backend,
    schema = 'security_' + randomBytes(12).toString('hex');
  let store: ReturnType<typeof createPostgresSecurityStateStore>;
  try {
    store = createPostgresSecurityStateStore(base.app.sql, 'main', schema);
  } catch (cause) {
    secret.fill(0);
    await primary.close();
    throw cause;
  }
  const state = { secretAvailable: true, effects: 0 };
  let schemaCreated = false,
    sibling: Awaited<ReturnType<typeof createApplication>> | undefined;
  async function authorizeSession(
    verified: Awaited<ReturnType<typeof primary.second.sessions.validate>>,
  ) {
    const account = owners.get(verified.sessionId);
    if (
      !account ||
      account.identity.issuer !== verified.issuer ||
      account.identity.subject !== verified.subject ||
      !primary.base.auth.isVerifiedTenant(account.subject.tenant)
    )
      throw new Error('Runtime session ownership mismatch');
    primary.base.auth.requireScope(account.identity, 'csrf:manage');
    return { verified, account };
  }
  const mac = (domain: string, parts: readonly string[], reference: string) => {
    if (
      !state.secretAvailable ||
      reference !== 'fixture/http-security' ||
      ![
        'arkenivajs.security-http.native-key.v1',
        'arkenivajs.security-http.owner.v1',
        'arkenivajs.security-http.state.v1',
      ].includes(domain)
    )
      throw new Error('Private CSRF key provider rejection');
    return createHmac('sha256', secret)
      .update(JSON.stringify([domain, parts]))
      .digest('hex');
  };
  const settings: SecurityHttpPluginSettings = cookieSecuritySettings({
    sessions: primary.second.sessions,
    store: { store, securityLevel: 'test-only', operationTimeoutMs: 5000 },
    hmac: {
      algorithm: 'HMAC-SHA256',
      async digest(domain, parts, reference) {
        return mac(domain, parts, reference);
      },
      async verify(domain, parts, expected, reference) {
        const actual = Buffer.from(mac(domain, parts, reference)),
          claimed = Buffer.from(expected);
        return actual.length === claimed.length && timingSafeEqual(actual, claimed);
      },
    },
    hmacKeyRef: 'fixture/http-security',
    allowedOrigins: ['https://app.fixture.invalid'],
    authenticatedSessionToken: () => ambient.getStore(),
    async authorize(session) {
      return (await authorizeSession(session)).account.subject;
    },
  });
  async function instance(backend: SecurityTransactionalStore = store) {
    const app = await createApplication({
      service: { name: 'http-security-postgres', version: '1.0.0', environment: 'test' },
      http: { host: '127.0.0.1', port: 0 },
      logging: { level: 'silent' },
      plugins: [
        loggingPlugin(),
        apiPlugin(),
        securityHttpPlugin({ ...settings, csrfStore: { ...settings.csrfStore, store: backend } }),
      ],
    });
    applications.push(app);
    app.api.get('/token', {
      schema: {
        response: {
          type: 'object',
          properties: { token: { type: 'string' } },
          required: ['token'],
          additionalProperties: false,
        },
      },
      auth: { required: false },
      async handler(context) {
        return {
          token: await service.csrfToken({ sessionId: context.headers['x-session-hint'] ?? '' }),
        };
      },
    });
    app.api.post('/protected', {
      schema: {
        response: {
          type: 'object',
          properties: { ok: { type: 'boolean' } },
          required: ['ok'],
          additionalProperties: false,
        },
      },
      auth: { required: false },
      handler() {
        state.effects++;
        return { ok: true };
      },
    });
    await app.start();
    const service = app.resolve<SecurityHttpService>(SECURITY_HTTP_CAPABILITY),
      origin = (app.api as ManagedApiServer).address()!;
    return { app, service, origin };
  }
  async function close() {
    try {
      await Promise.all(applications.map((app) => app.stop()));
    } finally {
      secret.fill(0);
      ambient.disable();
      try {
        await sibling?.stop();
      } finally {
        try {
          if (schemaCreated)
            await base.app.sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
        } finally {
          await primary.close();
        }
      }
    }
  }
  try {
    await base.app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
    schemaCreated = true;
    await createPostgresSecurityStateTables(base.app.sql, 'main', schema);
    sibling = await createApplication({
      service: { name: 'http-security-peer-database', version: '1.0.0', environment: 'test' },
      databases: {
        main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 4 },
      },
      plugins: [postgresPlugin()],
    });
    await sibling.start();
    const first = await instance(),
      second = await instance(createPostgresSecurityStateStore(sibling.sql, 'main', schema));
    return {
      primary,
      backend: { ...base, schema, store },
      first,
      second,
      instance,
      state,
      settings,
      close,
      async session(claims: Record<string, unknown> = {}) {
        const account = await primary.session({ scope: 'sessions:manage csrf:manage', ...claims });
        const issued = await account.run(() =>
          primary.first.sessions.create(account.identity, primary.settings.defaultPolicy),
        );
        owners.set(issued.sessionId, account);
        return {
          ...account,
          issued,
          run<T>(work: () => T) {
            return ambient.run(issued.value, work);
          },
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
