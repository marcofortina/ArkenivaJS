// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncLocalStorage } from 'node:async_hooks';
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import type { TenantId, ServerTlsFiles } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { securityHttpPlugin, SECURITY_HTTP_CAPABILITY } from '../../dist/index.js';
import type {
  SecurityHttpPluginSettings,
  SecurityHttpService,
  SecurityTransactionalStore,
  IdentitySubject,
} from '../../dist/index.js';

/** Test-only authenticated state; production session validation is exercised by the SQL consumer. */
export function fixtureSettings() {
  const keys = { current: randomBytes(32) },
    ambient = new AsyncLocalStorage<string>();
  const rows = new Map<string, Readonly<Record<string, unknown>>>(),
    credentials = new Map<string, { sessionId: string; identity: IdentitySubject }>();
  const state = {
    hmacAvailable: true,
    storageAvailable: true,
    authorityAvailable: true,
    writes: 0,
    reads: 0,
    authorizations: 0,
    effects: 0,
    holdWrite: undefined as Promise<void> | undefined,
    holdRead: undefined as Promise<void> | undefined,
    holdHmac: undefined as Promise<void> | undefined,
  };
  const credential = (tenant: string) => {
    const identity = Object.freeze({
      issuer: 'https://csrf.fixture.invalid',
      subject: 'subject-' + tenant,
      audience: ['http-security'],
      scopes: [],
      claims: {},
    });
    const subject = Object.freeze({
      issuer: identity.issuer,
      subject: identity.subject,
      tenant: Object.freeze({
        tenantId: tenant as TenantId,
        identity,
        verifiedAt: new Date().toISOString(),
        source: 'oidc' as const,
      }),
    });
    const cookie = randomBytes(32).toString('base64url'),
      sessionId = randomUUID();
    credentials.set(cookie, { sessionId, identity: subject });
    return { cookie, sessionId, subject };
  };
  const alice = credential('alpha'),
    bob = credential('beta');
  const available = () => {
    if (!state.storageAvailable) throw new Error('Private storage failure');
  };
  const store: SecurityTransactionalStore & { securityLevel: 'test-only' } = {
    securityLevel: 'test-only',
    async read(namespace, id) {
      await state.holdRead;
      available();
      state.reads++;
      return rows.get(namespace + ':' + id) ?? null;
    },
    async compareAndSet(namespace, id, expected, next) {
      await state.holdWrite;
      available();
      state.writes++;
      const key = namespace + ':' + id,
        previous = rows.get(key);
      if ((previous?.version ?? null) !== expected) return { committed: false };
      const version = randomUUID();
      if (next === null) rows.delete(key);
      else rows.set(key, { ...next, version });
      return { committed: true, version };
    },
    async claimOnce() {
      available();
      throw new Error('CSRF is not a one-use credential');
    },
    async atomicBatch() {
      available();
      throw new Error('This fixture does not implement application transactions');
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
  const digest = async (domain: string, parts: readonly string[]) => {
    await state.holdHmac;
    if (!state.hmacAvailable) throw new Error('Private HMAC provider failure');
    return createHmac('sha256', keys.current)
      .update(JSON.stringify([domain, ...parts]))
      .digest('hex');
  };
  const settings: SecurityHttpPluginSettings = {
    policy: {
      contentSecurityPolicy: {
        'default-src': ["'self'"],
        'object-src': ["'none'"],
        'base-uri': ["'none'"],
      },
      hstsMaxAgeSeconds: 31536000,
      csrfEnabled: true,
      frameAncestors: ["'none'"],
    },
    csrfStore: { store, securityLevel: 'test-only', operationTimeoutMs: 1000 },
    csrfHmac: {
      algorithm: 'HMAC-SHA256',
      digest,
      async verify(domain, parts, expected) {
        const actual = await digest(domain, parts),
          a = Buffer.from(actual),
          b = Buffer.from(expected);
        return a.length === b.length && timingSafeEqual(a, b);
      },
    },
    csrfKeyRef: 'fixture://http-security',
    authority: {
      async require(_action, _subject, context) {
        state.authorizations++;
        const cookie = context.request?.cookies['__Host-session'] ?? ambient.getStore();
        const authenticated = cookie ? credentials.get(cookie) : undefined;
        if (
          !state.authorityAvailable ||
          !authenticated ||
          authenticated.sessionId !== context.sessionId
        )
          throw new Error('Private authority rejection');
        return authenticated.identity;
      },
    },
    allowedOrigins: ['https://app.fixture.invalid'],
    cookieRoutes: [{ method: 'POST', path: '/protected' }],
    cookieSession: {
      async resolve(request) {
        const authenticated = credentials.get(request.cookies['__Host-session'] ?? '');
        if (!state.authorityAvailable || !authenticated)
          throw new Error('Private cookie session rejection');
        return { sessionId: authenticated.sessionId };
      },
    },
  };
  return {
    settings,
    state,
    alice,
    bob,
    rows,
    keys,
    credentials,
    as<T>(cookie: string, work: () => T) {
      return ambient.run(cookie, work);
    },
  };
}

export async function startFixture(
  input = fixtureSettings(),
  tls?: ServerTlsFiles,
  telemetryEndpoint?: string,
  http2 = false,
) {
  const logs: string[] = [];
  const app = await createApplication({
    service: { name: 'http-security-test', version: '1.0.0', environment: 'test' },
    http: {
      host: '127.0.0.1',
      port: 0,
      ...(tls ? { protocol: 'https' as const, tls, http2 } : {}),
    },
    logging: { level: 'info' },
    ...(telemetryEndpoint ? { telemetry: { mode: 'standard' as const, samplingRatio: 1 } } : {}),
    plugins: [
      loggingPlugin({
        destination: new Writable({
          write(chunk, _encoding, callback) {
            logs.push(String(chunk));
            callback();
          },
        }),
      }),
      ...(telemetryEndpoint
        ? [
            telemetryPlugin({
              endpoint: telemetryEndpoint,
              allowInsecureLoopback: true,
              exportIntervalMs: 1000,
              exportTimeoutMs: 1000,
            }),
          ]
        : []),
      apiPlugin({ dependencies: telemetryEndpoint ? ['telemetry'] : [] }),
      securityHttpPlugin(input.settings),
    ],
  });
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
  for (const path of ['/protected', '/ordinary'])
    app.api.post(path, {
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
        input.state.effects++;
        return { ok: true };
      },
    });
  const native = (app.api as ManagedApiServer).native();
  try {
    await app.start();
  } catch (cause) {
    try {
      await app.stop().catch(() => undefined);
    } finally {
      native.server.closeAllConnections?.();
      await native.close();
    }
    throw cause;
  }
  const service = app.resolve<SecurityHttpService>(SECURITY_HTTP_CAPABILITY);
  const origin = (app.api as ManagedApiServer).address()!;
  return {
    ...input,
    app,
    service,
    origin,
    logs,
    async close() {
      try {
        await app.stop();
      } finally {
        native.server.closeAllConnections?.();
        await native.close();
      }
    },
  };
}
