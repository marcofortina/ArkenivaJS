// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncLocalStorage } from 'node:async_hooks';
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import type { Identity } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { createAuthService } from '@arkenivajs/security';
import { apiKeyPlugin, APIKEY_CAPABILITY } from '@arkenivajs/security-apikey';
import type {
  ApiKeyPluginSettings,
  ApiKeyService,
  IdentitySubject,
} from '@arkenivajs/security-apikey';
import { securityStateFixture } from './security-state-fixture.js';
import { startMfaIssuer } from './mfa-issuer.js';

/** Actual signed OIDC and durable PostgreSQL; ephemeral native keys remain fixture-owned memory. */
export async function apiKeyFixture(maxKeys = 4, maxAttempts = 10000) {
  const backend = await securityStateFixture();
  let issuer: Awaited<ReturnType<typeof startMfaIssuer>>;
  try {
    issuer = await startMfaIssuer();
  } catch (error) {
    await backend.close();
    throw error;
  }
  let auth: Awaited<ReturnType<typeof createAuthService>>;
  try {
    auth = await createAuthService({
      issuer: issuer.authority,
      audience: 'api://mfa-fixture',
      environment: 'test',
      allowInsecureLoopback: true,
      algorithms: ['RS256'],
      authorizeTenant: (_identity, tenantId) => tenantId === 'tenant-a' || tenantId === 'tenant-b',
    });
  } catch (error) {
    try {
      await issuer.close();
    } finally {
      await backend.close();
    }
    throw error;
  }
  const requests = new AsyncLocalStorage<Identity>(),
    accounts = new Map<string, IdentitySubject>(),
    revokedSessions = new Set<string>(),
    adminAttempts = new Map<string, number>();
  const ownerBinding = (subject: IdentitySubject) =>
    JSON.stringify([subject.issuer, subject.subject, subject.tenant?.tenantId ?? null]);
  const hmacKeys = new Map<string, Buffer>(),
    blindIndexKey = randomBytes(32);
  let active = randomUUID();
  hmacKeys.set(active, randomBytes(32));
  const state = { authorityAvailable: true, secretAvailable: true, accountEnabled: true };
  let remainingBatches = 0,
    releaseBatches: (() => void) | undefined,
    batchBarrier: Promise<void> | undefined;
  const mac = (domain: string, parts: readonly string[], key: Buffer) =>
    createHmac('sha256', key)
      .update(JSON.stringify([domain, parts]))
      .digest();
  const settings: ApiKeyPluginSettings = {
    store: {
      store: {
        ...backend.store,
        async atomicBatch(mutations, options) {
          if (remainingBatches > 0) {
            const held = batchBarrier;
            if (--remainingBatches === 0) releaseBatches!();
            await held;
          }
          return backend.store.atomicBatch(mutations, options);
        },
      },
      securityLevel: 'test-only',
      operationTimeoutMs: 5000,
    },
    hmac: {
      algorithm: 'HMAC-SHA256',
      async digest(domain, parts, keyRef) {
        if (!state.secretAvailable || keyRef !== 'fixture/apikey-hmac')
          throw new Error('Fixture secret unavailable');
        if (
          [
            'arkenivajs.apikey.owner.v1',
            'arkenivajs.apikey.rate-owner.v1',
            'arkenivajs.sessions.owner.v1',
            'arkenivajs.sessions.rate-owner.v1',
            'arkenivajs.sessions.logout-owner.v1',
            'arkenivajs.magiclink.owner.v1',
          ].includes(domain)
        )
          return mac(domain, parts, blindIndexKey).toString('hex');
        if (
          ![
            'arkenivajs.apikey.verifier.v1',
            'arkenivajs.sessions.verifier.v1',
            'arkenivajs.magiclink.verifier.v1',
          ].includes(domain)
        )
          throw new Error('Unapproved HMAC domain');
        return active + ':' + mac(domain, parts, hmacKeys.get(active)!).toString('hex');
      },
      async verify(domain, parts, expected, keyRef) {
        if (
          !state.secretAvailable ||
          keyRef !== 'fixture/apikey-hmac' ||
          ![
            'arkenivajs.apikey.verifier.v1',
            'arkenivajs.sessions.verifier.v1',
            'arkenivajs.magiclink.verifier.v1',
          ].includes(domain)
        )
          throw new Error('Fixture secret unavailable');
        const [version, encoded] = expected.split(':'),
          key = hmacKeys.get(version!),
          actual = mac(domain, parts, key ?? blindIndexKey),
          claimed =
            encoded && /^[a-f0-9]{64}$/.test(encoded)
              ? Buffer.from(encoded, 'hex')
              : Buffer.alloc(32);
        return timingSafeEqual(actual, claimed) && key !== undefined;
      },
    },
    hmacKeyRef: 'fixture/apikey-hmac',
    maxActiveKeysPerSubject: maxKeys,
    maxVerifyAttemptsPerMinute: maxAttempts,
    authority: {
      async require(action, hint, context) {
        const canonical = hint && accounts.get(ownerBinding(hint));
        if (
          !state.authorityAvailable ||
          !state.accountEnabled ||
          !canonical ||
          context.apiKeyPolicy?.scopes.some((scope) => scope !== 'orders.read') ||
          (context.apiKeyPolicy && Date.parse(context.apiKeyPolicy.expiresAt) > Date.now() + 600000)
        )
          throw new Error('Fixture account policy denied');
        if (action !== 'apikey.verify') {
          const identity = requests.getStore();
          if (
            !identity ||
            identity.issuer !== canonical.issuer ||
            identity.subject !== canonical.subject ||
            identity.claims.tenant_id !== canonical.tenant?.tenantId ||
            typeof identity.claims.sid !== 'string' ||
            revokedSessions.has(identity.claims.sid) ||
            typeof identity.claims.auth_time !== 'number' ||
            Date.now() / 1000 - identity.claims.auth_time > 60
          )
            throw new Error('Verified recent fixture session required');
          auth.requireScope(identity, 'apikey:manage');
          const tenant = auth.tenantFrom(identity);
          if (!auth.isVerifiedTenant(tenant) || tenant !== canonical.tenant)
            throw new Error('Verified tenant membership required');
          const minute = Math.floor(Date.now() / 60000),
            key = identity.claims.sid + ':' + minute;
          if (adminAttempts.size > 128) throw new Error('Fixture management budget exceeded');
          const used = adminAttempts.get(key) ?? 0;
          if (used >= 40) throw new Error('Fixture management rate exceeded');
          adminAttempts.set(key, used + 1);
        }
        if (
          ![
            'apikey.issue',
            'apikey.rotate',
            'apikey.revoke',
            'apikey.list',
            'apikey.verify',
          ].includes(action)
        )
          throw new Error('Unknown fixture authority action');
        return canonical;
      },
    },
  };
  const applications: Awaited<ReturnType<typeof createApplication>>[] = [];
  async function instance() {
    const app = await createApplication({
      service: { name: 'apikey-postgres-fixture', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      plugins: [loggingPlugin(), apiKeyPlugin(settings)],
    });
    applications.push(app);
    await app.start();
    return { app, keys: app.resolve<ApiKeyService>(APIKEY_CAPABILITY) };
  }
  try {
    const first = await instance(),
      second = await instance();
    return {
      backend,
      issuer,
      settings,
      auth,
      currentIdentity: () => requests.getStore(),
      state,
      first,
      second,
      synchronizeNextBatches(count: number) {
        if (!Number.isSafeInteger(count) || count < 2 || count > 4 || remainingBatches !== 0)
          throw new Error('Invalid fixture batch barrier');
        remainingBatches = count;
        batchBarrier = new Promise<void>((resolve) => {
          releaseBatches = resolve;
        });
      },
      async session(claims: Record<string, unknown> = {}) {
        const token = await issuer.bearer({ scope: 'apikey:manage', ...claims }),
          identity = await auth.verifyBearer(token),
          tenant = auth.tenantFrom(identity);
        const subject = Object.freeze({
          issuer: identity.issuer,
          subject: identity.subject,
          tenant,
        });
        accounts.set(ownerBinding(subject), subject);
        return {
          subject,
          identity,
          token,
          run<T>(work: () => Promise<T>) {
            return requests.run(identity, work);
          },
        };
      },
      revokeSession(sessionId: string) {
        revokedSessions.add(sessionId);
      },
      rotateHmac() {
        active = randomUUID();
        hmacKeys.set(active, randomBytes(32));
      },
      async close() {
        try {
          await Promise.all(applications.map((app) => app.stop()));
        } finally {
          try {
            await auth.close();
            await issuer.close();
          } finally {
            for (const key of hmacKeys.values()) key.fill(0);
            blindIndexKey.fill(0);
            requests.disable();
            await backend.close();
          }
        }
      },
    };
  } catch (error) {
    try {
      await Promise.all(applications.map((app) => app.stop()));
      await auth.close();
      await issuer.close();
    } finally {
      for (const key of hmacKeys.values()) key.fill(0);
      blindIndexKey.fill(0);
      requests.disable();
      await backend.close();
    }
    throw error;
  }
}
