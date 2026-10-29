// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { loggingPlugin } from '@arkenivajs/logging';
import { webhooksPlugin, WEBHOOKS_CAPABILITY } from '@arkenivajs/webhooks';
import type {
  WebhookService,
  WebhooksPluginSettings,
  SecurityTransactionalStore,
} from '@arkenivajs/webhooks';
import { createPostgresSecurityStateStore } from '../../dist/security-state-store.js';
import { sessionFixture } from './session-fixture.js';

/** Real signed OIDC, durable primary revocation and independent PostgreSQL connection pools. */
export async function webhooksFixture() {
  const primary = await sessionFixture(),
    backend = primary.base.backend,
    secret = randomBytes(32),
    state = { secretAvailable: true },
    applications: Awaited<ReturnType<typeof createApplication>>[] = [];
  let sibling: Awaited<ReturnType<typeof createApplication>> | undefined;
  const settings: WebhooksPluginSettings = {
    destinations: [
      {
        name: 'receiver',
        origin: 'https://receiver.fixture.invalid',
        hmacKeyRef: 'fixture/webhooks',
        allowedCidrs: ['0.0.0.0/0', '::/0'],
        maxRetries: 0,
        timeoutMs: 5000,
      },
    ],
    policy: { maxConcurrent: 4, timeoutMs: 5000, maxInputBytes: 65536, maxOutputBytes: 65536 },
    nonceStore: { store: backend.store, securityLevel: 'test-only', operationTimeoutMs: 5000 },
    secretProvider: {
      async get(reference) {
        if (!state.secretAvailable || reference !== 'fixture/webhooks')
          throw new Error('Private webhook fixture secret diagnostic');
        return { bytes: secret, keyVersion: 'one' };
      },
    },
    authority: {
      async require(action, _subject, context, options) {
        if (!['webhooks.sign', 'webhooks.verify', 'webhooks.send'].includes(action))
          throw new Error('Unknown webhook fixture action');
        if (context.destinationId !== 'receiver')
          throw new Error('Webhook destination policy denied');
        const account = await primary.verifyPrimary(options);
        primary.base.auth.requireScope(account.identity, action.replace('.', ':'));
        if (!primary.base.auth.isVerifiedTenant(account.subject.tenant))
          throw new Error('Verified tenant membership required');
        return account.subject;
      },
    },
  };
  async function instance(store: SecurityTransactionalStore = backend.store) {
    // Exercise the real providers while rejecting executable callable metadata.
    for (const provider of [settings.secretProvider, settings.authority, store])
      for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(provider)))
        if ('value' in descriptor && typeof descriptor.value === 'function')
          for (const key of ['bind', 'name', 'length'])
            Object.defineProperty(descriptor.value, key, {
              configurable: true,
              get() {
                throw new Error('Webhook provider callable metadata must not execute');
              },
            });
    const app = await createApplication({
      service: { name: 'webhooks-postgres-fixture', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      plugins: [
        loggingPlugin(),
        webhooksPlugin({ ...settings, nonceStore: { ...settings.nonceStore, store } }),
      ],
    });
    applications.push(app);
    await app.start();
    return { app, webhooks: app.resolve<WebhookService>(WEBHOOKS_CAPABILITY) };
  }
  const close = async () => {
    try {
      await Promise.all(applications.map((app) => app.stop()));
    } finally {
      secret.fill(0);
      try {
        await sibling?.stop();
      } finally {
        await primary.close();
      }
    }
  };
  try {
    sibling = await createApplication({
      service: { name: 'webhooks-peer-database', version: '1.0.0', environment: 'test' },
      databases: {
        main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 4 },
      },
      plugins: [postgresPlugin()],
    });
    await sibling.start();
    const peer = createPostgresSecurityStateStore(sibling.sql, 'main', backend.schema),
      first = await instance(),
      second = await instance(peer);
    return {
      primary,
      backend,
      settings,
      state,
      first,
      second,
      instance,
      close,
      session: (claims: Record<string, unknown> = {}) =>
        primary.session({
          scope: 'sessions:manage webhooks:sign webhooks:verify webhooks:send',
          ...claims,
        }),
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
