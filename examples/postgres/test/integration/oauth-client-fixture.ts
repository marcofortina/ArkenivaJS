// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { loggingPlugin } from '@arkenivajs/logging';
import { cryptoPlugin } from '@arkenivajs/security-crypto';
import { oauthClientPlugin, OAUTH_CLIENT_CAPABILITY } from '@arkenivajs/security-oauth-client';
import type {
  OAuthClientService,
  SecurityTransactionalStore,
} from '@arkenivajs/security-oauth-client';
import { createPostgresSecurityStateStore } from '../../dist/security-state-store.js';
import { outgoingOAuthSettings } from '../../dist/oauth-client.js';
import { sessionFixture } from './session-fixture.js';

/** Verified-HTTPS AS, signed local OIDC authority and independently pooled durable grant state. */
export async function oauthFixture() {
  const path = process.env.ARKENIVA_OAUTH_FIXTURE;
  if (!path) throw new Error('The owned HTTPS OAuth fixture metadata is required');
  const metadata = JSON.parse(await readFile(path, 'utf8')) as {
    issuer: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    audience: string;
  };
  if (!metadata.issuer.startsWith('https://127.0.0.1:'))
    throw new Error('The isolated OAuth fixture must use verified loopback HTTPS');
  const primary = await sessionFixture(),
    backend = primary.base.backend;
  const material = new Map([
    ['fixture://oauth/encryption', randomBytes(32)],
    ['fixture://oauth/mac', randomBytes(32)],
    ['fixture://oauth/client-secret', Buffer.from(metadata.clientSecret)],
  ]);
  const state = { secretsAvailable: true },
    applications: Awaited<ReturnType<typeof createApplication>>[] = [];
  let peerApplication: Awaited<ReturnType<typeof createApplication>> | undefined;
  const secretProvider = {
    usage: 'test-only' as const,
    async get(reference: string) {
      const bytes = material.get(reference);
      if (!state.secretsAvailable || !bytes)
        throw new Error('Private OAuth fixture secret unavailable');
      return { bytes, keyVersion: 'fixture-version' };
    },
  };
  const settings = outgoingOAuthSettings({
    clients: [
      {
        id: 'orders',
        issuer: metadata.issuer,
        clientId: metadata.clientId,
        clientSecretRef: 'fixture://oauth/client-secret',
        redirectUri: metadata.redirectUri,
        allowedAudiences: [metadata.audience],
        allowedScopes: ['openid', 'orders.read'],
      },
    ],
    secretProvider,
    stateStore: { store: backend.store, securityLevel: 'production', operationTimeoutMs: 5000 },
    encryptionKeyRefs: ['fixture://oauth/encryption'],
    macKeyRefs: ['fixture://oauth/mac'],
    allowInsecureLoopback: true,
    authority: {
      async require(action, hint, context, options) {
        if (
          ![
            'oauth.begin_authorization',
            'oauth.exchange_code',
            'oauth.client_credentials',
            'oauth.refresh',
            'oauth.revoke',
          ].includes(action) ||
          context.oauth?.clientId !== 'orders' ||
          context.oauth.audience !== metadata.audience
        )
          throw new Error('The OAuth application policy denied this grant');
        const account = await primary.verifyPrimary(options);
        primary.base.auth.requireScope(account.identity, 'oauth:manage');
        if (
          !primary.base.auth.isVerifiedTenant(account.subject.tenant) ||
          (hint &&
            (hint.issuer !== account.subject.issuer ||
              hint.subject !== account.subject.subject ||
              hint.tenant?.tenantId !== account.subject.tenant?.tenantId))
        )
          throw new Error('The authenticated OAuth grant owner does not match');
        return account.subject;
      },
    },
  });
  const instance = async (store: SecurityTransactionalStore = backend.store) => {
    const app = await createApplication({
      service: { name: 'oauth-postgres-fixture', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      plugins: [
        loggingPlugin(),
        cryptoPlugin({
          secrets: secretProvider,
          encryptionKeyRefs: settings.stateEncryptionKeyRefs,
          signingKeyRefs: settings.stateMacKeyRefs,
          policy: {
            maxConcurrent: 32,
            timeoutMs: 5000,
            maxInputBytes: 32768,
            maxOutputBytes: 32768,
          },
        }),
        oauthClientPlugin({ ...settings, stateStore: { ...settings.stateStore, store } }),
      ],
    });
    applications.push(app);
    await app.start();
    return { app, oauth: app.resolve<OAuthClientService>(OAUTH_CLIENT_CAPABILITY) };
  };
  const close = async () => {
    try {
      await Promise.all(applications.map((app) => app.stop()));
    } finally {
      for (const bytes of material.values()) bytes.fill(0);
      try {
        await peerApplication?.stop();
      } finally {
        await primary.close();
      }
    }
  };
  try {
    peerApplication = await createApplication({
      service: { name: 'oauth-peer-database', version: '1.0.0', environment: 'test' },
      databases: {
        main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 4 },
      },
      plugins: [postgresPlugin()],
    });
    await peerApplication.start();
    const peer = createPostgresSecurityStateStore(peerApplication.sql, 'main', backend.schema),
      first = await instance(),
      second = await instance(peer);
    return {
      primary,
      backend,
      state,
      metadata,
      first,
      second,
      instance,
      close,
      session: (claims: Record<string, unknown> = {}) =>
        primary.session({ scope: 'sessions:manage oauth:manage', ...claims }),
      async authorize(url: string) {
        const response = await fetch(url, {
          redirect: 'manual',
          signal: AbortSignal.timeout(5000),
        });
        if (response.status !== 302) throw new Error('The owned OAuth authorization failed');
        const callback = new URL(response.headers.get('location')!);
        return {
          stateRef: callback.searchParams.get('state')!,
          code: callback.searchParams.get('code')!,
          issuer: callback.searchParams.get('iss')!,
          redirectUri: metadata.redirectUri,
        };
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}
