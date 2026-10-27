// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes, randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import type {
  IdentitySubject,
  OAuthClientPluginSettings,
  OAuthClientService,
} from '../../dist/index.js';
import type { TenantId } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { cryptoPlugin } from '@arkenivajs/security-crypto';
import { oauthClientPlugin, OAUTH_CLIENT_CAPABILITY } from '../../dist/index.js';
import { unitStore } from './store.js';
import { startServer } from './server.js';

/** Actual native SDK and crypto, with explicitly unit-only shared state and runtime authority. */
export async function fixture(observed = false) {
  const server = await startServer(),
    memory = unitStore(),
    account = randomUUID(),
    issuer = 'https://owner.fixture.invalid',
    material = new Map<string, Buffer>([
      ['state/encryption/v1', randomBytes(32)],
      ['state/mac/v1', randomBytes(32)],
      ['client/secret', Buffer.from(server.secret)],
    ]),
    versions = new Map([...material.keys()].map((ref) => [ref, randomUUID()])),
    state = {
      primary: true,
      enabled: true,
      secretAvailable: true,
      tenant: undefined as string | undefined,
      holdSecret: undefined as Promise<void> | undefined,
      secretCalls: 0,
    },
    applications: Awaited<ReturnType<typeof createApplication>>[] = [],
    logs: string[] = [],
    destinations: Writable[] = [];
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
  const provider = {
    usage: 'test-only' as const,
    async get(reference: string) {
      state.secretCalls++;
      await state.holdSecret;
      const bytes = material.get(reference),
        keyVersion = versions.get(reference);
      if (!state.secretAvailable || !bytes || !keyVersion)
        throw new Error('Private fixture secret unavailable');
      return { bytes, keyVersion };
    },
  };
  const settings: OAuthClientPluginSettings = {
    clients: [
      {
        id: 'orders',
        issuer: server.issuer,
        clientId: server.clientId,
        clientSecretRef: 'client/secret',
        redirectUri: server.redirectUri,
        allowedAudiences: [server.audience],
        allowedScopes: ['openid', 'orders.read'],
      },
    ],
    secretProvider: provider,
    stateStore: { store: memory.store, securityLevel: 'test-only', operationTimeoutMs: 5000 },
    maxStateTtlMs: 300000,
    stateEncryptionKeyRefs: ['state/encryption/v1'],
    stateMacKeyRefs: ['state/mac/v1'],
    allowInsecureLoopback: true,
    authority: {
      async require(_action, hint) {
        const current = owner();
        if (
          !state.primary ||
          !state.enabled ||
          (hint &&
            (hint.issuer !== issuer ||
              hint.subject !== account ||
              hint.tenant?.tenantId !== current.tenant?.tenantId))
        )
          throw new Error('Private runtime authority denied');
        return current;
      },
    },
  };
  const instance = async () => {
    const destination = new Writable({
      write(chunk: Buffer, _encoding, done) {
        logs.push(chunk.toString());
        done();
      },
    });
    destinations.push(destination);
    const app = await createApplication({
      service: { name: 'oauth-unit', version: '1.0.0', environment: 'test' },
      logging: { level: observed ? 'debug' : 'silent' },
      ...(observed ? { telemetry: { mode: 'standard' as const, samplingRatio: 1 } } : {}),
      plugins: [
        loggingPlugin({ destination }),
        ...(observed
          ? [
              telemetryPlugin({
                endpoint: server.issuer,
                allowInsecureLoopback: true,
                exportIntervalMs: 1000,
                exportTimeoutMs: 1000,
              }),
            ]
          : []),
        cryptoPlugin({
          secrets: provider,
          encryptionKeyRefs: settings.stateEncryptionKeyRefs,
          signingKeyRefs: settings.stateMacKeyRefs,
          policy: {
            maxConcurrent: 32,
            timeoutMs: 5000,
            maxInputBytes: 32768,
            maxOutputBytes: 32768,
          },
        }),
        oauthClientPlugin(settings),
      ],
    });
    applications.push(app);
    await app.start();
    return { app, oauth: app.resolve<OAuthClientService>(OAUTH_CLIENT_CAPABILITY) };
  };
  try {
    const first = await instance(),
      second = await instance();
    return {
      server,
      memory,
      state,
      owner,
      settings,
      material,
      versions,
      logs,
      first,
      second,
      instance,
      async close() {
        try {
          await Promise.all(applications.map((app) => app.stop()));
        } finally {
          for (const bytes of material.values()) bytes.fill(0);
          for (const destination of destinations) destination.destroy();
          await server.close();
        }
      },
    };
  } catch (error) {
    try {
      await Promise.all(applications.map((app) => app.stop()));
    } finally {
      for (const bytes of material.values()) bytes.fill(0);
      for (const destination of destinations) destination.destroy();
      await server.close();
    }
    throw error;
  }
}
