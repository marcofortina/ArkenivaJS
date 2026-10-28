// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createApplication, KitError } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { createAuthService } from '@arkenivajs/security';
import { magicLinksPlugin, MAGICLINK_CAPABILITY } from '@arkenivajs/security-magiclink';
import type { MagicLinkService } from '@arkenivajs/security-magiclink';
import { createPostgresSecurityStateStore } from '../../dist/security-state-store.js';
import { nativeFixtureHmac } from '../magiclink-unit-fixture.js';

interface Start {
  type: 'start';
  schema: string;
  issuer: string;
  bearer: string;
  key: Uint8Array;
}
let database: Awaited<ReturnType<typeof createApplication>> | undefined;
let application: Awaited<ReturnType<typeof createApplication>> | undefined;
let auth: Awaited<ReturnType<typeof createAuthService>> | undefined;
let key: Buffer | undefined;
let magic: MagicLinkService | undefined;
let starting = false,
  consuming = false;
async function close() {
  try {
    await application?.stop();
  } finally {
    try {
      await auth?.close();
    } finally {
      await database?.stop();
      key?.fill(0);
    }
  }
}
async function start(input: Start) {
  if (starting) throw new Error('The worker was already started');
  starting = true;
  key = Buffer.from(input.key);
  if (key.length !== 32) throw new Error('Invalid ephemeral fixture key');
  const authority = await createAuthService({
    issuer: input.issuer,
    audience: 'api://mfa-fixture',
    environment: 'test',
    allowInsecureLoopback: true,
    algorithms: ['RS256'],
    authorizeTenant: (_identity, tenant) => tenant === 'tenant-a',
  });
  auth = authority;
  database = await createApplication({
    service: { name: 'magiclink-process-database', version: '1.0.0', environment: 'test' },
    plugins: [postgresPlugin()],
    databases: { main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 1 } },
  });
  await database.start();
  application = await createApplication({
    service: { name: 'magiclink-process', version: '1.0.0', environment: 'test' },
    logging: { level: 'silent' },
    plugins: [
      loggingPlugin(),
      magicLinksPlugin({
        stateStore: {
          store: createPostgresSecurityStateStore(database.sql, 'main', input.schema),
          securityLevel: 'test-only',
          operationTimeoutMs: 5000,
        },
        hmac: nativeFixtureHmac(key),
        signingKeyRef: 'fixture/magiclink',
        trustedBaseUrl: 'https://identity.fixture.invalid/confirm',
        ttlMs: 60000,
        maxClaimsPerHour: 8,
        authority: {
          async require(action, hint, context) {
            const identity = await authority.verifyBearer(input.bearer);
            authority.requireScope(identity, 'magiclink:manage');
            const tenant = authority.tenantFrom(identity);
            if (
              !authority.isVerifiedTenant(tenant) ||
              (hint && (hint.issuer !== identity.issuer || hint.subject !== identity.subject)) ||
              (action.startsWith('magiclink.consume.') &&
                context.magicLink?.tenantId !== tenant.tenantId)
            )
              throw new Error('The independent signed account policy denied the operation');
            return Object.freeze({ issuer: identity.issuer, subject: identity.subject, tenant });
          },
        },
      }),
    ],
  });
  await application.start();
  magic = application.resolve<MagicLinkService>(MAGICLINK_CAPABILITY);
  process.send?.({ type: 'ready' });
}
process.on('message', (message: Start | { type: 'consume'; token: string }) => {
  void (async () => {
    if (message.type === 'start') {
      await start(message);
      return;
    }
    if (message.type !== 'consume' || !magic || consuming)
      throw new Error('Invalid worker operation');
    consuming = true;
    let result: string;
    try {
      await magic.consume(message.token, { method: 'POST', purpose: 'login' });
      result = 'accepted';
    } catch (error) {
      result = error instanceof KitError ? error.code : 'EK_INTERNAL';
    }
    await close();
    process.send?.({ type: 'result', result }, () => process.disconnect());
  })().catch(async () => {
    await close().catch(() => undefined);
    process.send?.({ type: 'failed' }, () => process.disconnect());
    process.exitCode = 1;
  });
});
process.once('SIGTERM', () => {
  void close().finally(() => process.exit(1));
});
