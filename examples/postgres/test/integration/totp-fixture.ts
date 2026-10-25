// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import type { Application, MfaSubjectContext, Identity } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { createAuthService } from '@arkenivajs/security';
import type { ManagedAuthService } from '@arkenivajs/security';
import {
  createPostgresTotpTables,
  createPostgresTotpStateStore,
} from '../../dist/totp-state-store.js';
import {
  createPostgresMfaRateLimitTable,
  createPostgresMfaRateLimitStore,
} from '../../dist/mfa-rate-limit-store.js';
import {
  createPostgresMfaEvidenceTable,
  createPostgresMfaEvidenceStore,
} from '../../dist/mfa-evidence-store.js';
import { createDisposableMfaSecretProtector } from '../../dist/mfa-secret-protector.js';
import { startMfaIssuer } from './mfa-issuer.js';

/** Owned live SQL state and a real signed primary identity; no production account is contacted. */
export async function totpFixture() {
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  assert.ok(process.env.DATABASE_URL, 'DATABASE_URL is required');
  const issuer = await startMfaIssuer(),
    schema = 'mfa_' + randomBytes(12).toString('hex'),
    encryptionKey = randomBytes(32);
  let app: Application | undefined,
    auth: ManagedAuthService | undefined,
    created = false,
    closed = false,
    clock = Date.now();
  const close = async () => {
    if (closed) return;
    closed = true;
    try {
      if (created) await app!.sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
    } finally {
      try {
        await app?.stop();
      } finally {
        try {
          await auth?.close();
        } finally {
          encryptionKey.fill(0);
          await issuer.close();
        }
      }
    }
  };
  try {
    app = await createApplication({
      service: { name: 'totp-storage-fixture', version: '1.0.0', environment: 'test' },
      plugins: [postgresPlugin()],
      databases: {
        main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 4 },
      },
    });
    await app.start();
    await app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
    created = true;
    await createPostgresTotpTables(app.sql, 'main', schema);
    await createPostgresMfaRateLimitTable(app.sql, 'main', schema);
    await createPostgresMfaEvidenceTable(app.sql, 'main', schema);
    auth = await createAuthService({
      issuer: issuer.authority,
      audience: 'api://mfa-fixture',
      environment: 'test',
      allowInsecureLoopback: true,
      algorithms: ['RS256'],
    });
    const verifier = auth,
      owners = new WeakMap<MfaSubjectContext, Identity>();
    const subject = async (claims: Record<string, unknown> = {}) => {
      const identity = await verifier.verifyBearer(
        await issuer.bearer({ ...claims, auth_time: Math.floor(clock / 1000) }),
      );
      const tenant =
        identity.claims.tenant_id === undefined ? undefined : verifier.tenantFrom(identity);
      const value = Object.freeze({
        issuer: identity.issuer,
        subject: identity.subject,
        ...(tenant ? { tenant } : {}),
        primarySessionId: String(identity.claims.sid),
        authenticatedAt: new Date((identity.claims.auth_time as number) * 1000).toISOString(),
      });
      owners.set(value, identity);
      return value;
    };
    const protector = createDisposableMfaSecretProtector(
      'encryption-first',
      async () => encryptionKey,
    );
    return {
      schema,
      app,
      auth: verifier,
      owners,
      subject,
      protector,
      // Copies are used only over owned child stdin for cross-process tests, never persisted or printed.
      workerEncryptionKey: () => new Uint8Array(encryptionKey),
      clock: () => clock,
      setTime(value: number) {
        clock = value;
      },
      state: createPostgresTotpStateStore(app.sql, 'main', schema, () => clock),
      limiter: createPostgresMfaRateLimitStore(app.sql, 'main', schema),
      evidence: createPostgresMfaEvidenceStore(app.sql, 'main', schema),
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
