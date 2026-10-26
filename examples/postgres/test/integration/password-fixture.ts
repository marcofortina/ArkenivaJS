// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { passwordPlugin, PASSWORD_CAPABILITY } from '@arkenivajs/security-password';
import type {
  PasswordPluginSettings,
  PasswordService,
  IdentitySubject,
} from '@arkenivajs/security-password';
import { sessionFixture } from './session-fixture.js';

/** Actual signed primary authentication and one PostgreSQL transaction spanning all reset effects. */
export async function passwordFixture() {
  const sessions = await sessionFixture(),
    base = sessions.base,
    backend = base.backend,
    accounts = new Map<string, IdentitySubject>(),
    applications: Awaited<ReturnType<typeof createApplication>>[] = [],
    secret = randomBytes(32),
    version = randomUUID();
  const state = {
    authorityAvailable: true,
    secretAvailable: true,
    failCommit: false,
    failAfterPasswordWrite: false,
  };
  const binding = (owner: IdentitySubject) =>
      JSON.stringify([owner.issuer, owner.subject, owner.tenant?.tenantId ?? null]),
    table = backend.schema + '.password_credentials',
    records = backend.schema + '.security_records',
    epochs = backend.schema + '.security_epochs';
  let pending = 0,
    release: (() => void) | undefined,
    barrier: Promise<void> | undefined;
  const primary = async (options?: OperationOptions) => {
    const identity = base.currentIdentity();
    if (!identity) throw new Error('Independent signed primary authentication required');
    base.auth.requireScope(identity, 'password:manage');
    if (
      typeof identity.claims.auth_time !== 'number' ||
      !Number.isSafeInteger(identity.claims.auth_time) ||
      identity.claims.auth_time > Date.now() / 1000 ||
      Date.now() / 1000 - identity.claims.auth_time > 60
    )
      throw new Error('Recent signed primary authentication required');
    const tenant = base.auth.tenantFrom(identity);
    if (!base.auth.isVerifiedTenant(tenant)) throw new Error('Verified tenant membership required');
    const account = await sessions.verifyPrimary(options);
    return account.subject;
  };
  const settings: PasswordPluginSettings = {
    resetStore: base.settings.store,
    secretProvider: {
      async get(reference) {
        if (!state.secretAvailable || reference !== 'fixture/password-reset')
          throw new Error('Fixture external secret unavailable');
        return { bytes: secret, keyVersion: version };
      },
    },
    resetHmacKeyRef: 'fixture/password-reset',
    resetTtlMs: 300000,
    maxResetAttemptsPerHour: 1000,
    policy: {
      minLength: 12,
      memoryCostKiB: 8192,
      timeCost: 1,
      parallelism: 1,
      blockBreachedPasswords: false,
    },
    authority: {
      async require(action, hint, context, options) {
        if (!state.authorityAvailable || !hint) throw new Error('Fixture authority unavailable');
        const account = accounts.get(binding(hint));
        if (!account || !base.auth.isVerifiedTenant(account.tenant))
          throw new Error('Verified account required');
        if (action !== 'password.consume_reset') {
          const caller = await primary(options);
          if (binding(caller) !== binding(hint)) throw new Error('Foreign account denied');
          if (
            action === 'password.create_reset' &&
            (!context.authorization || binding(context.authorization) !== binding(caller))
          )
            throw new Error('Reset authorization mismatch');
        }
        if (
          action === 'password.consume_reset' &&
          base.currentIdentity() &&
          binding(await primary(options)) !== binding(account)
        )
          throw new Error('Authenticated request tenant does not match the reset owner');
        const current = await backend.app.sql.queryOne<{ enabled: boolean }>(
          'main',
          {
            text: `SELECT enabled FROM ${table} WHERE issuer=:issuer AND subject=:subject AND tenant_id=:tenant`,
            bindings: {
              issuer: account.issuer,
              subject: account.subject,
              tenant: account.tenant?.tenantId ?? '',
            },
          },
          options,
        );
        if (!current?.enabled) throw new Error('Disabled or missing account');
        return account;
      },
    },
    resetCommitter: {
      async commitReset(input, options) {
        if (pending > 0) {
          const held = barrier;
          if (--pending === 0) release!();
          await held;
        }
        if (state.failCommit) throw new Error('Fixture transaction unavailable');
        if (input.reset.namespace !== 'password.resets.v1')
          throw new Error('Unapproved reset namespace');
        const account = accounts.get(binding(input.subject));
        if (!account) throw new Error('Unknown account');
        const sessionOwner = createHash('sha256')
          .update(
            await sessions.settings.hmac.digest(
              'arkenivajs.sessions.owner.v1',
              [account.issuer, account.subject, account.tenant?.tenantId ?? ''],
              sessions.settings.hmacKeyRef,
              options,
            ),
          )
          .digest('hex');
        return backend.app.sql.transaction(
          'main',
          async (tx) => {
            const resetRows = await tx.query<{ version: string; owner_key: string; body: string }>(
              {
                text: `SELECT version::text,owner_key,body FROM ${records} WHERE namespace=:namespace AND id=:id AND expires_at>clock_timestamp() FOR UPDATE`,
                bindings: { namespace: input.reset.namespace, id: input.reset.id },
              },
              { ...options, maxRows: 2 },
            );
            if (resetRows.rows.length > 1) throw new Error('Reset lookup must be unique');
            const reset = resetRows.rows[0];
            if (
              !reset ||
              reset.version !== input.reset.version ||
              reset.owner_key !== input.reset.ownerKey
            )
              return { committed: false };
            const row = JSON.parse(reset.body) as { subject: IdentitySubject };
            if (binding(row.subject) !== binding(account))
              throw new Error('Durable reset owner mismatch');
            const currentRows = await tx.query<{ enabled: boolean }>(
              {
                text: `SELECT enabled FROM ${table} WHERE issuer=:issuer AND subject=:subject AND tenant_id=:tenant FOR UPDATE`,
                bindings: {
                  issuer: account.issuer,
                  subject: account.subject,
                  tenant: account.tenant?.tenantId ?? '',
                },
              },
              { ...options, maxRows: 2 },
            );
            if (currentRows.rows.length > 1) throw new Error('Account lookup must be unique');
            const current = currentRows.rows[0];
            if (!current?.enabled) return { committed: false };
            const revision = randomUUID();
            await tx.execute(
              {
                text: `UPDATE ${table} SET phc=:phc,credential_version=:version::uuid WHERE issuer=:issuer AND subject=:subject AND tenant_id=:tenant`,
                bindings: {
                  phc: input.replacement.phc,
                  version: revision,
                  issuer: account.issuer,
                  subject: account.subject,
                  tenant: account.tenant?.tenantId ?? '',
                },
              },
              options,
            );
            if (state.failAfterPasswordWrite)
              throw new Error('Controlled failure before reset and epoch changes');
            await tx.execute(
              {
                text: `DELETE FROM ${records} WHERE namespace=:namespace AND id=:id AND version=:version::uuid`,
                bindings: {
                  namespace: input.reset.namespace,
                  id: input.reset.id,
                  version: input.reset.version,
                },
              },
              options,
            );
            await tx.execute(
              {
                text: `INSERT INTO ${epochs} AS existing(namespace,owner_key,epoch) VALUES(:namespace,:owner,1) ON CONFLICT(namespace,owner_key) DO UPDATE SET epoch=existing.epoch+1`,
                bindings: { namespace: 'sessions.epochs.v1', owner: sessionOwner },
              },
              options,
            );
            return { committed: true, version: revision };
          },
          options,
        );
      },
    },
  };
  const instance = async () => {
    const app = await createApplication({
      service: { name: 'password-postgres-fixture', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      plugins: [loggingPlugin(), passwordPlugin(settings)],
    });
    applications.push(app);
    await app.start();
    return { app, passwords: app.resolve<PasswordService>(PASSWORD_CAPABILITY) };
  };
  try {
    await backend.app.sql.execute('main', {
      text: `CREATE TABLE ${table}(issuer TEXT NOT NULL,subject TEXT NOT NULL,tenant_id TEXT NOT NULL,phc TEXT NOT NULL,credential_version UUID NOT NULL,enabled BOOLEAN NOT NULL DEFAULT true,PRIMARY KEY(issuer,subject,tenant_id))`,
    });
    const first = await instance(),
      second = await instance();
    return {
      settings,
      state,
      sessions,
      base,
      first,
      second,
      async setEnabled(owner: IdentitySubject, enabled: boolean) {
        await backend.app.sql.execute('main', {
          text: `UPDATE ${table} SET enabled=:enabled WHERE issuer=:issuer AND subject=:subject AND tenant_id=:tenant`,
          bindings: {
            enabled,
            issuer: owner.issuer,
            subject: owner.subject,
            tenant: owner.tenant?.tenantId ?? '',
          },
        });
      },
      synchronizeCommits(count: number) {
        if (pending !== 0 || !Number.isSafeInteger(count) || count < 2 || count > 4)
          throw new Error('Invalid commit barrier');
        pending = count;
        barrier = new Promise<void>((resolve) => {
          release = resolve;
        });
      },
      async session(plain: string, claims: Record<string, unknown> = {}) {
        const session = await sessions.session({
          scope: 'password:manage sessions:manage orders.read',
          ...claims,
        });
        accounts.set(binding(session.subject), session.subject);
        const hash = await first.passwords.hash(plain);
        await backend.app.sql.execute('main', {
          text: `INSERT INTO ${table}(issuer,subject,tenant_id,phc,credential_version) VALUES(:issuer,:subject,:tenant,:phc,:version::uuid) ON CONFLICT(issuer,subject,tenant_id) DO UPDATE SET phc=EXCLUDED.phc,credential_version=EXCLUDED.credential_version`,
          bindings: {
            issuer: session.subject.issuer,
            subject: session.subject.subject,
            tenant: session.subject.tenant?.tenantId ?? '',
            phc: hash.phc,
            version: randomUUID(),
          },
        });
        return session;
      },
      async current(owner: IdentitySubject) {
        const row = await backend.app.sql.queryOne<{ phc: string }>('main', {
          text: `SELECT phc FROM ${table} WHERE issuer=:issuer AND subject=:subject AND tenant_id=:tenant`,
          bindings: {
            issuer: owner.issuer,
            subject: owner.subject,
            tenant: owner.tenant?.tenantId ?? '',
          },
        });
        if (!row) throw new Error('Account missing');
        return { scheme: 'argon2id' as const, phc: row.phc };
      },
      async close() {
        try {
          await Promise.all(applications.map((app) => app.stop()));
        } finally {
          secret.fill(0);
          await sessions.close();
        }
      },
    };
  } catch (error) {
    try {
      await Promise.all(applications.map((app) => app.stop()));
    } finally {
      secret.fill(0);
      await sessions.close();
    }
    throw error;
  }
}
