// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type {
  MfaChallengeRecord,
  MfaStateStore,
  OperationOptions,
  SqlProvider,
} from '@arkenivajs/core';
import { copyData } from '@arkenivajs/core/support';

const fields = [
  'id',
  'purpose',
  'issuer',
  'subject',
  'tenantId',
  'primarySessionId',
  'rpId',
  'challengeDigest',
  'expiresAt',
  'createdAt',
] as const;
const purposes: readonly string[] = [
  'totp-enroll',
  'webauthn-register',
  'webauthn-authenticate',
  'webauthn-passwordless',
];
const invalid = () =>
  new KitError({ code: 'EK_MFA_POLICY', message: 'Invalid MFA challenge storage input' });

function text(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length < 1 || value.length > 1024) throw invalid();
  for (const character of value)
    if (character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127) throw invalid();
}

function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  let owned: unknown;
  try {
    owned = copyData(value);
  } catch {
    throw invalid();
  }
  if (!owned || typeof owned !== 'object' || Array.isArray(owned)) throw invalid();
  const record = owned as Record<string, unknown>;
  if (Object.keys(record).some((key) => !keys.includes(key))) throw invalid();
  return record;
}

function instant(value: unknown): number {
  text(value);
  const parsed = Date.parse(value);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value) ||
    !Number.isFinite(parsed) ||
    new Date(parsed).toISOString().slice(0, 19) !== value.slice(0, 19)
  )
    throw invalid();
  return parsed;
}

function identity(value: unknown): asserts value is string {
  text(value);
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(value)) throw invalid();
}

function record(value: unknown): MfaChallengeRecord {
  const owned = object(value, fields);
  identity(owned.id);
  if (typeof owned.purpose !== 'string' || !purposes.includes(owned.purpose)) throw invalid();
  text(owned.issuer);
  for (const key of ['subject', 'tenantId', 'primarySessionId', 'rpId'])
    if (Object.hasOwn(owned, key)) text(owned[key]);
  if (typeof owned.challengeDigest !== 'string' || !/^[a-f0-9]{64}$/.test(owned.challengeDigest))
    throw invalid();
  if (instant(owned.expiresAt) <= instant(owned.createdAt)) throw invalid();
  return Object.freeze(owned) as unknown as MfaChallengeRecord;
}

function table(schema: string): string {
  if (process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'MFA storage example requires a disposable PostgreSQL fixture',
    });
  if (typeof schema !== 'string' || !/^mfa_[a-f0-9]{24}$/.test(schema)) throw invalid();
  // Only a caller-owned random test namespace is interpolated; all record values remain SQL binds.
  return schema + '.mfa_challenges';
}

async function storage<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (cause) {
    if (cause instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(cause.code)) throw cause;
    throw new KitError({
      code: 'EK_MFA_STORAGE',
      message: 'MFA challenge storage is unavailable',
      cause,
    });
  }
}

/** Create the table only inside an already-created, owned disposable example schema. */
export async function createPostgresMfaStateTable(
  sql: SqlProvider,
  connection: string,
  schema: string,
): Promise<void> {
  const name = table(schema);
  text(connection);
  await storage(() =>
    sql.execute(connection, {
      text: `CREATE TABLE ${name} (
      id TEXT PRIMARY KEY, purpose TEXT NOT NULL, issuer TEXT NOT NULL,
      subject TEXT, tenant_id TEXT, primary_session_id TEXT, rp_id TEXT,
      expires_at TIMESTAMPTZ NOT NULL, body JSONB NOT NULL
    )`,
    }),
  );
}

/**
 * Application-owned reference adapter for the shared challenge SPI, not a factor service.
 * PostgreSQL performs owner matching and deletion in one statement across processes.
 * This example is intentionally restricted to an explicitly disposable database.
 */
export function createPostgresMfaStateStore(
  sql: SqlProvider,
  connection: string,
  schema: string,
): MfaStateStore {
  const name = table(schema);
  text(connection);
  return Object.freeze({
    async createChallenge(input: MfaChallengeRecord, options?: OperationOptions): Promise<void> {
      const challenge = record(input);
      await storage(() =>
        sql.execute(
          connection,
          {
            text: `INSERT INTO ${name}
          (id,purpose,issuer,subject,tenant_id,primary_session_id,rp_id,expires_at,body)
          VALUES (:id,:purpose,:issuer,:subject,:tenant,:session,:rp,:expires::timestamptz,:body::jsonb)`,
            bindings: {
              id: challenge.id,
              purpose: challenge.purpose,
              issuer: challenge.issuer,
              subject: challenge.subject ?? null,
              tenant: challenge.tenantId ?? null,
              session: challenge.primarySessionId ?? null,
              rp: challenge.rpId ?? null,
              expires: challenge.expiresAt,
              body: JSON.stringify(challenge),
            },
          },
          options,
        ),
      );
    },
    async claimChallenge(
      input: Parameters<MfaStateStore['claimChallenge']>[0],
      options?: OperationOptions,
    ): Promise<MfaChallengeRecord | null> {
      const claim = object(input, [
        'id',
        'purpose',
        'issuer',
        'subject',
        'tenantId',
        'primarySessionId',
        'rpId',
        'now',
      ]);
      identity(claim.id);
      if (typeof claim.purpose !== 'string' || !purposes.includes(claim.purpose)) throw invalid();
      text(claim.issuer);
      instant(claim.now);
      for (const key of ['subject', 'tenantId', 'primarySessionId', 'rpId'])
        if (Object.hasOwn(claim, key)) text(claim[key]);
      const result = await storage(() =>
        sql.queryOne<{ body: string }>(
          connection,
          {
            // NULL-safe equality prevents omitted ownership fields from matching an owned ceremony.
            text: `DELETE FROM ${name} WHERE id=:id AND purpose=:purpose AND issuer=:issuer
          AND subject IS NOT DISTINCT FROM :subject
          AND tenant_id IS NOT DISTINCT FROM :tenant
          AND primary_session_id IS NOT DISTINCT FROM :session
          AND rp_id IS NOT DISTINCT FROM :rp
          AND expires_at > :now::timestamptz RETURNING body`,
            bindings: {
              id: String(claim.id),
              purpose: String(claim.purpose),
              issuer: String(claim.issuer),
              subject: claim.subject === undefined ? null : String(claim.subject),
              tenant: claim.tenantId === undefined ? null : String(claim.tenantId),
              session: claim.primarySessionId === undefined ? null : String(claim.primarySessionId),
              rp: claim.rpId === undefined ? null : String(claim.rpId),
              now: String(claim.now),
            },
          },
          options,
        ),
      );
      if (!result) return null;
      // Malformed stored data cannot become a successful verification proof after consumption.
      return storage(async () => {
        // The adapter preserves JSONB as text; this string-only record has an explicit parse bound.
        if (typeof result.body !== 'string' || result.body.length > 16384) throw invalid();
        const consumed = record(JSON.parse(result.body));
        // Denormalized SQL predicates and JSON metadata must describe the same ceremony.
        for (const key of [
          'id',
          'purpose',
          'issuer',
          'subject',
          'tenantId',
          'primarySessionId',
          'rpId',
        ] as const)
          if (consumed[key] !== claim[key]) throw invalid();
        if (instant(consumed.expiresAt) <= instant(claim.now)) throw invalid();
        return consumed;
      });
    },
    async discardChallenge(id: string, options?: OperationOptions): Promise<void> {
      identity(id);
      await storage(() =>
        sql.execute(
          connection,
          {
            text: `DELETE FROM ${name} WHERE id=:id`,
            bindings: { id },
          },
          options,
        ),
      );
    },
  });
}
