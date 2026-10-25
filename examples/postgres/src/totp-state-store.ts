// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import type {
  SqlProvider,
  SqlTransaction,
  MfaSubjectContext,
  MfaSealedSecret,
} from '@arkenivajs/core';
import type {
  TotpComponent,
  TotpStateStore,
  TotpPendingEnrollment,
  TotpFactorRecord,
} from '@arkenivajs/security-totp';
import {
  mfaTable,
  mfaText as text,
  mfaId as id,
  mfaObject as object,
  mfaInstant as instant,
  mfaPolicyError as invalid,
  mfaStorage as storage,
} from './mfa-store-support.js';
import { createPostgresMfaStateStore, createPostgresMfaStateTable } from './mfa-state-store.js';

const hash = (value: string) => createHash('sha256').update(value).digest('hex');
function integer(value: unknown, minimum = 0): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw invalid();
}
function owner(issuer: unknown, subject: unknown, tenant?: unknown) {
  text(issuer);
  text(subject);
  if (tenant !== undefined) text(tenant);
  return {
    owner: hash(JSON.stringify(['arkenivajs-totp-owner-v1', issuer, subject, tenant ?? null])),
    issuer,
    subject,
    tenant: tenant ?? (null as string | null),
  };
}
function context(subject: MfaSubjectContext) {
  const record = object(subject, [
    'issuer',
    'subject',
    'tenant',
    'primarySessionId',
    'authenticatedAt',
  ]);
  text(record.primarySessionId);
  instant(record.authenticatedAt);
  const tenant =
    record.tenant === undefined
      ? undefined
      : object(record.tenant, ['tenantId', 'identity', 'verifiedAt', 'source']).tenantId;
  return { ...owner(record.issuer, record.subject, tenant), session: record.primarySessionId };
}
function bindings(scope: ReturnType<typeof owner>) {
  return { owner: scope.owner, issuer: scope.issuer, subject: scope.subject, tenant: scope.tenant };
}
function sealed(value: unknown): MfaSealedSecret {
  const secret = object(value, ['keyId', 'ciphertext', 'nonce', 'tag']);
  for (const field of ['keyId', 'ciphertext', 'nonce', 'tag']) text(secret[field]);
  return Object.freeze(secret) as unknown as MfaSealedSecret;
}
function pending(value: unknown): TotpPendingEnrollment {
  const record = object(value, [
    'id',
    'issuer',
    'subject',
    'tenantId',
    'primarySessionId',
    'secret',
    'expiresAt',
  ]);
  id(record.id);
  owner(record.issuer, record.subject, record.tenantId);
  text(record.primarySessionId);
  instant(record.expiresAt);
  record.secret = sealed(record.secret);
  return Object.freeze(record) as unknown as TotpPendingEnrollment;
}
function decode(value: unknown): unknown {
  if (typeof value !== 'string' || value.length > 16384) throw invalid();
  return JSON.parse(value);
}
function count(value: unknown): number {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) throw invalid();
  const parsed = Number(value);
  integer(parsed);
  return parsed;
}
function same(
  record: { issuer: string; subject: string; tenantId?: string },
  scope: ReturnType<typeof owner>,
) {
  if (
    record.issuer !== scope.issuer ||
    record.subject !== scope.subject ||
    (record.tenantId ?? null) !== scope.tenant
  )
    throw invalid();
}

/** Create owned reference tables; pending rows retain consumed IDs as replay tombstones. */
export async function createPostgresTotpTables(
  sql: SqlProvider,
  connection: string,
  schema: string,
): Promise<void> {
  const accounts = mfaTable(schema, 'totp_accounts'),
    enrollments = mfaTable(schema, 'totp_pending'),
    recovery = mfaTable(schema, 'totp_recovery');
  text(connection);
  await createPostgresMfaStateTable(sql, connection, schema);
  await storage(async () => {
    await sql.execute(connection, {
      text: `CREATE TABLE ${accounts} (owner TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL, tenant_id TEXT, generation BIGINT NOT NULL DEFAULT 0 CHECK(generation>=0 AND generation<=9007199254740991), active BOOLEAN NOT NULL DEFAULT FALSE, factor_id TEXT, last_step BIGINT, body JSONB)`,
    });
    await sql.execute(connection, {
      text: `CREATE TABLE ${enrollments} (id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES ${accounts}(owner), primary_session_id TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, expected_generation BIGINT NOT NULL, consumed BOOLEAN NOT NULL DEFAULT FALSE, body JSONB NOT NULL)`,
    });
    await sql.execute(connection, {
      text: `CREATE TABLE ${recovery} (owner TEXT NOT NULL REFERENCES ${accounts}(owner), lookup TEXT NOT NULL, keyed_hash TEXT NOT NULL, PRIMARY KEY(owner,lookup))`,
    });
  });
}

/**
 * Application-owned durable TOTP reference. The factor service must authenticate and authorize first.
 * One account row serializes activation/revocation/recovery changes; OTP acceptance is an atomic CAS.
 */
export function createPostgresTotpStateStore(
  sql: SqlProvider,
  connection: string,
  schema: string,
  clock: () => number = Date.now,
): TotpComponent<TotpStateStore> {
  const accounts = mfaTable(schema, 'totp_accounts'),
    enrollments = mfaTable(schema, 'totp_pending'),
    recovery = mfaTable(schema, 'totp_recovery');
  text(connection);
  if (typeof clock !== 'function') throw invalid();
  const now = () => {
    const value = clock();
    integer(value);
    const iso = new Date(value).toISOString();
    instant(iso);
    return iso;
  };
  const predicates =
    'owner=:owner AND issuer=:issuer AND subject=:subject AND tenant_id IS NOT DISTINCT FROM :tenant';
  const lock = async (tx: SqlTransaction, scope: ReturnType<typeof owner>, create = false) => {
    if (create)
      await tx.execute({
        text: `INSERT INTO ${accounts} (owner,issuer,subject,tenant_id) VALUES (:owner,:issuer,:subject,:tenant) ON CONFLICT(owner) DO NOTHING`,
        bindings: bindings(scope),
      });
    const row = (
      await tx.query<{ active: boolean; generation: string; factor_id: string | null }>({
        text: `SELECT active,generation::text,factor_id FROM ${accounts} WHERE ${predicates} FOR UPDATE`,
        bindings: bindings(scope),
      })
    ).rows[0];
    if (!row) return null;
    count(row.generation);
    if (typeof row.active !== 'boolean') throw invalid();
    return row;
  };
  const readPending = async (
    tx: SqlTransaction,
    scope: ReturnType<typeof context>,
    enrollmentId: string,
    at: string,
  ) => {
    const row = (
      await tx.query<{ body: string; expected: string; expires_match: boolean }>({
        text: `SELECT body,expected_generation::text AS expected,(body->>'expiresAt')::timestamptz=expires_at AS expires_match FROM ${enrollments} WHERE id=:id AND owner=:owner AND primary_session_id=:session AND NOT consumed AND expires_at>:now::timestamptz`,
        bindings: { id: enrollmentId, owner: scope.owner, session: scope.session, now: at },
      })
    ).rows[0];
    if (!row) return null;
    const value = pending(decode(row.body));
    same(value, scope);
    if (
      value.id !== enrollmentId ||
      value.primarySessionId !== scope.session ||
      row.expires_match !== true ||
      instant(value.expiresAt) <= instant(at)
    )
      throw invalid();
    return { value, generation: count(row.expected) };
  };
  return Object.freeze<TotpComponent<TotpStateStore>>({
    ...createPostgresMfaStateStore(sql, connection, schema),
    usage: 'test-only',
    async putPending(input, options) {
      const record = pending(input),
        scope = owner(record.issuer, record.subject, record.tenantId);
      if (instant(record.expiresAt) <= instant(now())) throw invalid();
      await storage(() =>
        sql.transaction(
          connection,
          async (tx) => {
            const current = await lock(tx, scope, true);
            if (!current) throw invalid();
            await tx.execute({
              text: `INSERT INTO ${enrollments} (id,owner,primary_session_id,expires_at,expected_generation,body) VALUES (:id,:owner,:session,:expires::timestamptz,:generation,:body::jsonb)`,
              bindings: {
                id: record.id,
                owner: scope.owner,
                session: record.primarySessionId,
                expires: record.expiresAt,
                generation: count(current.generation),
                body: JSON.stringify(record),
              },
            });
          },
          options,
        ),
      );
    },
    async getPending(subject, enrollmentId, options) {
      const scope = context(subject);
      id(enrollmentId);
      const at = now();
      return storage(() =>
        sql.transaction(
          connection,
          async (tx) => {
            const current = await lock(tx, scope);
            if (!current) return null;
            const result = await readPending(tx, scope, enrollmentId, at);
            return result && result.generation === count(current.generation) ? result.value : null;
          },
          options,
        ),
      );
    },
    async activatePending(subject, enrollmentId, acceptedStep, at, options) {
      const scope = context(subject);
      id(enrollmentId);
      integer(acceptedStep);
      instant(at);
      return storage(() =>
        sql.transaction(
          connection,
          async (tx) => {
            const current = await lock(tx, scope);
            if (!current) return false;
            const result = await readPending(tx, scope, enrollmentId, at),
              generation = count(current.generation) + 1;
            if (!result || result.generation !== count(current.generation)) return false;
            integer(generation, 1);
            const factor: TotpFactorRecord = {
              id: result.value.id,
              issuer: scope.issuer,
              subject: scope.subject,
              ...(scope.tenant === null ? {} : { tenantId: scope.tenant }),
              secret: result.value.secret,
              generation,
              lastAcceptedStep: acceptedStep,
              enabledAt: at,
            };
            await tx.execute({
              text: `UPDATE ${accounts} SET active=TRUE,generation=:generation,factor_id=:id,last_step=:step,body=:body::jsonb WHERE owner=:owner`,
              bindings: {
                owner: scope.owner,
                generation,
                id: factor.id,
                step: acceptedStep,
                body: JSON.stringify(factor),
              },
            });
            await tx.execute({
              text: `UPDATE ${enrollments} SET consumed=TRUE WHERE owner=:owner`,
              bindings: { owner: scope.owner },
            });
            await tx.execute({
              text: `DELETE FROM ${recovery} WHERE owner=:owner`,
              bindings: { owner: scope.owner },
            });
            return true;
          },
          options,
        ),
      );
    },
    async getFactor(subject, options) {
      const scope = context(subject);
      return storage(async () => {
        const row = await sql.queryOne<{
          body: string;
          generation: string;
          last_step: string;
          factor_id: string;
        }>(
          connection,
          {
            text: `SELECT body,generation::text,last_step::text,factor_id FROM ${accounts} WHERE ${predicates} AND active`,
            bindings: bindings(scope),
          },
          options,
        );
        if (!row) return null;
        const value = object(decode(row.body), [
          'id',
          'issuer',
          'subject',
          'tenantId',
          'secret',
          'generation',
          'lastAcceptedStep',
          'enabledAt',
        ]);
        id(value.id);
        owner(value.issuer, value.subject, value.tenantId);
        instant(value.enabledAt);
        integer(value.generation, 1);
        integer(value.lastAcceptedStep);
        const record = { ...value, secret: sealed(value.secret) } as unknown as TotpFactorRecord;
        same(record, scope);
        if (
          record.id !== row.factor_id ||
          record.generation !== count(row.generation) ||
          record.lastAcceptedStep !== count(row.last_step)
        )
          throw invalid();
        return Object.freeze(record);
      });
    },
    async acceptStepIfGreater(subject, factorId, generation, step, options) {
      const scope = context(subject);
      id(factorId);
      integer(generation, 1);
      integer(step);
      return storage(async () => {
        const row = await sql.queryOne<{ won: boolean }>(
          connection,
          {
            text: `UPDATE ${accounts} SET last_step=:step,body=jsonb_set(body,'{lastAcceptedStep}',to_jsonb(:step::bigint)) WHERE ${predicates} AND active AND factor_id=:factor AND generation=:generation AND (last_step IS NULL OR last_step<:step) RETURNING TRUE AS won`,
            bindings: { ...bindings(scope), factor: factorId, generation, step },
          },
          options,
        );
        return row?.won === true;
      });
    },
    async revokeFactor(subject, factorId, options) {
      const scope = context(subject);
      id(factorId);
      return storage(() =>
        sql.transaction(
          connection,
          async (tx) => {
            const current = await lock(tx, scope);
            if (!current || !current.active || current.factor_id !== factorId) return false;
            const generation = count(current.generation) + 1;
            integer(generation, 1);
            await tx.execute({
              text: `UPDATE ${accounts} SET active=FALSE,generation=:generation,body=NULL WHERE owner=:owner`,
              bindings: { owner: scope.owner, generation },
            });
            await tx.execute({
              text: `UPDATE ${enrollments} SET consumed=TRUE WHERE owner=:owner`,
              bindings: { owner: scope.owner },
            });
            await tx.execute({
              text: `DELETE FROM ${recovery} WHERE owner=:owner`,
              bindings: { owner: scope.owner },
            });
            return true;
          },
          options,
        ),
      );
    },
    async replaceRecoveryHashes(subject, hashes, options) {
      const scope = context(subject);
      if (!Array.isArray(hashes) || hashes.length > 100 || new Set(hashes).size !== hashes.length)
        throw invalid();
      const records = hashes.map((value) => {
        text(value);
        return { lookup: hash(value), value };
      });
      await storage(() =>
        sql.transaction(
          connection,
          async (tx) => {
            const current = await lock(tx, scope);
            if (!current?.active) throw invalid();
            await tx.execute({
              text: `DELETE FROM ${recovery} WHERE owner=:owner`,
              bindings: { owner: scope.owner },
            });
            await tx.execute({
              text: `INSERT INTO ${recovery} (owner,lookup,keyed_hash) SELECT :owner,value->>'lookup',value->>'value' FROM jsonb_array_elements(:records::jsonb)`,
              bindings: { owner: scope.owner, records: JSON.stringify(records) },
            });
          },
          options,
        ),
      );
    },
    async consumeRecoveryHash(subject, keyedHash, options) {
      const scope = context(subject);
      text(keyedHash);
      return storage(() =>
        sql.transaction(
          connection,
          async (tx) => {
            const current = await lock(tx, scope);
            if (!current?.active) return false;
            const result = await tx.query<{ won: boolean }>({
              text: `DELETE FROM ${recovery} WHERE owner=:owner AND lookup=:lookup AND keyed_hash=:value RETURNING TRUE AS won`,
              bindings: { owner: scope.owner, lookup: hash(keyedHash), value: keyedHash },
            });
            return result.rows.length === 1 && result.rows[0]?.won === true;
          },
          options,
        ),
      );
    },
  });
}
