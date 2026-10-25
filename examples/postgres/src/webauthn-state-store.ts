// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes } from 'node:crypto';
import type { MfaSubjectContext, SqlProvider, SqlTransaction } from '@arkenivajs/core';
import type {
  WebAuthnStateStore,
  WebAuthnCredentialRecord,
  WebAuthnStateMutationResult,
} from '@arkenivajs/security-webauthn';
import {
  mfaTable,
  mfaText as text,
  mfaObject as object,
  mfaInstant as instant,
  mfaPolicyError as invalid,
  mfaStorage as storage,
} from './mfa-store-support.js';
import { createPostgresMfaStateStore } from './mfa-state-store.js';

const counter = (value: unknown): number => {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xffffffff)
    throw invalid();
  return value as number;
};
function encoded(value: unknown, maximum: number, exact?: number): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum) throw invalid();
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw invalid();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (exact !== undefined && bytes.length !== exact))
    throw invalid();
  return value;
}
function scope(rp: unknown, issuer: unknown, subject: unknown, tenant?: unknown) {
  text(rp);
  text(issuer);
  text(subject);
  if (tenant !== undefined) text(tenant);
  return {
    owner: createHash('sha256')
      .update(JSON.stringify(['arkenivajs-webauthn-owner-v1', rp, issuer, subject, tenant ?? null]))
      .digest('hex'),
    rp,
    issuer,
    subject,
    tenant: tenant ?? (null as string | null),
  };
}
function context(subject: MfaSubjectContext, rp: string) {
  const data = object(subject, [
    'issuer',
    'subject',
    'tenant',
    'primarySessionId',
    'authenticatedAt',
  ]);
  text(data.primarySessionId);
  instant(data.authenticatedAt);
  const tenant =
    data.tenant === undefined
      ? undefined
      : object(data.tenant, ['tenantId', 'identity', 'source', 'verifiedAt']).tenantId;
  return scope(rp, data.issuer, data.subject, tenant);
}
const fields = [
  'credentialId',
  'rpId',
  'issuer',
  'subject',
  'tenantId',
  'userHandle',
  'stateVersion',
  'publicKey',
  'counter',
  'backupEligible',
  'backedUp',
  'transports',
  'registeredAt',
  'revokedAt',
] as const;
const typedArray = Object.getPrototypeOf(Uint8Array.prototype) as object;
const byteLength = Object.getOwnPropertyDescriptor(typedArray, 'byteLength')!.get!;
const copyBytes = Uint8Array.prototype.set;

/** Snapshot public-key bytes separately; the general JSON copier intentionally rejects typed arrays. */
function credential(input: unknown): WebAuthnCredentialRecord {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw invalid();
  const descriptors = Object.getOwnPropertyDescriptors(input),
    plain: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== 'string' || !fields.includes(key as (typeof fields)[number]))
      throw invalid();
    const property = descriptors[key]!;
    if (!('value' in property)) throw invalid();
    if (key !== 'publicKey') plain[key] = property.value;
  }
  const key = descriptors.publicKey?.value as unknown;
  if (!(key instanceof Uint8Array)) throw invalid();
  const size = byteLength.call(key) as number;
  if (size < 1 || size > 16384) throw invalid();
  const owned = new Uint8Array(size);
  copyBytes.call(owned, key);
  const record = object(plain, fields);
  encoded(record.credentialId, 1366);
  scope(record.rpId, record.issuer, record.subject, record.tenantId);
  encoded(record.userHandle, 43, 32);
  text(record.stateVersion);
  counter(record.counter);
  if (
    typeof record.backupEligible !== 'boolean' ||
    typeof record.backedUp !== 'boolean' ||
    (record.backedUp && !record.backupEligible)
  )
    throw invalid();
  instant(record.registeredAt);
  if (record.revokedAt !== undefined) instant(record.revokedAt);
  if (record.transports !== undefined) {
    if (!Array.isArray(record.transports) || record.transports.length > 16) throw invalid();
    const seen = new Set<string>();
    for (const transport of record.transports) {
      text(transport);
      if (transport.length > 64 || seen.has(transport)) throw invalid();
      seen.add(transport);
    }
  }
  return Object.freeze({ ...record, publicKey: owned }) as unknown as WebAuthnCredentialRecord;
}
type Row = {
  rp_id: string;
  credential_id: string;
  owner: string;
  issuer: string;
  subject: string;
  tenant_id: string | null;
  user_handle: string;
  state_version: string;
  counter: string;
  backup_eligible: boolean;
  backed_up: boolean;
  revoked_at: string | null;
  body: string;
};
const projection =
  'rp_id,credential_id,owner,issuer,subject,tenant_id,user_handle,state_version::text,counter::text,backup_eligible,backed_up,revoked_at,body';
function read(row: Row): WebAuthnCredentialRecord {
  if (typeof row.body !== 'string' || Buffer.byteLength(row.body) > 32768) throw invalid();
  const body = object(JSON.parse(row.body), fields);
  const publicKey = encoded(body.publicKey, 21846);
  if (typeof row.counter !== 'string' || !/^\d{1,10}$/.test(row.counter)) throw invalid();
  const value = credential({
    ...body,
    publicKey: Buffer.from(publicKey, 'base64url'),
    stateVersion: row.state_version,
    counter: Number(row.counter),
    backedUp: row.backed_up,
    ...(row.revoked_at === null ? {} : { revokedAt: row.revoked_at }),
  });
  const owner = scope(value.rpId, value.issuer, value.subject, value.tenantId);
  if (
    row.owner !== owner.owner ||
    row.rp_id !== owner.rp ||
    row.issuer !== owner.issuer ||
    row.subject !== owner.subject ||
    row.tenant_id !== owner.tenant ||
    row.credential_id !== value.credentialId ||
    row.user_handle !== value.userHandle ||
    row.backup_eligible !== value.backupEligible
  )
    throw invalid();
  return value;
}

/** Owned reference schema; migration and production retention remain application responsibilities. */
export async function createPostgresWebAuthnTables(
  sql: SqlProvider,
  connection: string,
  schema: string,
): Promise<void> {
  const accounts = mfaTable(schema, 'webauthn_accounts'),
    credentials = mfaTable(schema, 'webauthn_credentials');
  text(connection);
  await storage(async () => {
    await sql.execute(connection, {
      text: `CREATE TABLE ${accounts} (owner TEXT NOT NULL, rp_id TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, tenant_id TEXT, user_handle TEXT NOT NULL CHECK(length(user_handle)=43), UNIQUE NULLS NOT DISTINCT(rp_id,issuer,subject,tenant_id), UNIQUE(rp_id,user_handle), UNIQUE(rp_id,owner,user_handle))`,
    });
    await sql.execute(connection, {
      text: `CREATE TABLE ${credentials} (rp_id TEXT NOT NULL, credential_id TEXT NOT NULL CHECK(length(credential_id) BETWEEN 1 AND 1366), owner TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, tenant_id TEXT, user_handle TEXT NOT NULL, state_version UUID NOT NULL DEFAULT gen_random_uuid(), counter BIGINT NOT NULL CHECK(counter BETWEEN 0 AND 4294967295), backup_eligible BOOLEAN NOT NULL, backed_up BOOLEAN NOT NULL, revoked_at TEXT, body JSONB NOT NULL CHECK(octet_length(body::text)<=32768), PRIMARY KEY(rp_id,credential_id), FOREIGN KEY(rp_id,owner,user_handle) REFERENCES ${accounts}(rp_id,owner,user_handle), CHECK(NOT backed_up OR backup_eligible))`,
    });
  });
}

/**
 * Disposable, application-owned durable adapter using the existing named SQL provider and pool.
 * Authorization belongs to the factor authority. Row locks and full version predicates survive pods.
 */
export function createPostgresWebAuthnStateStore(
  sql: SqlProvider,
  connection: string,
  schema: string,
  clock: () => number = Date.now,
): WebAuthnStateStore & { readonly usage: 'test-only' } {
  const accounts = mfaTable(schema, 'webauthn_accounts'),
    credentials = mfaTable(schema, 'webauthn_credentials'),
    challenges = mfaTable(schema, 'challenges');
  text(connection);
  if (typeof clock !== 'function') throw invalid();
  const lock = async (tx: SqlTransaction, rp: string, id: string) => {
    const row = (
      await tx.query<Row>(
        {
          text: `SELECT ${projection} FROM ${credentials} WHERE rp_id=:rp AND credential_id=:id FOR UPDATE`,
          bindings: { rp, id },
        },
        { maxRows: 1 },
      )
    ).rows[0];
    return row ? read(row) : null;
  };
  const predicates =
    'rp_id=:rp AND credential_id=:id AND owner=:owner AND issuer=:issuer AND subject=:subject AND tenant_id IS NOT DISTINCT FROM :tenant AND user_handle=:handle AND state_version::text=:version AND counter=:previous AND revoked_at IS NULL';
  const mutation = async (
    tx: SqlTransaction,
    statement: Parameters<SqlTransaction['query']>[0],
  ): Promise<WebAuthnStateMutationResult> => {
    const row = (await tx.query<{ version: string }>(statement, { maxRows: 1 })).rows[0];
    if (!row) return { status: 'conflict' };
    text(row.version);
    return { status: 'updated', newVersion: row.version };
  };
  return Object.freeze({
    ...createPostgresMfaStateStore(sql, connection, schema),
    usage: 'test-only' as const,
    async getOrCreateUserHandle(subject, rp, options) {
      const owner = context(subject, rp),
        candidate = randomBytes(32).toString('base64url');
      return storage(async () => {
        const row = await sql.queryOne<{
          owner: string;
          rp_id: string;
          issuer: string;
          subject: string;
          tenant_id: string | null;
          user_handle: string;
        }>(
          connection,
          {
            text: `INSERT INTO ${accounts} AS stored (owner,rp_id,issuer,subject,tenant_id,user_handle) VALUES (:owner,:rp,:issuer,:subject,:tenant,:handle) ON CONFLICT(rp_id,issuer,subject,tenant_id) DO UPDATE SET user_handle=stored.user_handle RETURNING owner,rp_id,issuer,subject,tenant_id,user_handle`,
            bindings: { ...owner, handle: candidate },
          },
          options,
        );
        if (
          !row ||
          row.owner !== owner.owner ||
          row.rp_id !== owner.rp ||
          row.issuer !== owner.issuer ||
          row.subject !== owner.subject ||
          row.tenant_id !== owner.tenant
        )
          throw invalid();
        return encoded(row.user_handle, 43, 32);
      });
    },
    async listCredentials(subject, rp, options) {
      const owner = context(subject, rp);
      return storage(async () => {
        const rows = (
          await sql.query<Row>(
            connection,
            {
              text: `SELECT ${projection} FROM ${credentials} WHERE rp_id=:rp AND owner=:owner AND issuer=:issuer AND subject=:subject AND tenant_id IS NOT DISTINCT FROM :tenant AND revoked_at IS NULL ORDER BY credential_id`,
              bindings: owner,
            },
            { ...options, maxRows: 100 },
          )
        ).rows;
        return rows.map(read);
      });
    },
    async getCredential(id, rp, options) {
      encoded(id, 1366);
      text(rp);
      return storage(async () => {
        const row = await sql.queryOne<Row>(
          connection,
          {
            text: `SELECT ${projection} FROM ${credentials} WHERE rp_id=:rp AND credential_id=:id`,
            bindings: { rp, id },
          },
          options,
        );
        return row ? read(row) : null;
      });
    },
    async verifyUserHandleBinding(input, options) {
      const data = object(input, ['credentialId', 'rpId', 'userHandle']);
      const id = encoded(data.credentialId, 1366);
      text(data.rpId);
      const rp = data.rpId;
      const handle =
        data.userHandle === undefined || data.userHandle === null
          ? null
          : encoded(data.userHandle, 43, 32);
      return storage(async () => {
        const row = await sql.queryOne<{ valid: boolean }>(
          connection,
          {
            text: `SELECT EXISTS(SELECT 1 FROM ${credentials} c JOIN ${accounts} a ON a.owner=c.owner AND a.rp_id=c.rp_id AND a.user_handle=c.user_handle AND a.issuer=c.issuer AND a.subject=c.subject AND a.tenant_id IS NOT DISTINCT FROM c.tenant_id WHERE c.rp_id=:rp AND c.credential_id=:id AND c.revoked_at IS NULL AND (:handle::text IS NULL OR c.user_handle=:handle)) AS valid`,
            bindings: { rp, id, handle },
          },
          options,
        );
        if (!row || typeof row.valid !== 'boolean') throw invalid();
        return row.valid;
      });
    },
    async insertCredentialIfAbsent(input, options) {
      const record = credential(input),
        owner = scope(record.rpId, record.issuer, record.subject, record.tenantId);
      if (record.revokedAt !== undefined) throw invalid();
      const body = JSON.stringify({
        credentialId: record.credentialId,
        rpId: record.rpId,
        issuer: record.issuer,
        subject: record.subject,
        ...(record.tenantId === undefined ? {} : { tenantId: record.tenantId }),
        userHandle: record.userHandle,
        backupEligible: record.backupEligible,
        ...(record.transports === undefined ? {} : { transports: record.transports }),
        registeredAt: record.registeredAt,
        publicKey: Buffer.from(record.publicKey).toString('base64url'),
      });
      if (Buffer.byteLength(body) > 32768) throw invalid();
      return storage(async () => {
        const result = await sql.execute(
          connection,
          {
            text: `INSERT INTO ${credentials} (rp_id,credential_id,owner,issuer,subject,tenant_id,user_handle,counter,backup_eligible,backed_up,body) SELECT :rp,:id,:owner,:issuer,:subject,:tenant,:handle,:counter,:eligible,:backed,:body::jsonb FROM ${accounts} WHERE owner=:owner AND rp_id=:rp AND issuer=:issuer AND subject=:subject AND tenant_id IS NOT DISTINCT FROM :tenant AND user_handle=:handle ON CONFLICT(rp_id,credential_id) DO NOTHING RETURNING credential_id`,
            bindings: {
              ...owner,
              id: record.credentialId,
              handle: record.userHandle,
              counter: record.counter,
              eligible: record.backupEligible,
              backed: record.backedUp,
              body,
            },
          },
          options,
        );
        if (result.rowCount !== 0 && result.rowCount !== 1) throw invalid();
        return result.rowCount === 1;
      });
    },
    async advanceCounter(input, options) {
      const data = object(input, [
        'credentialId',
        'rpId',
        'issuer',
        'subject',
        'tenantId',
        'userHandle',
        'expectedVersion',
        'previousCounter',
        'newCounter',
        'backedUp',
      ]);
      const id = encoded(data.credentialId, 1366),
        owner = scope(data.rpId, data.issuer, data.subject, data.tenantId),
        handle = encoded(data.userHandle, 43, 32);
      text(data.expectedVersion);
      const previous = counter(data.previousCounter),
        next = counter(data.newCounter);
      if (
        ((previous !== 0 || next !== 0) && next <= previous) ||
        typeof data.backedUp !== 'boolean'
      )
        throw invalid();
      const version = data.expectedVersion,
        backed = data.backedUp;
      return storage(() =>
        sql.transaction(
          connection,
          async (tx) => {
            const current = await lock(tx, owner.rp, id);
            if (!current) return { status: 'not-found' };
            if (
              scope(current.rpId, current.issuer, current.subject, current.tenantId).owner !==
                owner.owner ||
              current.userHandle !== handle
            )
              return { status: 'conflict' };
            if (current.revokedAt !== undefined) return { status: 'revoked' };
            if (current.stateVersion !== version || current.counter !== previous)
              return { status: 'conflict' };
            if (backed && !current.backupEligible) throw invalid();
            return mutation(tx, {
              text: `UPDATE ${credentials} SET counter=:next,backed_up=:backed,state_version=gen_random_uuid() WHERE ${predicates} RETURNING state_version::text AS version`,
              bindings: { ...owner, id, handle, version, previous, next, backed },
            });
          },
          options,
        ),
      );
    },
    async revokeCredential(subject, rp, id, expectedVersion, options) {
      const owner = context(subject, rp);
      encoded(id, 1366);
      text(expectedVersion);
      const at = clock();
      if (!Number.isSafeInteger(at) || at < 0 || at > 253402300799999) throw invalid();
      const revoked = new Date(at).toISOString();
      return storage(() =>
        sql.transaction(
          connection,
          async (tx) => {
            const current = await lock(tx, rp, id);
            if (
              !current ||
              scope(current.rpId, current.issuer, current.subject, current.tenantId).owner !==
                owner.owner
            )
              return { status: 'not-found' };
            if (current.revokedAt !== undefined) return { status: 'revoked' };
            if (current.stateVersion !== expectedVersion) return { status: 'conflict' };
            const result = await mutation(tx, {
              text: `UPDATE ${credentials} SET revoked_at=:revoked,state_version=gen_random_uuid() WHERE ${predicates} RETURNING state_version::text AS version`,
              bindings: {
                ...owner,
                id,
                handle: current.userHandle,
                version: expectedVersion,
                previous: current.counter,
                revoked,
              },
            });
            if (result.status === 'updated')
              await tx.execute({
                text: `DELETE FROM ${challenges} WHERE rp_id=:rp AND issuer=:issuer AND subject=:subject AND tenant_id IS NOT DISTINCT FROM :tenant AND purpose IN ('webauthn-register','webauthn-authenticate')`,
                bindings: {
                  rp: owner.rp,
                  issuer: owner.issuer,
                  subject: owner.subject,
                  tenant: owner.tenant,
                },
              });
            return result;
          },
          options,
        ),
      );
    },
  } satisfies WebAuthnStateStore & { usage: 'test-only' });
}
