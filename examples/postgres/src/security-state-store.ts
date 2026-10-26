// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import type { OperationOptions, SqlProvider, SqlTransaction } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type {
  DurableMutationReceipt,
  SecurityAtomicMutation,
  SecurityIndexedRecord,
  SecurityTransactionalStore,
} from './security-store-contracts.js';
import {
  Conflict,
  captureSql,
  fields,
  instant,
  integer,
  invalid,
  object,
  owner,
  reference,
  runtime,
  table,
  version,
} from './security-store-support.js';

export type {
  DurableMutationReceipt,
  SecurityAtomicMutation,
  SecurityIndexedRecord,
  SecurityStateStore,
  SecurityTransactionalStore,
} from './security-store-contracts.js';
type Mutation = Omit<SecurityAtomicMutation, 'ownerKey'> & { readonly ownerKey?: string };
interface Row {
  id: string;
  owner_key: string;
  version: string;
  expires_at: string | null;
  body: string;
  live: boolean;
}
const projection = `id,owner_key,version::text,to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,body::text AS body,(expires_at IS NULL OR expires_at>clock_timestamp()) AS live`;

/** Only an explicitly disposable caller-owned schema receives example DDL. */
export async function createPostgresSecurityStateTables(
  sql: SqlProvider,
  connection: string,
  schema: string,
): Promise<void> {
  reference(connection, 128);
  const backend = captureSql(sql);
  const records = table(schema, 'records'),
    claims = table(schema, 'claims'),
    epochs = table(schema, 'epochs'),
    run = runtime();
  await run(undefined, true, (options) =>
    backend.transaction(
      connection,
      async (tx) => {
        // Keep serialized JSON as bounded text; JSONB numeric expansion must not amplify reads.
        await tx.execute(
          {
            text: `CREATE TABLE ${records} (namespace TEXT NOT NULL CHECK(length(namespace) BETWEEN 1 AND 128),id TEXT NOT NULL CHECK(length(id) BETWEEN 1 AND 256),owner_key TEXT NOT NULL CHECK(length(owner_key) BETWEEN 16 AND 256),version UUID NOT NULL,expires_at TIMESTAMPTZ,body TEXT NOT NULL CHECK(octet_length(body)<=32768 AND jsonb_typeof(body::jsonb)='object'),PRIMARY KEY(namespace,id))`,
          },
          options,
        );
        await tx.execute(
          {
            text: `CREATE INDEX security_records_owner ON ${records}(namespace,owner_key,id) INCLUDE(expires_at)`,
          },
          options,
        );
        await tx.execute(
          {
            text: `CREATE TABLE ${claims}(namespace TEXT NOT NULL,digest TEXT NOT NULL,expires_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(namespace,digest))`,
          },
          options,
        );
        await tx.execute(
          {
            text: `CREATE TABLE ${epochs}(namespace TEXT NOT NULL,owner_key TEXT NOT NULL,epoch BIGINT NOT NULL CHECK(epoch BETWEEN 1 AND 9007199254740991),PRIMARY KEY(namespace,owner_key))`,
          },
          options,
        );
      },
      options,
    ),
  );
}
function nextRecord(
  input: Readonly<Record<string, unknown>>,
  expectedOwner?: string,
): Readonly<Record<string, unknown>> & { readonly ownerKey: string } {
  const captured = fields(input),
    ownerKey = Object.hasOwn(captured, 'ownerKey') ? captured.ownerKey : expectedOwner;
  owner(ownerKey);
  if (expectedOwner !== undefined && ownerKey !== expectedOwner) throw invalid();
  if (captured.expiresAt !== undefined) instant(captured.expiresAt);
  const result = freezeData({ ...captured, ownerKey });
  if (Object.keys(result).length > 64 || Buffer.byteLength(JSON.stringify(result)) > 32768)
    throw invalid();
  return result;
}
function row(input: Row): SecurityIndexedRecord {
  reference(input.id);
  owner(input.owner_key);
  version(input.version);
  if (
    input.version === null ||
    typeof input.body !== 'string' ||
    Buffer.byteLength(input.body) > 32768 ||
    typeof input.live !== 'boolean'
  )
    throw invalid();
  const parsed = nextRecord(JSON.parse(input.body) as Record<string, unknown>, input.owner_key);
  if ((parsed.expiresAt ?? null) !== input.expires_at) throw invalid();
  if (input.expires_at !== null) instant(input.expires_at);
  return Object.freeze({
    id: input.id,
    ownerKey: input.owner_key,
    version: input.version,
    ...(input.expires_at === null ? {} : { expiresAt: input.expires_at }),
    fields: parsed,
  });
}

/**
 * Durable reference adapter using only an injected named SQL connection.
 * The application must derive ownerKey through its approved domain-separated HMAC provider.
 * This adapter never authenticates a subject merely because its state was stored successfully.
 */
export function createPostgresSecurityStateStore(
  sql: SqlProvider,
  connection: string,
  schema: string,
): SecurityTransactionalStore & { readonly securityLevel: 'test-only' } {
  reference(connection, 128);
  const backend = captureSql(sql);
  const records = table(schema, 'records'),
    claims = table(schema, 'claims'),
    epochs = table(schema, 'epochs'),
    run = runtime();
  function keys(namespace: string, id: string) {
    reference(namespace, 128);
    reference(id);
  }
  async function mutate(
    mutations: readonly Mutation[],
    options?: OperationOptions,
  ): Promise<DurableMutationReceipt> {
    try {
      return await run(options, true, (operation) =>
        backend.transaction(
          connection,
          async (tx: SqlTransaction) => {
            // Every changed row shares this transaction's fresh revision; old revisions never return.
            const receipt = randomUUID();
            for (const mutation of mutations) {
              const rows = await tx.query<Row>(
                {
                  text: `SELECT ${projection} FROM ${records} WHERE namespace=:namespace AND id=:id FOR UPDATE`,
                  bindings: { namespace: mutation.namespace, id: mutation.id },
                },
                { ...operation, maxRows: 2 },
              );
              if (rows.rows.length > 1) throw invalid();
              const existing = rows.rows[0],
                actual = existing?.live ? row(existing) : undefined;
              if (
                mutation.expectedVersion === null
                  ? actual !== undefined
                  : actual?.version !== mutation.expectedVersion
              )
                throw new Conflict();
              if (
                actual &&
                mutation.ownerKey !== undefined &&
                actual.ownerKey !== mutation.ownerKey
              )
                throw new Conflict();
              if (mutation.next === null) {
                if (existing)
                  await tx.execute(
                    {
                      text: `DELETE FROM ${records} WHERE namespace=:namespace AND id=:id`,
                      bindings: { namespace: mutation.namespace, id: mutation.id },
                    },
                    operation,
                  );
                continue;
              }
              const next = nextRecord(mutation.next, mutation.ownerKey);
              if (actual && actual.ownerKey !== next.ownerKey) throw new Conflict();
              if (existing)
                await tx.execute(
                  {
                    text: `DELETE FROM ${records} WHERE namespace=:namespace AND id=:id`,
                    bindings: { namespace: mutation.namespace, id: mutation.id },
                  },
                  operation,
                );
              const inserted = await tx.query<{ version: string }>(
                {
                  text: `INSERT INTO ${records}(namespace,id,owner_key,version,expires_at,body) VALUES(:namespace,:id,:owner,:version::uuid,:expires::timestamptz,:body) ON CONFLICT(namespace,id) DO NOTHING RETURNING version::text`,
                  bindings: {
                    namespace: mutation.namespace,
                    id: mutation.id,
                    owner: String(next.ownerKey),
                    version: receipt,
                    expires: typeof next.expiresAt === 'string' ? next.expiresAt : null,
                    body: JSON.stringify(next),
                  },
                },
                { ...operation, maxRows: 2 },
              );
              if (inserted.rows.length !== 1 || inserted.rows[0]?.version !== receipt)
                throw new Conflict();
            }
            return Object.freeze({ committed: true, version: receipt });
          },
          operation,
        ),
      );
    } catch (error) {
      if (error instanceof Conflict) return Object.freeze({ committed: false });
      throw error;
    }
  }
  return Object.freeze({
    securityLevel: 'test-only' as const,
    async claimOnce(
      namespace: string,
      digest: string,
      expiresAt: string,
      options?: OperationOptions,
    ) {
      keys(namespace, digest);
      owner(digest);
      instant(expiresAt);
      return run(options, true, async (operation) => {
        // The database clock controls claim expiry, independently of application request data.
        const result = await backend.query<{ digest: string }>(
          connection,
          {
            text: `INSERT INTO ${claims} AS claimed(namespace,digest,expires_at) SELECT :namespace,:digest,:expires::timestamptz WHERE :expires::timestamptz>clock_timestamp() ON CONFLICT(namespace,digest) DO UPDATE SET expires_at=EXCLUDED.expires_at WHERE claimed.expires_at<=clock_timestamp() RETURNING digest`,
            bindings: { namespace, digest, expires: expiresAt },
          },
          { ...operation, maxRows: 2 },
        );
        if (result.rows.length > 1 || (result.rows[0] && result.rows[0].digest !== digest))
          throw invalid();
        return result.rows.length === 1;
      });
    },
    async compareAndSet(
      namespace: string,
      id: string,
      expectedVersion: string | null,
      input: Readonly<Record<string, unknown>> | null,
      options?: OperationOptions,
    ) {
      keys(namespace, id);
      version(expectedVersion);
      const next = input === null ? null : nextRecord(input);
      return mutate(
        [
          {
            namespace,
            id,
            expectedVersion,
            next,
            ...(next === null ? {} : { ownerKey: next.ownerKey }),
          },
        ],
        options,
      );
    },
    async read(namespace: string, id: string, options?: OperationOptions) {
      keys(namespace, id);
      return run(options, false, async (operation) => {
        const result = await backend.queryOne<Row>(
          connection,
          {
            text: `SELECT ${projection} FROM ${records} WHERE namespace=:namespace AND id=:id AND (expires_at IS NULL OR expires_at>clock_timestamp())`,
            bindings: { namespace, id },
          },
          operation,
        );
        if (!result) return null;
        const record = row(result);
        if (!result.live) return null;
        return Object.freeze({ ...record.fields, version: record.version });
      });
    },
    async atomicBatch(input: readonly SecurityAtomicMutation[], options?: OperationOptions) {
      if (
        !Array.isArray(input) ||
        input.length < 1 ||
        input.length > 32 ||
        Reflect.ownKeys(input).length !== input.length + 1
      )
        throw invalid();
      let bytes = 0;
      const seen = new Set<string>(),
        mutations: Mutation[] = [];
      for (let index = 0; index < input.length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
        if (!descriptor || !('value' in descriptor)) throw invalid();
        const fields = object(descriptor.value, [
          'namespace',
          'id',
          'expectedVersion',
          'next',
          'ownerKey',
        ]);
        reference(fields.namespace, 128);
        reference(fields.id);
        owner(fields.ownerKey);
        version(fields.expectedVersion);
        const next =
            fields.next === null
              ? null
              : nextRecord(fields.next as Record<string, unknown>, fields.ownerKey),
          key = JSON.stringify([fields.namespace, fields.id]);
        if (seen.has(key)) throw invalid();
        seen.add(key);
        bytes += next === null ? 0 : Buffer.byteLength(JSON.stringify(next));
        if (bytes > 1048576) throw invalid();
        mutations.push({
          namespace: fields.namespace,
          id: fields.id,
          expectedVersion: fields.expectedVersion,
          ownerKey: fields.ownerKey,
          next,
        });
      }
      // Every process locks the same complete key ordering to avoid reversed-batch deadlocks.
      mutations.sort((left, right) =>
        left.namespace < right.namespace
          ? -1
          : left.namespace > right.namespace
            ? 1
            : left.id < right.id
              ? -1
              : left.id > right.id
                ? 1
                : 0,
      );
      return mutate(mutations, options);
    },
    async listByOwner(
      namespace: string,
      ownerKey: string,
      limit: number,
      options?: OperationOptions,
    ) {
      reference(namespace, 128);
      owner(ownerKey);
      integer(limit, 1000);
      return run(options, false, async (operation) => {
        const result = await backend.query<Row>(
          connection,
          {
            text: `SELECT ${projection} FROM ${records} WHERE namespace=:namespace AND owner_key=:owner AND (expires_at IS NULL OR expires_at>clock_timestamp()) ORDER BY id LIMIT :limit`,
            bindings: { namespace, owner: ownerKey, limit: limit + 1 },
          },
          { ...operation, maxRows: limit + 1 },
        );
        if (result.rows.length > limit) throw invalid();
        let bytes = 0;
        return Object.freeze(
          result.rows.map((input) => {
            bytes += typeof input.body === 'string' ? Buffer.byteLength(input.body) : 1048577;
            if (bytes > 1048576) throw invalid();
            const result = row(input);
            if (!input.live || result.ownerKey !== ownerKey) throw invalid();
            return result;
          }),
        );
      });
    },
    async bumpOwnerEpoch(namespace: string, ownerKey: string, options?: OperationOptions) {
      reference(namespace, 128);
      owner(ownerKey);
      return run(options, true, async (operation) => {
        const result = await backend.queryOne<{ epoch: string }>(
          connection,
          {
            text: `INSERT INTO ${epochs} AS owner_epoch(namespace,owner_key,epoch) VALUES(:namespace,:owner,1) ON CONFLICT(namespace,owner_key) DO UPDATE SET epoch=owner_epoch.epoch+1 WHERE owner_epoch.epoch<9007199254740991 RETURNING epoch::text`,
            bindings: { namespace, owner: ownerKey },
          },
          operation,
        );
        if (!result || typeof result.epoch !== 'string' || !/^[1-9][0-9]{0,15}$/.test(result.epoch))
          throw invalid();
        return integer(Number(result.epoch), Number.MAX_SAFE_INTEGER);
      });
    },
    async currentOwnerEpoch(namespace: string, ownerKey: string, options?: OperationOptions) {
      reference(namespace, 128);
      owner(ownerKey);
      return run(options, false, async (operation) => {
        const result = await backend.queryOne<{ epoch: string }>(
          connection,
          {
            text: `SELECT epoch::text FROM ${epochs} WHERE namespace=:namespace AND owner_key=:owner`,
            bindings: { namespace, owner: ownerKey },
          },
          operation,
        );
        if (!result) return 0;
        if (typeof result.epoch !== 'string' || !/^[1-9][0-9]{0,15}$/.test(result.epoch))
          throw invalid();
        return integer(Number(result.epoch), Number.MAX_SAFE_INTEGER);
      });
    },
  });
}
