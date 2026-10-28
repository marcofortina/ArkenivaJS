// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import SCIMMY from 'scimmy';
import { KitError } from '@arkenivajs/core';
import type {
  AuthService,
  SqlProvider,
  SqlTransaction,
  VerifiedTenantContext,
  OperationOptions,
} from '@arkenivajs/core';
import { copyData } from '@arkenivajs/core/support';
import type { ScimProvider, ScimRecord } from '@arkenivajs/security-scim';
import { captureSql } from './security-store-support.js';

type Kind = 'Users' | 'Groups';
interface Row {
  id: string;
  owner_key: string;
  kind: Kind;
  body: string;
  version: string;
  deleted: boolean;
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const error = (
  code:
    | 'EK_SCIM_UNAUTHORIZED'
    | 'EK_SCIM_CONFLICT'
    | 'EK_SCIM_PRECONDITION'
    | 'EK_SCIM_BAD_REQUEST'
    | 'EK_HTTP_NOT_FOUND'
    | 'EK_BACKEND_UNAVAILABLE'
    | 'EK_CONFIG_INVALID',
) => new KitError({ code, message: 'The PostgreSQL provisioning operation could not be accepted' });
function table(schema: string): string {
  if (!/^security_[a-f0-9]{24}$/.test(schema)) throw error('EK_CONFIG_INVALID');
  return schema + '.scim_resources';
}
const Schema = (kind: Kind) => (kind === 'Users' ? SCIMMY.Schemas.User : SCIMMY.Schemas.Group);
function body(input: unknown): ScimRecord {
  const copied = copyData(input);
  const encoded = JSON.stringify(copied);
  if (!encoded || Buffer.byteLength(encoded) > 131072) throw error('EK_SCIM_BAD_REQUEST');
  return JSON.parse(encoded) as ScimRecord;
}
function normalized(kind: Kind, input: unknown): ScimRecord {
  return body(JSON.parse(JSON.stringify(new (Schema(kind))(body(input), 'out'))) as unknown);
}
const shape = (value: ScimRecord) =>
  Object.fromEntries(Object.entries(value).filter(([key]) => !['id', 'meta'].includes(key)));
function value(row: Row): ScimRecord {
  return {
    ...body(JSON.parse(row.body) as unknown),
    id: row.id,
    meta: {
      resourceType: row.kind === 'Users' ? 'User' : 'Group',
      version: '"' + row.version + '"',
    },
  };
}

/** Example DDL is restricted to the caller-owned disposable schema; application migrations remain explicit. */
export async function createPostgresScimTables(
  sql: SqlProvider,
  connection: string,
  schema: string,
): Promise<void> {
  if (process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1') throw error('EK_CONFIG_INVALID');
  const name = table(schema);
  await sql.execute(connection, {
    text: `CREATE TABLE ${name}(id UUID PRIMARY KEY,owner_key CHAR(64) NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('Users','Groups')),external_id TEXT,creation_key CHAR(64) NOT NULL,user_name TEXT,body TEXT NOT NULL CHECK(octet_length(body)<=131072),version BIGINT NOT NULL DEFAULT 1,deleted BOOLEAN NOT NULL DEFAULT false,UNIQUE(owner_key,kind,creation_key),UNIQUE(owner_key,kind,external_id),UNIQUE(owner_key,kind,user_name))`,
  });
  await sql.execute(connection, { text: `CREATE INDEX scim_owner ON ${name}(owner_key,kind,id)` });
}

/** Concrete tenant/integration ownership, idempotency and ETags share one real PostgreSQL transaction. */
export function createPostgresScimProvider(
  sql: SqlProvider,
  auth: AuthService,
  connection: string,
  schema: string,
  kind: Kind,
): ScimProvider {
  const backend = captureSql(sql),
    name = table(schema);
  if (!['Users', 'Groups'].includes(kind) || !/^[A-Za-z][A-Za-z0-9_-]{0,127}$/.test(connection))
    throw error('EK_CONFIG_INVALID');
  const scope = (tenant: VerifiedTenantContext) => {
    if (auth.tenantFrom(tenant.identity) !== tenant) throw error('EK_SCIM_UNAUTHORIZED');
    return createHash('sha256')
      .update(JSON.stringify([tenant.identity.issuer, tenant.identity.subject, tenant.tenantId]))
      .digest('hex');
  };
  const projection = 'id::text,owner_key,kind,body,version::text,deleted';
  async function lock(
    tx: SqlTransaction,
    owner: string,
    options?: OperationOptions,
  ): Promise<void> {
    await tx.query(
      { text: 'SELECT pg_advisory_xact_lock(hashtextextended(:owner,0))', bindings: { owner } },
      options,
    );
  }
  async function rows(
    tx: SqlTransaction,
    owner: string,
    options?: OperationOptions,
  ): Promise<Row[]> {
    const size = (
      await tx.query<{ count: string; bytes: string }>(
        {
          text: `SELECT count(*)::text AS count,COALESCE(sum(octet_length(body)),0)::text AS bytes FROM ${name} WHERE owner_key=:owner AND deleted=false`,
          bindings: { owner },
        },
        options,
      )
    ).rows[0]!;
    if (BigInt(size.count) > 1000n || BigInt(size.bytes) > 2097152n)
      throw error('EK_BACKEND_UNAVAILABLE');
    const result = await tx.query<Row>(
      {
        text: `SELECT ${projection} FROM ${name} WHERE owner_key=:owner AND deleted=false ORDER BY id LIMIT 1001 FOR UPDATE`,
        bindings: { owner },
      },
      options,
    );
    if (result.rows.length > 1000) throw error('EK_BACKEND_UNAVAILABLE');
    return [...result.rows];
  }
  async function read(
    tx: SqlTransaction,
    id: string,
    owner: string,
    options?: OperationOptions,
  ): Promise<Row> {
    if (!uuid.test(id)) throw error('EK_HTTP_NOT_FOUND');
    const row = (
      await tx.query<Row>(
        { text: `SELECT ${projection} FROM ${name} WHERE id=:id FOR UPDATE`, bindings: { id } },
        options,
      )
    ).rows[0];
    if (row && row.owner_key !== owner) throw error('EK_SCIM_UNAUTHORIZED');
    if (!row || row.kind !== kind || row.deleted) throw error('EK_HTTP_NOT_FOUND');
    return row;
  }
  function condition(row: Row, expected: string | undefined): void {
    if (expected !== undefined && expected !== '*' && expected !== '"' + row.version + '"')
      throw error('EK_SCIM_PRECONDITION');
  }
  async function policy(
    tx: SqlTransaction,
    owner: string,
    record: ScimRecord,
    options?: OperationOptions,
  ): Promise<void> {
    // This example deliberately denies privilege-bearing user attributes; applications own any broader policy.
    if (
      record.roles !== undefined ||
      record.entitlements !== undefined ||
      record.password !== undefined
    )
      throw error('EK_SCIM_UNAUTHORIZED');
    const existing = await rows(tx, owner, options);
    const previous = existing.find((item) => item.id === record.id),
      bytes =
        existing.reduce((sum, item) => sum + Buffer.byteLength(item.body), 0) -
        (previous ? Buffer.byteLength(previous.body) : 0) +
        Buffer.byteLength(JSON.stringify(record));
    if ((!previous && existing.length >= 1000) || bytes > 2097152)
      throw error('EK_BACKEND_UNAVAILABLE');
    if (kind === 'Groups') {
      const groups = new Map(
        existing.filter((row) => row.kind === 'Groups').map((row) => [row.id, value(row)]),
      );
      groups.set(record.id, record);
      const active = new Set<string>(),
        completed = new Set<string>();
      const visit = (group: ScimRecord, depth: number) => {
        if (depth > 32 || active.has(group.id)) throw error('EK_SCIM_CONFLICT');
        if (completed.has(group.id)) return;
        active.add(group.id);
        for (const member of (group.members ?? []) as readonly { value: string; type?: string }[]) {
          const target = existing.find((row) => row.id === member.value);
          if (
            !target ||
            (member.type === 'Group' ? target.kind !== 'Groups' : target.kind !== 'Users')
          )
            throw error('EK_SCIM_UNAUTHORIZED');
          if (target.kind === 'Groups') visit(groups.get(target.id)!, depth + 1);
        }
        active.delete(group.id);
        completed.add(group.id);
      };
      visit(record, 0);
    }
  }
  async function transaction<T>(
    tenant: VerifiedTenantContext,
    options: OperationOptions | undefined,
    work: (tx: SqlTransaction, owner: string) => Promise<T>,
  ): Promise<T> {
    const owner = scope(tenant);
    try {
      return await backend.transaction(
        connection,
        async (tx) => {
          await lock(tx, owner, options);
          return work(tx, owner);
        },
        options,
      );
    } catch (cause) {
      if (cause instanceof KitError && cause.code === 'EK_DATABASE_CONSTRAINT')
        throw error('EK_SCIM_CONFLICT');
      throw cause;
    }
  }
  return Object.freeze<ScimProvider>({
    async list(filter, tenant, options) {
      return transaction(tenant, options, async (tx, owner) => {
        const owned = (await rows(tx, owner, options))
            .filter((row) => row.kind === kind)
            .map(value),
          matched = new SCIMMY.Types.Filter(filter.expression).match(
            owned,
            Schema(kind).definition,
          ) as ScimRecord[];
        const native = new SCIMMY.Messages.ListResponse(
          matched.map((item) => new (Schema(kind))(item)),
          {
            ...(filter.sortBy
              ? { sortBy: filter.sortBy, sortOrder: filter.sortOrder ?? 'ascending' }
              : {}),
            startIndex: filter.startIndex ?? 1,
            count: filter.count ?? 100,
            totalResults: matched.length,
          },
        );
        const Resources = native.Resources.map((item) =>
          normalized(kind, JSON.parse(JSON.stringify(item)) as unknown),
        );
        return {
          startIndex: filter.startIndex ?? 1,
          itemsPerPage: Resources.length,
          totalResults: matched.length,
          Resources,
        };
      });
    },
    async get(id, tenant, options) {
      return transaction(tenant, options, async (tx, owner) => {
        try {
          return value(await read(tx, id, owner, options));
        } catch (cause) {
          if (cause instanceof KitError && cause.code === 'EK_HTTP_NOT_FOUND') return null;
          throw cause;
        }
      });
    },
    async create(input, tenant, options) {
      if (body(input).password !== undefined) throw error('EK_SCIM_UNAUTHORIZED');
      const record = normalized(kind, input);
      if (!uuid.test(record.id)) throw error('EK_SCIM_BAD_REQUEST');
      const contents = shape(record),
        creation = createHash('sha256')
          .update(
            JSON.stringify(
              record.externalId === undefined ? contents : ['externalId', record.externalId],
            ),
          )
          .digest('hex');
      return transaction(tenant, options, async (tx, owner) => {
        const previous = (
          await tx.query<Row>(
            {
              text: `SELECT ${projection} FROM ${name} WHERE owner_key=:owner AND kind=:kind AND creation_key=:creation FOR UPDATE`,
              bindings: { owner, kind, creation },
            },
            options,
          )
        ).rows[0];
        if (previous) {
          if (previous.deleted || !isDeepStrictEqual(shape(value(previous)), contents))
            throw error('EK_SCIM_CONFLICT');
          return value(previous);
        }
        await policy(tx, owner, record, options);
        const result = await tx.query<Row>(
          {
            text: `INSERT INTO ${name}(id,owner_key,kind,external_id,creation_key,user_name,body) VALUES(:id,:owner,:kind,:external,:creation,:username,:body) RETURNING ${projection}`,
            bindings: {
              id: record.id,
              owner,
              kind,
              external: record.externalId ?? null,
              creation,
              username: kind === 'Users' ? String(record.userName).toLowerCase() : null,
              body: JSON.stringify(record),
            },
          },
          options,
        );
        return value(result.rows[0]!);
      });
    },
    async replace(id, input, ifMatch, tenant, options) {
      return transaction(tenant, options, async (tx, owner) => {
        const row = await read(tx, id, owner, options);
        condition(row, ifMatch);
        const record = normalized(kind, { ...body(input), id });
        if (record.externalId !== value(row).externalId) throw error('EK_SCIM_CONFLICT');
        if (isDeepStrictEqual(shape(record), shape(value(row)))) return value(row);
        await policy(tx, owner, record, options);
        const result = await tx.query<Row>(
          {
            text: `UPDATE ${name} SET body=:body,user_name=:username,version=version+1 WHERE id=:id AND owner_key=:owner AND version=CAST(:version AS BIGINT) RETURNING ${projection}`,
            bindings: {
              body: JSON.stringify(record),
              username: kind === 'Users' ? String(record.userName).toLowerCase() : null,
              id,
              owner,
              version: row.version,
            },
          },
          options,
        );
        if (!result.rows.length) throw error('EK_SCIM_PRECONDITION');
        return value(result.rows[0]!);
      });
    },
    async patch(id, input, ifMatch, tenant, options) {
      return transaction(tenant, options, async (tx, owner) => {
        const row = await read(tx, id, owner, options);
        condition(row, ifMatch);
        const previous = value(row),
          record = normalized(
            kind,
            JSON.parse(
              JSON.stringify(
                (await new SCIMMY.Messages.PatchOp(copyData(input) as never).apply(
                  new (Schema(kind))(previous),
                )) ?? previous,
              ),
            ) as unknown,
          );
        if (record.id !== id || record.externalId !== previous.externalId)
          throw error('EK_SCIM_CONFLICT');
        if (isDeepStrictEqual(shape(record), shape(previous))) return previous;
        await policy(tx, owner, record, options);
        const result = await tx.query<Row>(
          {
            text: `UPDATE ${name} SET body=:body,version=version+1 WHERE id=:id AND owner_key=:owner AND version=CAST(:version AS BIGINT) RETURNING ${projection}`,
            bindings: { body: JSON.stringify(record), id, owner, version: row.version },
          },
          options,
        );
        if (!result.rows.length) throw error('EK_SCIM_PRECONDITION');
        return value(result.rows[0]!);
      });
    },
    async delete(id, ifMatch, tenant, options) {
      await transaction(tenant, options, async (tx, owner) => {
        const row = await read(tx, id, owner, options);
        condition(row, ifMatch);
        const existing = await rows(tx, owner, options);
        if (
          existing.some(
            (item) =>
              item.kind === 'Groups' &&
              ((value(item).members ?? []) as { value: string }[]).some(
                (member) => member.value === id,
              ),
          )
        )
          throw error('EK_SCIM_CONFLICT');
        const tombstone = { ...value(row), ...(kind === 'Users' ? { active: false } : {}) };
        await tx.execute(
          {
            text: `UPDATE ${name} SET deleted=true,body=:body,version=version+1 WHERE id=:id AND owner_key=:owner AND version=CAST(:version AS BIGINT)`,
            bindings: { body: JSON.stringify(tombstone), id, owner, version: row.version },
          },
          options,
        );
      });
    },
  });
}
