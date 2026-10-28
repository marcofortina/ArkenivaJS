// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import type {
  AuthService,
  OperationOptions,
  SqlProvider,
  VerifiedTenantContext,
} from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';
import { types } from 'node:util';
import { SseCursorError } from '@arkenivajs/realtime';
import type { SseEvent, SseSource, SseSourceContext } from '@arkenivajs/realtime';
import { captureSql, object } from './security-store-support.js';

function identifier(value: string): string {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9_]{0,62}$/.test(value))
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'An allowlisted PostgreSQL identifier is required',
    });
  return value;
}
/** Explicit migration for an application-owned schema; never runs implicitly on listener startup. */
export async function createRealtimeTables(
  sql: SqlProvider,
  connection: string,
  schema: string,
): Promise<void> {
  const root = identifier(schema);
  await sql.execute(connection, {
    text: `CREATE TABLE ${root}.realtime_streams(scope TEXT PRIMARY KEY, next_sequence BIGINT NOT NULL DEFAULT 1, retained_from BIGINT NOT NULL DEFAULT 1)`,
  });
  await sql.execute(connection, {
    text: `CREATE TABLE ${root}.realtime_events(scope TEXT NOT NULL REFERENCES ${root}.realtime_streams(scope), sequence BIGINT NOT NULL, id UUID NOT NULL UNIQUE, type TEXT NOT NULL, data TEXT, PRIMARY KEY(scope,sequence))`,
  });
}
/** Ordered PostgreSQL source: one locked sequence per verified issuer/tenant, with explicit bounded retention. */
export class PostgresRealtimeSource implements SseSource {
  readonly kind = 'durable' as const;
  private readonly sql: ReturnType<typeof captureSql>;
  private readonly schema: string;
  constructor(
    sql: SqlProvider,
    private readonly auth: AuthService,
    private readonly connection: string,
    schema: string,
  ) {
    this.sql = captureSql(sql);
    this.schema = identifier(schema);
    identifier(connection);
  }
  private scope(tenant: VerifiedTenantContext): string {
    if (types.isProxy(tenant))
      throw new KitError({ code: 'EK_REALTIME_AUTH', message: 'A verified tenant is required' });
    const identity =
      tenant && typeof tenant === 'object'
        ? Object.getOwnPropertyDescriptor(tenant, 'identity')
        : undefined;
    if (!identity || !('value' in identity) || this.auth.tenantFrom(identity.value) !== tenant)
      throw new KitError({
        code: 'EK_REALTIME_AUTH',
        message: 'A current verified tenant is required for durable realtime events',
      });
    return createHash('sha256')
      .update(JSON.stringify([tenant.identity.issuer, tenant.tenantId]))
      .digest('hex');
  }
  private context(context: SseSourceContext): {
    scope: string;
    signal: AbortSignal;
    lastEventId?: string;
  } {
    if (types.isProxy(context))
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Invalid durable realtime source context',
      });
    const value = object(context, ['tenant', 'signal', 'lastEventId']);
    const scope = this.scope(value.tenant as VerifiedTenantContext),
      signal = captureAbortSignal(value.signal);
    if (signal.aborted)
      throw new KitError({
        code: 'EK_ABORTED',
        message: 'Durable realtime subscription was cancelled',
      });
    if (
      value.lastEventId !== undefined &&
      (typeof value.lastEventId !== 'string' ||
        !/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(value.lastEventId))
    )
      throw new SseCursorError('invalid');
    return {
      scope,
      signal,
      ...(value.lastEventId === undefined ? {} : { lastEventId: value.lastEventId as string }),
    };
  }
  private async checkpoint(context: SseSourceContext): Promise<bigint> {
    const selected = this.context(context);
    if (!selected.lastEventId) return 0n;
    const row = await this.sql.queryOne<{ sequence: string; retained_from: string }>(
      this.connection,
      {
        text: `SELECT e.sequence,s.retained_from FROM ${this.schema}.realtime_events e JOIN ${this.schema}.realtime_streams s ON s.scope=e.scope WHERE e.scope=:scope AND e.id=:id`,
        bindings: { scope: selected.scope, id: selected.lastEventId },
      },
      { signal: selected.signal, timeoutMs: 1000 },
    );
    if (!row) throw new SseCursorError('invalid');
    if (BigInt(row.sequence) < BigInt(row.retained_from)) throw new SseCursorError('expired');
    return BigInt(row.sequence);
  }
  async validateCursor(context: SseSourceContext): Promise<void> {
    await this.checkpoint(context);
  }
  async append(
    tenant: VerifiedTenantContext,
    event: Readonly<{ type: string; data: string }>,
    options?: OperationOptions,
  ): Promise<string> {
    if (types.isProxy(event))
      throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid durable realtime event' });
    const scope = this.scope(tenant),
      value = object(event, ['type', 'data']);
    if (
      typeof value.type !== 'string' ||
      !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(value.type) ||
      typeof value.data !== 'string' ||
      Buffer.byteLength(value.data) > 8192 ||
      Buffer.from(value.data).toString('utf8') !== value.data ||
      /[\r\0]/.test(value.data)
    )
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'The durable realtime event is invalid or oversized',
      });
    const id = randomUUID(),
      type = value.type,
      data = value.data;
    await this.sql.transaction(
      this.connection,
      async (transaction) => {
        await transaction.execute({
          text: `INSERT INTO ${this.schema}.realtime_streams(scope) VALUES (:scope) ON CONFLICT DO NOTHING`,
          bindings: { scope },
        });
        const stream = (
          await transaction.query<{ next_sequence: string; retained_from: string }>({
            text: `SELECT next_sequence,retained_from FROM ${this.schema}.realtime_streams WHERE scope=:scope FOR UPDATE`,
            bindings: { scope },
          })
        ).rows[0]!;
        const sequence = BigInt(stream.next_sequence);
        if (sequence - BigInt(stream.retained_from) >= 1000n)
          throw new KitError({
            code: 'EK_REALTIME_BACKPRESSURE',
            message: 'Explicit event retention is required before appending more events',
          });
        await transaction.execute({
          text: `INSERT INTO ${this.schema}.realtime_events(scope,sequence,id,type,data) VALUES (:scope,:sequence,:id,:type,:data)`,
          bindings: { scope, sequence, id, type, data },
        });
        await transaction.execute({
          text: `UPDATE ${this.schema}.realtime_streams SET next_sequence=:next WHERE scope=:scope`,
          bindings: { scope, next: sequence + 1n },
        });
      },
      options,
    );
    return id;
  }
  /** Retain this event and later events; the last 256 earlier IDs remain recognizable as expired. */
  async retainFrom(
    tenant: VerifiedTenantContext,
    id: string,
    options?: OperationOptions,
  ): Promise<void> {
    const scope = this.scope(tenant);
    if (typeof id !== 'string' || !/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(id))
      throw new SseCursorError('invalid');
    await this.sql.transaction(
      this.connection,
      async (transaction) => {
        const stream = (
          await transaction.query<{ retained_from: string }>({
            text: `SELECT retained_from FROM ${this.schema}.realtime_streams WHERE scope=:scope FOR UPDATE`,
            bindings: { scope },
          })
        ).rows[0];
        const event = (
          await transaction.query<{ sequence: string }>({
            text: `SELECT sequence FROM ${this.schema}.realtime_events WHERE scope=:scope AND id=:id`,
            bindings: { scope, id },
          })
        ).rows[0];
        if (!stream || !event) throw new SseCursorError('invalid');
        const sequence = BigInt(event.sequence);
        if (sequence < BigInt(stream.retained_from)) throw new SseCursorError('expired');
        await transaction.execute({
          text: `UPDATE ${this.schema}.realtime_streams SET retained_from=:sequence WHERE scope=:scope`,
          bindings: { scope, sequence },
        });
        await transaction.execute({
          text: `UPDATE ${this.schema}.realtime_events SET data=NULL WHERE scope=:scope AND sequence<:sequence`,
          bindings: { scope, sequence },
        });
        await transaction.execute({
          text: `DELETE FROM ${this.schema}.realtime_events WHERE scope=:scope AND sequence<:floor`,
          bindings: { scope, floor: sequence > 256n ? sequence - 256n : 0n },
        });
      },
      options,
    );
  }
  async *subscribe(context: SseSourceContext): AsyncIterable<SseEvent> {
    const selected = this.context(context);
    let sequence = await this.checkpoint(context);
    let initialized = false;
    while (!selected.signal.aborted) {
      this.scope(context.tenant);
      const stream = await this.sql.queryOne<{ retained_from: string }>(
        this.connection,
        {
          text: `SELECT retained_from FROM ${this.schema}.realtime_streams WHERE scope=:scope`,
          bindings: { scope: selected.scope },
        },
        { signal: selected.signal, timeoutMs: 1000 },
      );
      if (stream && sequence + 1n < BigInt(stream.retained_from)) {
        if (initialized || context.lastEventId !== undefined) throw new SseCursorError('expired');
        sequence = BigInt(stream.retained_from) - 1n;
      }
      initialized = true;
      const rows = await this.sql.query<{
        sequence: string;
        id: string;
        type: string;
        data: string | null;
      }>(
        this.connection,
        {
          text: `SELECT sequence,id,type,data FROM ${this.schema}.realtime_events WHERE scope=:scope AND sequence>:sequence ORDER BY sequence LIMIT 64`,
          bindings: { scope: selected.scope, sequence },
        },
        { signal: selected.signal, timeoutMs: 1000, maxRows: 64 },
      );
      for (const row of rows.rows) {
        if (selected.signal.aborted) return;
        if (row.data === null || BigInt(row.sequence) !== sequence + 1n)
          throw new SseCursorError('expired');
        sequence = BigInt(row.sequence);
        yield Object.freeze({ id: row.id, type: row.type, data: row.data });
      }
      try {
        await delay(100, undefined, { signal: selected.signal });
      } catch (error) {
        if (selected.signal.aborted) return;
        throw error;
      }
    }
  }
}
