// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { setMaxListeners } from 'node:events';
import { createPool } from 'mysql2';
import type { Pool, PoolConnection, RowDataPacket } from 'mysql2';
import type { Pool as PromisePool } from 'mysql2/promise';
import { KitError, DEFAULT_POOL_ACQUIRE_TIMEOUT_MS } from '@arkenivajs/core';
import type {
  MeterSession,
  OperationOptions,
  SqlQueryOptions,
  SqlResult,
  SqlStatement,
  SqlTransaction,
  SqlValue,
} from '@arkenivajs/core';
import { instrumentOperation } from '@arkenivajs/core/support';
import { compileSql } from '@arkenivajs/database';
import type { CompiledSql } from '@arkenivajs/database';
import { captureSqlStatement, SqlDeadline } from '@arkenivajs/database/support';
import type { SqlConnectionAdapter, SqlObservationPorts } from '@arkenivajs/database/support';
import type { MysqlConfiguration } from './config.js';
import { mysqlError, mysqlCommitError } from './errors.js';

type Row = Record<string, unknown>;
type Kind = 'query' | 'queryOne' | 'execute' | 'ping';
interface SessionState {
  mode: string;
  encoding: string;
  zone: string;
}
interface Lease {
  readonly client: PoolConnection;
  readonly state: SessionState;
  readonly released: boolean;
  release(discard?: boolean): void;
}
const SQL_MODE = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION';

/** Control statements and stored procedures require explicit native transaction ownership. */
function portableControl(text: string): void {
  let at = 0;
  while (at < text.length) {
    if (/[ \t\r\n\f\v]/.test(text[at]!)) at++;
    else if (text.startsWith('/*', at)) at = text.indexOf('*/', at + 2) + 2;
    else if (
      text[at] === '#' ||
      (text.startsWith('--', at) && (at + 2 === text.length || text.charCodeAt(at + 2) <= 32))
    ) {
      while (at < text.length && !/[\r\n]/.test(text[at]!)) at++;
    } else break;
  }
  const command = text
    .slice(at)
    .match(/^[A-Za-z]+/)?.[0]
    ?.toUpperCase();
  if (
    [
      'BEGIN',
      'START',
      'COMMIT',
      'ROLLBACK',
      'SAVEPOINT',
      'RELEASE',
      'XA',
      'PREPARE',
      'EXECUTE',
      'DEALLOCATE',
      'CALL',
    ].includes(command ?? '')
  )
    throw new KitError({
      code: 'EK_DATABASE_TRANSACTION',
      message: 'MySQL transaction control and procedures require the owned callback or native API',
    });
}

function rowLimit(options: SqlQueryOptions = {}): number {
  if (!options || typeof options !== 'object' || Array.isArray(options))
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'SQL query options must be an object',
    });
  const limit = options.maxRows ?? 10_000;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100_000)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'SQL maxRows must be an integer from 1 to 100000',
    });
  return limit;
}

/** One pool owns bounded prepared streams, pinned transactions and abandoned acquisitions. */
export class MysqlConnection implements SqlConnectionAdapter {
  private readonly pool: Pool;
  private readonly promisePool: PromisePool;
  private readonly stop = new AbortController();
  private readonly active = new Map<PoolConnection, { lease: Lease; deadline: SqlDeadline }>();
  private readonly pending = new Set<Promise<Lease>>();
  private readonly cleanupFailures: unknown[] = [];
  private cleanupFailureCount = 0;
  private readonly capacity: number;
  private closed = false;
  private closing: Promise<void> | undefined;
  private observerFailures = 0;
  private operations = 0;

  constructor(
    private readonly name: string,
    private readonly config: MysqlConfiguration,
    private readonly observation: SqlObservationPorts,
  ) {
    this.capacity = Math.max(config.pool.connectionLimit ?? 10, 128);
    setMaxListeners(Math.min(this.capacity * 2 + 16, 2_147_483_647), this.stop.signal);
    this.pool = createPool(config.pool);
    this.promisePool = this.pool.promise();
    this.pool.on('connection', (client: PoolConnection) => {
      // Native borrowers keep their own error handlers; this observes late errors after cancellation.
      client.on('error', (cause: unknown) =>
        this.active.get(client)?.deadline.abort(mysqlError(cause, 'query')),
      );
    });
  }

  private open(): void {
    if (this.closed)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'MySQL pool is closed' });
  }
  private rememberCleanup(cause: unknown): void {
    this.cleanupFailureCount++;
    if (this.cleanupFailures.length < this.capacity) this.cleanupFailures.push(cause);
  }
  private diagnostic(work: () => void): void {
    try {
      work();
    } catch {
      this.observerFailures++;
    }
  }
  private current(): MeterSession | undefined {
    let session: MeterSession | undefined;
    this.diagnostic(() => {
      session = this.observation.meter?.current();
    });
    return session;
  }
  private missing(
    session: MeterSession | undefined,
    reason: 'driver_bytes_unavailable' | 'not_instrumented',
  ): void {
    if (!session) return;
    this.diagnostic(() => {
      const meter = this.observation.meter as SqlObservationPorts['meter'] & {
        markMissing?: (session: MeterSession, reason: string) => void;
      };
      if (typeof meter?.markMissing !== 'function')
        throw new Error('Meter quality controls are unavailable');
      meter.markMissing(session, reason);
    });
  }

  private async acquire(deadline: SqlDeadline): Promise<Lease> {
    this.open();
    deadline.check();
    if (this.pending.size + this.active.size >= this.capacity)
      throw new KitError({
        code: 'EK_DATABASE_POOL_TIMEOUT',
        message: 'MySQL acquisition capacity is exhausted',
        retryable: true,
      });
    const budget = new SqlDeadline({ timeoutMs: DEFAULT_POOL_ACQUIRE_TIMEOUT_MS });
    const cancel = () => budget.abort(deadline.signal.reason as KitError);
    deadline.signal.addEventListener('abort', cancel, { once: true });
    if (deadline.signal.aborted) cancel();
    const began = performance.now();
    const requested = this.promisePool.getConnection().then(
      (native): Lease => {
        // Promise pool connections expose the same public callback connection for prepared streams.
        const client = native.connection as unknown as PoolConnection;
        let released = false,
          failed = false,
          failure: unknown;
        const discard = () => {
          try {
            lease.release(true);
          } catch (cause) {
            this.rememberCleanup(cause);
          }
        };
        const lease: Lease = {
          client,
          state: { mode: SQL_MODE, encoding: 'utf8mb4', zone: '+00:00' },
          get released() {
            return released;
          },
          release: (destroy = false) => {
            if (released) {
              if (failed) throw failure;
              return;
            }
            released = true;
            deadline.signal.removeEventListener('abort', discard);
            this.active.delete(client);
            try {
              if (destroy || this.closed) native.destroy();
              else native.release();
            } catch (cause) {
              failed = true;
              failure = cause;
              throw cause;
            }
          },
        };
        if (this.closed || deadline.signal.aborted || budget.signal.aborted) {
          try {
            lease.release(true);
          } catch (cause) {
            this.rememberCleanup(cause);
            throw cause;
          }
          throw budget.signal.reason;
        }
        this.active.set(client, { lease, deadline });
        deadline.signal.addEventListener('abort', discard, { once: true });
        return lease;
      },
      (cause: unknown): never => {
        throw mysqlError(cause, 'connect');
      },
    );
    this.pending.add(requested);
    void requested.then(
      () => this.pending.delete(requested),
      () => this.pending.delete(requested),
    );
    try {
      return await budget.run(() => requested);
    } catch (cause) {
      if (cause instanceof KitError && cause.code === 'EK_TIMEOUT')
        throw new KitError({
          code: 'EK_DATABASE_POOL_TIMEOUT',
          message: 'MySQL pool acquisition deadline exceeded',
          cause,
          retryable: true,
        });
      throw cause;
    } finally {
      deadline.signal.removeEventListener('abort', cancel);
      budget.close();
      this.diagnostic(() =>
        this.observation.telemetry?.recordHistogram(
          'arkenivajs.db.pool.acquire.duration',
          (performance.now() - began) / 1000,
          { pool: this.name, driver: 'mysql' },
        ),
      );
    }
  }

  private command(lease: Lease, text: string, deadline: SqlDeadline): Promise<unknown> {
    return deadline.run(
      () =>
        new Promise((resolve, reject) =>
          lease.client.query(text, (error, result) => (error ? reject(error) : resolve(result))),
        ),
    );
  }
  private async reset(lease: Lease, deadline: SqlDeadline): Promise<void> {
    await deadline.run(
      () =>
        new Promise<void>((resolve, reject) =>
          lease.client.reset((error) => (error ? reject(error) : resolve())),
        ),
    );
    await this.command(lease, 'SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci', deadline);
    await this.command(
      lease,
      `SET SESSION sql_mode = '${SQL_MODE}', time_zone = '+00:00', autocommit = 1`,
      deadline,
    );
  }
  private async refresh(lease: Lease, deadline: SqlDeadline): Promise<void> {
    const rows = (await this.command(
      lease,
      'SELECT @@session.sql_mode AS mode, @@session.character_set_client AS encoding, @@session.time_zone AS zone',
      deadline,
    )) as RowDataPacket[];
    if (
      !Array.isArray(rows) ||
      rows.length !== 1 ||
      ['mode', 'encoding', 'zone'].some((key) => typeof rows[0]![key] !== 'string')
    )
      throw new KitError({
        code: 'EK_DATABASE_QUERY',
        message: 'MySQL session settings could not be established',
      });
    lease.state.mode = rows[0]!.mode as string;
    lease.state.encoding = rows[0]!.encoding as string;
    lease.state.zone = rows[0]!.zone as string;
  }
  private compile(
    statement: SqlStatement,
    state: SessionState = { mode: SQL_MODE, encoding: 'utf8mb4', zone: '+00:00' },
  ): CompiledSql {
    if (state.encoding !== 'utf8mb4' || state.zone !== '+00:00')
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Portable MySQL statements require UTF-8 and UTC session settings',
      });
    const modes = new Set(state.mode.split(','));
    const compiled = compileSql(statement, 'mysql', {
      noBackslashEscapes: modes.has('NO_BACKSLASH_ESCAPES'),
      ansiQuotes: modes.has('ANSI_QUOTES'),
    });
    portableControl(compiled.text);
    return compiled;
  }

  private async stream(
    lease: Lease,
    compiled: CompiledSql,
    kind: Kind,
    limit: number,
    deadline: SqlDeadline,
    session: MeterSession | undefined,
    transaction = false,
  ): Promise<SqlResult> {
    deadline.check();
    const attrs = {
      'db.system.name': 'mysql',
      'db.operation.name': kind === 'queryOne' ? 'query' : kind,
    };
    return instrumentOperation(
      this.observation.telemetry,
      'db.client.operation',
      attrs,
      async () => {
        deadline.check();
        const began = performance.now();
        this.operations++;
        this.diagnostic(() => session?.recordOperation('db.query'));
        this.missing(session, 'driver_bytes_unavailable');
        try {
          const result = await deadline.run(
            () =>
              new Promise<SqlResult>((resolve, reject) => {
                const values = (compiled.parameters as readonly SqlValue[]).map((value) =>
                  typeof value === 'bigint'
                    ? String(value)
                    : value instanceof Uint8Array
                      ? Buffer.from(value)
                      : value,
                );
                const command = lease.client.execute(compiled.text, values);
                // A destroyed stream detaches its error observer before native work necessarily settles.
                command.on('error', () => undefined);
                const source = command.stream({ highWaterMark: 1 });
                const rows: Row[] = [];
                let header = false,
                  resultSets = 0,
                  settled = false;
                let metadata: SqlResult['metadata'] = {},
                  count: number | null = null;
                const failed = (cause: unknown) => {
                  if (settled) return;
                  settled = true;
                  let primary = cause;
                  // Stream destruction alone resumes the native socket; discard it before detaching.
                  try {
                    lease.release(true);
                  } catch (cleanup) {
                    primary = new AggregateError([cause, cleanup]);
                  }
                  source.destroy();
                  reject(primary);
                };
                source.on('error', failed);
                source.on('fields', (fields: unknown) => {
                  header = fields === undefined;
                  if (++resultSets > 1)
                    failed(
                      new KitError({
                        code: 'EK_DATABASE_QUERY',
                        message: 'MySQL multiple result sets require the native API',
                      }),
                    );
                });
                source.on('data', (row: Row) => {
                  if (settled) return;
                  if (header) {
                    const affected = row.affectedRows;
                    count =
                      typeof affected === 'number' &&
                      Number.isSafeInteger(affected) &&
                      affected >= 0
                        ? affected
                        : null;
                    const insertId = row.insertId;
                    metadata = Object.freeze({
                      ...(count === null ? {} : { affectedRows: count }),
                      ...((typeof insertId === 'string' && /^[0-9]+(?![\s\S])/.test(insertId)) ||
                      (typeof insertId === 'number' &&
                        Number.isSafeInteger(insertId) &&
                        insertId >= 0)
                        ? { insertId }
                        : {}),
                    });
                    const warnings = row.warningStatus;
                    if (
                      typeof warnings === 'number' &&
                      Number.isSafeInteger(warnings) &&
                      warnings > 0 &&
                      warnings <= 65535
                    )
                      this.diagnostic(() =>
                        this.observation.logger?.warn('MySQL statement completed with warnings', {
                          driver: 'mysql',
                          connection: this.name,
                          fingerprint: compiled.fingerprint,
                          warningStatus: warnings,
                        }),
                      );
                    if (
                      transaction &&
                      typeof row.serverStatus === 'number' &&
                      !(row.serverStatus & 1)
                    )
                      failed(
                        new KitError({
                          code: 'EK_DATABASE_TRANSACTION',
                          message:
                            'MySQL statement implicitly committed the transaction; prior effects cannot be rolled back',
                          retryable: false,
                          details: { outcome: 'implicitly_committed' },
                        }),
                      );
                  } else if (rows.length >= limit) {
                    failed(
                      new KitError({
                        code: 'EK_DATABASE_QUERY',
                        message:
                          kind === 'queryOne'
                            ? 'SQL queryOne returned more than one row'
                            : 'SQL result exceeds maxRows',
                        ...(kind === 'queryOne' ? {} : { details: { limitExceeded: true } }),
                      }),
                    );
                  } else rows.push(row);
                });
                source.on('end', () => {
                  if (settled) return;
                  settled = true;
                  resolve(
                    Object.freeze({
                      rows: Object.freeze(rows),
                      rowCount: header ? count : rows.length,
                      metadata,
                    }),
                  );
                });
              }),
          );
          return result;
        } catch (cause) {
          const error = mysqlError(cause, 'query');
          this.diagnostic(() =>
            this.observation.logger?.warn('MySQL statement failed', {
              driver: 'mysql',
              connection: this.name,
              fingerprint: compiled.fingerprint,
              errorCode: error.code,
            }),
          );
          throw error;
        } finally {
          const elapsed = performance.now() - began;
          this.diagnostic(() =>
            this.observation.telemetry?.recordHistogram(
              'db.client.operation.duration',
              elapsed / 1000,
              attrs,
            ),
          );
          this.diagnostic(() =>
            session?.recordUsage('db.client.elapsed', {
              value: elapsed,
              unit: 'milliseconds',
              source: 'observed',
            }),
          );
        }
      },
      () => {
        this.observerFailures++;
      },
    );
  }

  private async standalone(
    statement: SqlStatement,
    kind: Kind,
    options: SqlQueryOptions = {},
  ): Promise<SqlResult> {
    this.open();
    const compiled = this.compile(statement);
    const limit = kind === 'queryOne' ? 1 : rowLimit(options);
    const deadline = new SqlDeadline(options, this.stop.signal);
    let lease: Lease | undefined,
      answer: SqlResult | undefined,
      failed = false,
      primary: unknown;
    try {
      lease = await this.acquire(deadline);
      await this.reset(lease, deadline);
      answer = await this.stream(lease, compiled, kind, limit, deadline, this.current());
    } catch (cause) {
      failed = true;
      primary = mysqlError(cause, 'query');
    } finally {
      deadline.close();
      try {
        lease?.release(failed);
      } catch (cleanup) {
        primary = new KitError({
          code: 'EK_DATABASE_QUERY',
          message: 'MySQL lease release failed',
          cause: failed ? new AggregateError([primary, cleanup]) : cleanup,
        });
        failed = true;
      }
    }
    if (failed) throw primary;
    return answer!;
  }
  async query<T extends object = Row>(
    statement: SqlStatement,
    options?: SqlQueryOptions,
  ): Promise<SqlResult<T>> {
    return this.standalone(statement, 'query', options) as Promise<SqlResult<T>>;
  }
  async queryOne<T extends object = Row>(
    statement: SqlStatement,
    options?: OperationOptions,
  ): Promise<T | null> {
    const result = await this.standalone(statement, 'queryOne', options);
    return (result.rows[0] as T | undefined) ?? null;
  }
  execute(statement: SqlStatement, options?: OperationOptions): Promise<SqlResult> {
    return this.standalone(statement, 'execute', options);
  }

  async warm(): Promise<void> {
    const deadline = new SqlDeadline({}, this.stop.signal);
    const leases: Lease[] = [];
    try {
      for (let i = 0; i < this.config.minimum; i++) leases.push(await this.acquire(deadline));
    } finally {
      deadline.close();
      for (const lease of leases) lease.release();
    }
  }

  async transaction<T>(
    handler: (tx: SqlTransaction) => Promise<T>,
    options?: OperationOptions,
  ): Promise<T> {
    this.open();
    if (typeof handler !== 'function')
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'SQL transaction handler must be a function',
      });
    const deadline = new SqlDeadline(options, this.stop.signal);
    setMaxListeners(Math.min(this.capacity + 16, 2_147_483_647), deadline.signal);
    let lease: Lease | undefined,
      active = true,
      began = false,
      committing = false,
      failed = false,
      primary: unknown,
      answer: T | undefined;
    let queue: Promise<unknown> = Promise.resolve();
    let statementFailed = false,
      statementFailure: unknown;
    const pending = new Set<Promise<SqlResult>>();
    const enqueue = (
      statement: SqlStatement,
      kind: 'query' | 'execute',
      input: SqlQueryOptions = {},
    ): Promise<SqlResult> => {
      if (!active || !lease || lease.released)
        return Promise.reject(
          new KitError({
            code: 'EK_DATABASE_TRANSACTION',
            message: 'MySQL transaction handle is no longer active',
          }),
        );
      if (pending.size >= this.capacity)
        return Promise.reject(
          new KitError({
            code: 'EK_DATABASE_TRANSACTION',
            message: 'MySQL pending transaction statement capacity is exhausted',
          }),
        );
      const captured = captureSqlStatement(statement);
      const limit = rowLimit(input);
      const operation = new SqlDeadline(input);
      const parentAbort = () => operation.abort(deadline.signal.reason as KitError);
      const cancel = () => deadline.abort(operation.signal.reason as KitError);
      deadline.signal.addEventListener('abort', parentAbort, { once: true });
      operation.signal.addEventListener('abort', cancel, { once: true });
      if (operation.signal.aborted) cancel();
      if (deadline.signal.aborted) parentAbort();
      const previous = queue;
      const session = this.current();
      const work = operation.run(() =>
        previous.then(async () => {
          operation.check();
          if (statementFailed) throw statementFailure;
          try {
            const result = await this.stream(
              lease!,
              this.compile(captured, lease!.state),
              kind,
              limit,
              operation,
              session,
              true,
            );
            await this.refresh(lease!, operation);
            return result;
          } catch (cause) {
            statementFailed = true;
            statementFailure = mysqlError(cause, 'query');
            throw statementFailure;
          }
        }),
      );
      queue = work.then(
        () => undefined,
        () => undefined,
      );
      pending.add(work);
      void work
        .finally(() => {
          pending.delete(work);
          deadline.signal.removeEventListener('abort', parentAbort);
          operation.signal.removeEventListener('abort', cancel);
          operation.close();
        })
        .catch(() => undefined);
      return work;
    };
    try {
      lease = await this.acquire(deadline);
      await this.reset(lease, deadline);
      await this.command(lease, 'START TRANSACTION', deadline);
      began = true;
      const tx: SqlTransaction = Object.freeze({
        query: async <R extends object = Row>(statement: SqlStatement, input?: SqlQueryOptions) =>
          enqueue(statement, 'query', input) as Promise<SqlResult<R>>,
        execute: async (statement: SqlStatement, input?: OperationOptions) =>
          enqueue(statement, 'execute', input),
      });
      const value = await deadline.run(async () => {
        const value = await handler(tx);
        active = false;
        await queue;
        if (statementFailed) throw statementFailure;
        return value;
      });
      committing = true;
      try {
        await this.command(lease, 'COMMIT', deadline);
      } catch (cause) {
        throw mysqlCommitError(cause);
      }
      answer = value;
    } catch (cause) {
      failed = true;
      primary = began ? cause : mysqlError(cause, 'query');
      if (began && !committing && lease && !lease.released) {
        const cleanup = new SqlDeadline({ timeoutMs: 5000 }, this.stop.signal);
        try {
          await cleanup.run(() => queue);
          await this.command(lease, 'ROLLBACK', cleanup);
        } catch (rollback) {
          primary = new KitError({
            code: 'EK_DATABASE_TRANSACTION',
            message: 'MySQL transaction and rollback failed',
            cause: new AggregateError([cause, rollback]),
          });
        } finally {
          cleanup.close();
        }
      }
    } finally {
      active = false;
      deadline.close();
      try {
        lease?.release(failed);
      } catch (cleanup) {
        primary = new KitError({
          code: 'EK_DATABASE_TRANSACTION',
          message: 'MySQL transaction lease release failed',
          cause: failed ? new AggregateError([primary, cleanup]) : cleanup,
        });
        failed = true;
      }
    }
    if (failed) throw primary;
    return answer as T;
  }

  async ping(options?: OperationOptions): Promise<boolean> {
    try {
      return (
        (await this.standalone({ text: 'SELECT 1 AS healthy' }, 'ping', options)).rows[0]
          ?.healthy === '1'
      );
    } catch (error) {
      if (
        error instanceof KitError &&
        ((error.code === 'EK_DATABASE_CONNECT' && error.retryable) ||
          ['EK_DATABASE_UNAVAILABLE', 'EK_DATABASE_POOL_TIMEOUT'].includes(error.code))
      )
        return false;
      throw error;
    }
  }
  stats(): Readonly<Record<string, number | null>> {
    this.open();
    // mysql2 has no stable public total/idle/queue counters; framework ownership is measured separately.
    return Object.freeze({
      total: null,
      idle: null,
      waiting: null,
      active: this.active.size,
      pendingAcquires: this.pending.size,
      operations: this.operations,
      observerFailures: this.observerFailures,
      cleanupFailures: this.cleanupFailureCount,
    });
  }
  native(): Pool {
    this.open();
    this.missing(this.current(), 'not_instrumented');
    return this.pool;
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    this.stop.abort();
    this.closing = (async () => {
      const released = await Promise.allSettled(
        [...this.active.values()].map(async ({ lease }) => lease.release(true)),
      );
      await Promise.allSettled([...this.pending]);
      const failures = released
        .filter((result) => result.status === 'rejected')
        .map((result) => result.reason as unknown);
      failures.push(...this.cleanupFailures);
      try {
        await new Promise<void>((resolve, reject) =>
          this.pool.end((error) => (error ? reject(error) : resolve())),
        );
      } catch (cause) {
        failures.push(cause);
      }
      if (failures.length)
        throw new KitError({
          code: 'EK_DATABASE_UNAVAILABLE',
          message: 'MySQL pool shutdown cleanup failed',
          cause: new AggregateError(failures),
        });
    })();
    return this.closing;
  }
}
