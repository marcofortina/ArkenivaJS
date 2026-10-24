import { performance } from 'node:perf_hooks';
import { setMaxListeners } from 'node:events';
import { Pool, types } from 'pg';
import type { PoolClient, PoolConfig, QueryResult, CustomTypesConfig } from 'pg';
import Cursor from 'pg-cursor';
import { KitError } from '@arkenivajs/core';
import type {
  MeterSession,
  OperationOptions,
  SqlQueryOptions,
  SqlStatement,
  SqlResult,
  SqlTransaction,
} from '@arkenivajs/core';
import { instrumentOperation } from '@arkenivajs/core/support';
import { compileSql } from '@arkenivajs/database';
import type { CompiledSql } from '@arkenivajs/database';
import { captureSqlStatement, SqlDeadline } from '@arkenivajs/database/support';
import type { SqlConnectionAdapter, SqlObservationPorts } from '@arkenivajs/database/support';
import { postgresError, postgresCommitError } from './errors.js';

interface SessionState {
  standard: boolean;
  encoding: string;
  transaction: string;
  broken: boolean;
}
interface Lease {
  readonly client: PoolClient;
  readonly state: SessionState;
  readonly released: boolean;
  release(discard?: boolean): void;
}
type Row = Record<string, unknown>;
type Kind = 'query' | 'queryOne' | 'execute' | 'ping';

/** Native parsing preserves decimal, bigint, JSON and temporal precision as text. */
function portableTypes(): CustomTypesConfig {
  const bytea = types.getTypeParser(17, 'text');
  const get = (oid: number, format?: string) => {
    if (format === 'binary') return types.getTypeParser(oid, 'binary');
    if (oid === 16) return (value: string) => value === 't';
    if ([21, 23, 26, 700, 701].includes(oid)) return (value: string) => Number(value);
    if (oid === 17) return bytea;
    return (value: string) => value;
  };
  return { getTypeParser: get as CustomTypesConfig['getTypeParser'] };
}

/** Transaction control belongs to the pinned callback API, including commented prefixes. */
function portableControl(text: string): void {
  let at = 0;
  while (at < text.length) {
    if (/[ \t\r\n\f\v]/.test(text[at]!)) {
      at++;
      continue;
    }
    if (text.startsWith('--', at)) {
      at += 2;
      while (at < text.length && !/[\r\n]/.test(text[at]!)) at++;
      continue;
    }
    if (text.startsWith('/*', at)) {
      let depth = 1;
      at += 2;
      while (at < text.length && depth) {
        if (text.startsWith('/*', at)) {
          depth++;
          at += 2;
        } else if (text.startsWith('*/', at)) {
          depth--;
          at += 2;
        } else at++;
      }
      continue;
    }
    break;
  }
  const command = /^[A-Za-z_]+/.exec(text.slice(at))?.[0]?.toUpperCase();
  if (
    command &&
    [
      'BEGIN',
      'START',
      'COMMIT',
      'END',
      'ROLLBACK',
      'ABORT',
      'SAVEPOINT',
      'RELEASE',
      'PREPARE',
    ].includes(command)
  )
    throw new KitError({
      code: 'EK_DATABASE_TRANSACTION',
      message: 'Portable SQL transaction control requires the transaction callback API',
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

/** One named pool owns every framework lease and late acquisition cleanup. */
export class PostgresConnection implements SqlConnectionAdapter {
  private readonly pool: Pool;
  private readonly stop = new AbortController();
  private readonly states = new WeakMap<PoolClient, SessionState>();
  private readonly active = new Map<PoolClient, { lease: Lease; deadline: SqlDeadline }>();
  private readonly pending = new Set<Promise<PoolClient>>();
  private readonly typePolicy = portableTypes();
  private closed = false;
  private closing: Promise<void> | undefined;
  private observerFailures = 0;
  private operationCount = 0;
  private readonly capacity: number;

  constructor(
    private readonly name: string,
    config: PoolConfig,
    private readonly observation: SqlObservationPorts,
  ) {
    this.capacity = Math.max(config.max ?? 10, 128);
    setMaxListeners(Math.min(this.capacity * 2 + 16, 2_147_483_647), this.stop.signal);
    this.pool = new Pool({ ...config, types: this.typePolicy });
    for (const event of ['acquire', 'release', 'remove'] as const)
      this.pool.on(event, () => globalThis.queueMicrotask(() => this.gauges()));
    this.pool.on('error', () =>
      this.diagnostic(() =>
        this.observation.logger?.warn('PostgreSQL idle connection failed', {
          driver: 'postgresql',
          connection: name,
        }),
      ),
    );
    this.pool.on('connect', (client) => {
      const state: SessionState = {
        standard: true,
        encoding: 'UTF8',
        transaction: 'I',
        broken: false,
      };
      this.states.set(client, state);
      client.connection.on(
        'parameterStatus',
        (message: { parameterName: string; parameterValue: string }) => {
          if (message.parameterName === 'standard_conforming_strings')
            state.standard = message.parameterValue === 'on';
          if (message.parameterName === 'client_encoding') state.encoding = message.parameterValue;
        },
      );
      client.connection.on('readyForQuery', (message: { status: string }) => {
        state.transaction = message.status;
      });
      client.on('error', (cause: Error) => {
        state.broken = true;
        this.active.get(client)?.deadline.abort(postgresError(cause, 'query'));
      });
    });
  }

  private open(): void {
    if (this.closed)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'PostgreSQL pool is closed' });
  }
  private diagnostic(work: () => void): void {
    try {
      work();
    } catch {
      this.observerFailures++;
    }
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
  private current(): MeterSession | undefined {
    let session: MeterSession | undefined;
    this.diagnostic(() => {
      session = this.observation.meter?.current();
    });
    return session;
  }
  private gauges(): void {
    this.diagnostic(() => {
      const labels = { pool: this.name, driver: 'postgresql' };
      this.observation.telemetry?.setGauge(
        'arkenivajs.db.pool.active',
        this.pool.totalCount - this.pool.idleCount,
        labels,
      );
      this.observation.telemetry?.setGauge('arkenivajs.db.pool.idle', this.pool.idleCount, labels);
    });
  }

  private async acquire(deadline: SqlDeadline): Promise<Lease> {
    this.open();
    deadline.check();
    if (this.pending.size + this.active.size >= this.capacity)
      throw new KitError({
        code: 'EK_DATABASE_POOL_TIMEOUT',
        message: 'PostgreSQL acquisition capacity is exhausted',
        retryable: true,
      });
    const began = performance.now();
    let observed = false;
    const observe = () => {
      if (observed) return;
      observed = true;
      this.diagnostic(() =>
        this.observation.telemetry?.recordHistogram(
          'arkenivajs.db.pool.acquire.duration',
          (performance.now() - began) / 1000,
          { pool: this.name, driver: 'postgresql' },
        ),
      );
    };
    const requested = this.pool.connect();
    this.pending.add(requested);
    const claimed = requested.then(
      (client): Lease => {
        this.pending.delete(requested);
        const state = this.states.get(client)!;
        let released = false,
          releaseFailed = false,
          releaseError: unknown;
        const cancel = () => {
          try {
            lease.release(true);
          } catch {
            this.observerFailures++;
            if (typeof client.end === 'function') void client.end().catch(() => undefined);
          }
        };
        const lease: Lease = {
          client,
          state,
          get released() {
            return released;
          },
          release: (discard = false) => {
            if (released) {
              if (releaseFailed) throw releaseError;
              return;
            }
            released = true;
            deadline.signal.removeEventListener('abort', cancel);
            this.active.delete(client);
            try {
              client.release(discard || state.broken || this.closed);
            } catch (cause) {
              releaseFailed = true;
              releaseError = cause;
              throw cause;
            } finally {
              this.gauges();
            }
          },
        };
        this.active.set(client, { lease, deadline });
        deadline.signal.addEventListener('abort', cancel, { once: true });
        if (this.closed || deadline.signal.aborted) {
          lease.release(true);
          deadline.check();
          this.open();
        }
        observe();
        this.gauges();
        return lease;
      },
      (error: unknown) => {
        this.pending.delete(requested);
        throw postgresError(error, 'connect');
      },
    );
    // A cancelled waiter still owns the eventual native lease and must release it.
    void claimed.catch(() => undefined);
    try {
      return await deadline.run(() => claimed);
    } catch (cause) {
      observe();
      if (cause instanceof KitError && cause.code === 'EK_TIMEOUT')
        throw new KitError({
          code: 'EK_DATABASE_POOL_TIMEOUT',
          message: 'PostgreSQL pool acquisition deadline exceeded',
          cause,
          retryable: true,
        });
      throw cause;
    }
  }

  private async reset(lease: Lease, deadline: SqlDeadline): Promise<void> {
    // A portable checkout cannot inherit session roles, search paths, listeners or temporary state.
    await deadline.run(() => lease.client.query('DISCARD ALL'));
    // DISCARD invalidates server prepared statements; synchronize pg's corresponding local caches.
    const native = lease.client.connection as unknown as {
      parsedStatements?: Record<string, unknown>;
      submittedNamedStatements?: Record<string, unknown>;
    };
    for (const cache of [native.parsedStatements, native.submittedNamedStatements])
      if (cache) for (const key of Object.keys(cache)) delete cache[key];
    await deadline.run(() =>
      lease.client.query("SET client_encoding TO 'UTF8'; SET standard_conforming_strings TO on"),
    );
    lease.state.standard = true;
    lease.state.encoding = 'UTF8';
  }

  private compile(statement: SqlStatement, state?: SessionState): CompiledSql {
    if (state && state.encoding !== 'UTF8')
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Portable PostgreSQL statements require a UTF-8 session',
      });
    const compiled = compileSql(statement, 'postgres', {
      standardConformingStrings: state?.standard ?? true,
    });
    portableControl(compiled.text);
    return compiled;
  }

  private async cursor(
    lease: Lease,
    compiled: CompiledSql,
    kind: Kind,
    limit: number,
    deadline: SqlDeadline,
    session: MeterSession | undefined,
  ): Promise<SqlResult> {
    deadline.check();
    const attrs = {
      'db.system.name': 'postgresql',
      'db.operation.name': kind === 'queryOne' ? 'query' : kind,
    };
    return instrumentOperation(
      this.observation.telemetry,
      'db.client.operation',
      attrs,
      async () => {
        deadline.check();
        const began = performance.now();
        let cursor: Cursor<Row> | undefined,
          failed = false,
          primary: unknown,
          answer: SqlResult | undefined;
        this.operationCount++;
        this.diagnostic(() => session?.recordOperation('db.query'));
        this.missing(session, 'driver_bytes_unavailable');
        try {
          cursor = lease.client.query(
            new Cursor<Row>(compiled.text, [...(compiled.parameters as readonly unknown[])], {
              types: this.typePolicy,
            }),
          );
          const rows: Row[] = [];
          let result: QueryResult | undefined;
          let fetches = 0;
          while (true) {
            const fetch = kind === 'queryOne' ? 2 : Math.min(256, limit + 1 - rows.length);
            const page = await deadline.run(
              () =>
                new Promise<Row[]>((resolve, reject) => {
                  cursor!.read(fetch, (error, values, metadata) => {
                    if (error) reject(error);
                    else {
                      if (metadata) result = metadata;
                      resolve(values);
                    }
                  });
                }),
            );
            fetches++;
            if (kind === 'queryOne' && page.length > 1)
              throw new KitError({
                code: 'EK_DATABASE_QUERY',
                message: 'SQL queryOne returned more than one row',
              });
            if (rows.length + page.length > limit)
              throw new KitError({
                code: 'EK_DATABASE_QUERY',
                message: 'SQL result exceeds maxRows',
                details: { limitExceeded: true },
              });
            rows.push(...page);
            if (kind === 'queryOne' || page.length < fetch) break;
          }
          const count =
            // Portal completion tags count the final Execute batch, including DML RETURNING.
            fetches === 1 &&
            typeof result?.rowCount === 'number' &&
            Number.isSafeInteger(result.rowCount) &&
            result.rowCount >= 0
              ? result.rowCount
              : null;
          const affected =
            count !== null &&
            ['INSERT', 'UPDATE', 'DELETE', 'MERGE'].includes(result?.command ?? '');
          answer = Object.freeze({
            rows: Object.freeze(rows),
            rowCount: count,
            metadata: Object.freeze(affected ? { affectedRows: count } : {}),
          });
        } catch (cause) {
          failed = true;
          primary = postgresError(cause, 'query');
          this.diagnostic(() =>
            this.observation.logger?.warn('PostgreSQL statement failed', {
              driver: 'postgresql',
              connection: this.name,
              fingerprint: compiled.fingerprint,
              errorCode: (primary as KitError).code,
            }),
          );
        } finally {
          try {
            if (cursor && !lease.released) {
              const cleanup = new SqlDeadline({ timeoutMs: 5000 }, this.stop.signal);
              try {
                await cleanup.run(() => cursor!.close());
              } catch (cause) {
                let cleanupCause: unknown = cause;
                try {
                  lease.release(true);
                } catch (release) {
                  cleanupCause = new AggregateError([cause, release]);
                }
                primary = new KitError({
                  code: 'EK_DATABASE_QUERY',
                  message: 'PostgreSQL cursor cleanup failed',
                  cause: failed ? new AggregateError([primary, cleanupCause]) : cleanupCause,
                });
                failed = true;
              } finally {
                cleanup.close();
              }
            }
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
        }
        if (failed) throw primary;
        return answer!;
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
    setMaxListeners(Math.min(this.capacity + 16, 2_147_483_647), deadline.signal);
    const session = this.current();
    let lease: Lease | undefined,
      failed = false,
      primary: unknown,
      reset = false,
      answer: SqlResult | undefined;
    try {
      lease = await this.acquire(deadline);
      await this.reset(lease, deadline);
      reset = true;
      answer = await this.cursor(lease, compiled, kind, limit, deadline, session);
    } catch (cause) {
      failed = true;
      primary = postgresError(cause, 'query');
    } finally {
      deadline.close();
      try {
        lease?.release(deadline.signal.aborted || !reset);
      } catch (cleanup) {
        primary = new KitError({
          code: 'EK_DATABASE_QUERY',
          message: 'PostgreSQL lease release failed',
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
      discard = false;
    let failed = false,
      primary: unknown,
      answer: T | undefined;
    let queue: Promise<unknown> = Promise.resolve();
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
            message: 'PostgreSQL transaction handle is no longer active',
          }),
        );
      if (pending.size >= this.capacity)
        return Promise.reject(
          new KitError({
            code: 'EK_DATABASE_TRANSACTION',
            message: 'PostgreSQL pending transaction statement capacity is exhausted',
          }),
        );
      const captured = captureSqlStatement(statement);
      const limit = rowLimit(input);
      const operation = new SqlDeadline(input, deadline.signal);
      const cancel = () => {
        if (!deadline.signal.aborted) deadline.abort(operation.signal.reason as KitError);
      };
      operation.signal.addEventListener('abort', cancel, { once: true });
      const session = this.current();
      if (operation.signal.aborted) cancel();
      const previous = queue;
      const work = operation.run(() =>
        previous.then(() => {
          operation.check();
          return this.cursor(
            lease!,
            this.compile(captured, lease!.state),
            kind,
            limit,
            operation,
            session,
          );
        }),
      );
      // Capture the previous queue before publishing this operation's tail.
      queue = work.then(
        () => undefined,
        () => undefined,
      );
      pending.add(work);
      void work.then(
        () => pending.delete(work),
        () => pending.delete(work),
      );
      void work
        .finally(() => {
          operation.signal.removeEventListener('abort', cancel);
          operation.close();
        })
        .catch(() => undefined);
      return work;
    };
    try {
      lease = await this.acquire(deadline);
      await this.reset(lease, deadline);
      await deadline.run(() => lease!.client.query('BEGIN'));
      began = true;
      const tx: SqlTransaction = Object.freeze({
        query: async <R extends object = Row>(statement: SqlStatement, input?: SqlQueryOptions) =>
          enqueue(statement, 'query', input) as Promise<SqlResult<R>>,
        execute: async (statement: SqlStatement, input?: OperationOptions) =>
          enqueue(statement, 'execute', input),
      });
      const value = await deadline.run(async () => {
        const answer = await handler(tx);
        active = false;
        const tail = await Promise.allSettled([...pending]);
        const rejected = tail.find((result) => result.status === 'rejected');
        if (rejected?.status === 'rejected') throw rejected.reason;
        return answer;
      });
      committing = true;
      let committed: QueryResult;
      try {
        committed = await deadline.run(() => lease!.client.query('COMMIT'));
      } catch (cause) {
        throw postgresCommitError(cause);
      }
      if (committed.command !== 'COMMIT')
        throw new KitError({
          code: 'EK_DATABASE_TRANSACTION',
          message: 'PostgreSQL rolled back the transaction before commit',
          details: { outcome: 'rolled_back' },
        });
      answer = value;
    } catch (cause) {
      failed = true;
      primary = cause;
      if (began && !committing && lease && !lease.released) {
        const cleanup = new SqlDeadline({ timeoutMs: 5000 }, this.stop.signal);
        try {
          await cleanup.run(() => queue);
          await cleanup.run(() => lease!.client.query('ROLLBACK'));
        } catch (rollback) {
          discard = true;
          primary = new KitError({
            code: 'EK_DATABASE_TRANSACTION',
            message: 'PostgreSQL transaction and rollback failed',
            cause: new AggregateError([cause, rollback]),
          });
        } finally {
          cleanup.close();
        }
      }
      if (committing || !began) discard = true;
    } finally {
      active = false;
      deadline.close();
      try {
        lease?.release(deadline.signal.aborted || discard);
      } catch (cleanup) {
        primary = new KitError({
          code: 'EK_DATABASE_TRANSACTION',
          message: 'PostgreSQL transaction lease release failed',
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
          ?.healthy === 1
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
    return Object.freeze({
      total: this.pool.totalCount,
      idle: this.pool.idleCount,
      active: this.pool.totalCount - this.pool.idleCount,
      waiting: this.pool.waitingCount,
      pendingAcquires: this.pending.size,
      operations: this.operationCount,
      observerFailures: this.observerFailures,
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
      for (const { lease } of [...this.active.values()]) lease.release(true);
      await Promise.allSettled([...this.pending]);
      await this.pool.end();
      this.gauges();
    })();
    return this.closing;
  }
}
