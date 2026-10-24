import { performance } from 'node:perf_hooks';
import { EventEmitter, setMaxListeners } from 'node:events';
import { createPool } from 'mariadb';
import type { Pool, PoolConnection, Prepare } from 'mariadb';
import { KitError } from '@arkenivajs/core';
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
import type { MariadbConfiguration } from './config.js';
import { mariadbError, mariadbCommitError } from './errors.js';

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
  release(discard?: boolean): Promise<void>;
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
      message:
        'MariaDB transaction control and procedures require the owned callback or native API',
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
export class MariadbConnection implements SqlConnectionAdapter {
  private readonly pool: Pool;
  private readonly stop = new AbortController();
  private readonly active = new Map<PoolConnection, { lease: Lease; deadline: SqlDeadline }>();
  private readonly pending = new Set<Promise<Lease>>();
  private readonly disposing = new Set<Promise<void>>();
  private readonly cleanupFailures: unknown[] = [];
  private cleanupFailureCount = 0;
  private readonly capacity: number;
  private closed = false;
  private closing: Promise<void> | undefined;
  private observerFailures = 0;
  private operations = 0;

  constructor(
    private readonly name: string,
    private readonly config: MariadbConfiguration,
    private readonly observation: SqlObservationPorts,
  ) {
    this.capacity = Math.max(config.pool.connectionLimit ?? 10, 128);
    setMaxListeners(Math.min(this.capacity * 2 + 16, 2_147_483_647), this.stop.signal);
    this.pool = createPool(config.pool);
    // The native pool emits errors even though its upstream Pool declaration omits that event.
    const events = this.pool as Pool & EventEmitter;
    events.on('error', () =>
      this.diagnostic(() =>
        this.observation.logger?.warn('MariaDB pool connection failed', {
          driver: 'mariadb',
          connection: name,
        }),
      ),
    );
  }

  private open(): void {
    if (this.closed)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'MariaDB pool is closed' });
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
        message: 'MariaDB acquisition capacity is exhausted',
        retryable: true,
      });
    const began = performance.now();
    const requested = this.pool.getConnection().then(
      async (client): Promise<Lease> => {
        let disposal: Promise<void> | undefined;
        const onError = (cause: unknown) => deadline.abort(mariadbError(cause, 'query'));
        const discard = () => {
          void lease.release(true).catch((cause: unknown) => this.rememberCleanup(cause));
        };
        const lease: Lease = {
          client,
          state: { mode: SQL_MODE, encoding: 'utf8mb4', zone: '+00:00' },
          get released() {
            return disposal !== undefined;
          },
          release: (destroy = false) => {
            if (disposal) return disposal;
            deadline.signal.removeEventListener('abort', discard);
            client.removeListener('error', onError);
            this.active.delete(client);
            disposal = (async () => {
              if (destroy || this.closed) client.destroy();
              else await client.release();
            })();
            this.disposing.add(disposal);
            void disposal.then(
              () => this.disposing.delete(disposal!),
              () => this.disposing.delete(disposal!),
            );
            return disposal;
          },
        };
        if (this.closed || deadline.signal.aborted) {
          try {
            await lease.release(true);
          } catch (cause) {
            this.rememberCleanup(cause);
            throw cause;
          }
          deadline.check();
          this.open();
        }
        this.active.set(client, { lease, deadline });
        client.on('error', onError);
        deadline.signal.addEventListener('abort', discard, { once: true });
        return lease;
      },
      (cause: unknown): never => {
        throw mariadbError(cause, 'connect');
      },
    );
    this.pending.add(requested);
    void requested.then(
      () => this.pending.delete(requested),
      () => this.pending.delete(requested),
    );
    try {
      return await deadline.run(() => requested);
    } catch (cause) {
      if (cause instanceof KitError && cause.code === 'EK_TIMEOUT')
        throw new KitError({
          code: 'EK_DATABASE_POOL_TIMEOUT',
          message: 'MariaDB pool acquisition deadline exceeded',
          cause,
          retryable: true,
        });
      throw cause;
    } finally {
      this.diagnostic(() =>
        this.observation.telemetry?.recordHistogram(
          'arkenivajs.db.pool.acquire.duration',
          (performance.now() - began) / 1000,
          { pool: this.name, driver: 'mariadb' },
        ),
      );
    }
  }

  private command(lease: Lease, text: string, deadline: SqlDeadline): Promise<unknown> {
    return deadline.run(() => lease.client.query<unknown>(text));
  }
  private async reset(lease: Lease, deadline: SqlDeadline): Promise<void> {
    await deadline.run(() => lease.client.reset());
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
    )) as Row[];
    if (
      !Array.isArray(rows) ||
      rows.length !== 1 ||
      ['mode', 'encoding', 'zone'].some((key) => typeof rows[0]![key] !== 'string')
    )
      throw new KitError({
        code: 'EK_DATABASE_QUERY',
        message: 'MariaDB session settings could not be established',
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
        message: 'Portable MariaDB statements require UTF-8 and UTC session settings',
      });
    const modes = new Set(state.mode.split(','));
    const compiled = compileSql(statement, 'mariadb', {
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
      'db.system.name': 'mariadb',
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
        let prepared: Prepare<unknown[]> | undefined,
          failed = false,
          primary: unknown,
          answer: SqlResult | undefined;
        try {
          const requested = lease.client.prepare<unknown[]>(compiled.text).then((statement) => {
            if (lease.released || deadline.signal.aborted) {
              try {
                statement.close();
              } catch (cause) {
                this.rememberCleanup(cause);
                throw cause;
              }
              deadline.check();
            }
            return statement;
          });
          void requested.catch(() => undefined);
          prepared = await deadline.run(() => requested);
          const values = (compiled.parameters as readonly SqlValue[]).map((value) =>
            typeof value === 'bigint'
              ? String(value)
              : value instanceof Date
                ? // The native binary encoder uses local calendar fields; portable Date binds use UTC text.
                  Date.prototype.toISOString.call(value).slice(0, -1).replace('T', ' ')
                : value instanceof Uint8Array
                  ? Buffer.from(value)
                  : value,
          );
          answer = await deadline.run(
            () =>
              new Promise<SqlResult>((resolve, reject) => {
                const source = prepared!.executeStream(values);
                const rows: Row[] = [];
                let header = true,
                  resultSets = 0,
                  settled = false;
                let metadata: SqlResult['metadata'] = {},
                  count: number | null = null;
                const rejectStream = (cause: unknown) => {
                  if (settled) return;
                  settled = true;
                  // Native close alone resumes row parsing: discard the connection before stopping its stream.
                  const disposal = lease.release(true);
                  let cleanupFailure: unknown,
                    cleanupFailed = false;
                  try {
                    const stream = source as typeof source & { close(): void };
                    stream.close();
                    source.destroy();
                  } catch (cleanup) {
                    cleanupFailed = true;
                    cleanupFailure = cleanup;
                  }
                  void disposal.then(
                    () =>
                      reject(cleanupFailed ? new AggregateError([cause, cleanupFailure]) : cause),
                    (cleanup: unknown) =>
                      reject(
                        new AggregateError([
                          cause,
                          ...(cleanupFailed ? [cleanupFailure] : []),
                          cleanup,
                        ]),
                      ),
                  );
                };
                source.on('error', rejectStream);
                source.on('fields', () => {
                  header = false;
                  if (++resultSets > 1)
                    rejectStream(
                      new KitError({
                        code: 'EK_DATABASE_QUERY',
                        message: 'MariaDB multiple result sets require the native API',
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
                      ...(typeof insertId === 'bigint' ||
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
                        this.observation.logger?.warn('MariaDB statement completed with warnings', {
                          driver: 'mariadb',
                          connection: this.name,
                          fingerprint: compiled.fingerprint,
                          warningStatus: warnings,
                        }),
                      );
                  } else if (rows.length >= limit) {
                    rejectStream(
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
                  const status = lease.client.info?.status;
                  if (transaction && status === undefined) {
                    rejectStream(
                      new KitError({
                        code: 'EK_DATABASE_TRANSACTION',
                        message: 'MariaDB transaction status is unavailable',
                        retryable: false,
                        details: { outcome: 'unknown' },
                      }),
                    );
                    return;
                  }
                  if (transaction && !(status! & 1)) {
                    rejectStream(
                      new KitError({
                        code: 'EK_DATABASE_TRANSACTION',
                        message:
                          'MariaDB statement implicitly committed the transaction; prior effects cannot be rolled back',
                        retryable: false,
                        details: { outcome: 'implicitly_committed' },
                      }),
                    );
                    return;
                  }
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
        } catch (cause) {
          failed = true;
          primary = mariadbError(cause, 'query');
        } finally {
          try {
            prepared?.close();
          } catch (cleanup) {
            let cleanupCause: unknown = cleanup;
            try {
              await lease.release(true);
            } catch (release) {
              cleanupCause = new AggregateError([cleanup, release]);
            }
            primary = new KitError({
              code: 'EK_DATABASE_QUERY',
              message: 'MariaDB prepared statement cleanup failed',
              cause: failed ? new AggregateError([primary, cleanupCause]) : cleanupCause,
            });
            failed = true;
          }
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
        if (failed) {
          this.diagnostic(() =>
            this.observation.logger?.warn('MariaDB statement failed', {
              driver: 'mariadb',
              connection: this.name,
              fingerprint: compiled.fingerprint,
              errorCode: (primary as KitError).code,
            }),
          );
          throw primary;
        }
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
      primary = mariadbError(cause, 'query');
    } finally {
      deadline.close();
      try {
        await lease?.release(failed);
      } catch (cleanup) {
        primary = new KitError({
          code: 'EK_DATABASE_QUERY',
          message: 'MariaDB lease release failed',
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

  async warm(options?: OperationOptions): Promise<void> {
    this.open();
    const deadline = new SqlDeadline(options, this.stop.signal);
    const leases: Lease[] = [];
    let failed = false,
      primary: unknown;
    try {
      deadline.check();
      for (let i = 0; i < this.config.minimum; i++) leases.push(await this.acquire(deadline));
    } catch (cause) {
      failed = true;
      primary = cause;
    } finally {
      deadline.close();
      const closed = await Promise.allSettled(leases.map((lease) => lease.release()));
      const failures = closed
        .filter((result) => result.status === 'rejected')
        .map((result) => result.reason as unknown);
      if (failures.length) {
        primary = new KitError({
          code: 'EK_DATABASE_CONNECT',
          message: 'MariaDB warmup lease cleanup failed',
          cause: new AggregateError([...(failed ? [primary] : []), ...failures]),
        });
        failed = true;
      }
    }
    if (failed) throw primary;
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
            message: 'MariaDB transaction handle is no longer active',
          }),
        );
      if (pending.size >= this.capacity)
        return Promise.reject(
          new KitError({
            code: 'EK_DATABASE_TRANSACTION',
            message: 'MariaDB pending transaction statement capacity is exhausted',
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
            statementFailure = mariadbError(cause, 'query');
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
        throw mariadbCommitError(cause);
      }
      answer = value;
    } catch (cause) {
      failed = true;
      primary = began ? cause : mariadbError(cause, 'query');
      if (began && !committing && lease && !lease.released) {
        const cleanup = new SqlDeadline({ timeoutMs: 5000 }, this.stop.signal);
        try {
          await cleanup.run(() => queue);
          await this.command(lease, 'ROLLBACK', cleanup);
        } catch (rollback) {
          primary = new KitError({
            code: 'EK_DATABASE_TRANSACTION',
            message: 'MariaDB transaction and rollback failed',
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
        await lease?.release(failed);
      } catch (cleanup) {
        primary = new KitError({
          code: 'EK_DATABASE_TRANSACTION',
          message: 'MariaDB transaction lease release failed',
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
      total: this.pool.totalConnections(),
      idle: this.pool.idleConnections(),
      waiting: this.pool.taskQueueSize(),
      nativeActive: this.pool.activeConnections(),
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
      const released = await Promise.allSettled([...this.disposing]);
      await Promise.allSettled([...this.pending]);
      const failures = released
        .filter((result) => result.status === 'rejected')
        .map((result) => result.reason as unknown);
      failures.push(...this.cleanupFailures);
      try {
        await this.pool.end();
      } catch (cause) {
        failures.push(cause);
      }
      if (failures.length)
        throw new KitError({
          code: 'EK_DATABASE_UNAVAILABLE',
          message: 'MariaDB pool shutdown cleanup failed',
          cause: new AggregateError(failures),
        });
    })();
    return this.closing;
  }
}
