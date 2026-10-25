import { performance } from 'node:perf_hooks';
import { setMaxListeners } from 'node:events';
import oracledb from 'oracledb';
import type {
  Connection,
  Pool,
  PoolAttributes,
  Result,
  ResultSet,
  ExecuteOptions,
  BindParameters,
  DbType,
} from 'oracledb';
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
import { SqlDeadline } from '@arkenivajs/database/support';
import type { SqlConnectionAdapter, SqlObservationPorts } from '@arkenivajs/database/support';
import { oracleError, oracleCommitError } from './errors.js';

type Row = Record<string, unknown>;
type Kind = 'query' | 'queryOne' | 'execute' | 'ping';
// The native SDK mode belongs to the process, including pools still being initialized.
let processMode: 'thin' | 'thick' | undefined;
interface Lease {
  readonly client: Connection;
  readonly released: boolean;
  own(cleanup: () => Promise<void>): () => void;
  call<T>(work: () => Promise<T>, late?: (value: T) => Promise<void>): Promise<T>;
  release(drop?: boolean): Promise<void>;
}

function limitRows(options: SqlQueryOptions = {}): number {
  const limit = options?.maxRows ?? 10_000;
  if (
    !options ||
    typeof options !== 'object' ||
    Array.isArray(options) ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 100_000
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'SQL maxRows must be an integer from 1 to 100000',
    });
  return limit;
}

function compile(statement: SqlStatement): CompiledSql {
  const compiled = compileSql(statement, 'oracle');
  const nativeNames = new Map<string, string>();
  for (const name of compiled.names) {
    const normalized = name.toUpperCase(),
      previous = nativeNames.get(normalized);
    if (previous !== undefined && previous !== name)
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Oracle bind names collide after native case folding',
      });
    nativeNames.set(normalized, name);
  }
  // Skip only lexical trivia already validated by the finite-state compiler.
  const command = compiled.text
    .replace(/^(?:\s|--[^\r\n]*(?:\r?\n|$)|\/\*[\s\S]*?\*\/)+/, '')
    .match(/^[A-Za-z]+/)?.[0]
    ?.toUpperCase();
  if (
    ['BEGIN', 'DECLARE', 'COMMIT', 'ROLLBACK', 'SAVEPOINT', 'SET', 'CALL'].includes(command ?? '')
  )
    throw new KitError({
      code: 'EK_DATABASE_TRANSACTION',
      message: 'Oracle transaction control and PL/SQL require the owned callback or native API',
    });
  return compiled;
}

const exactTypes = new Set<DbType>([
  oracledb.DB_TYPE_NUMBER,
  oracledb.DB_TYPE_BINARY_FLOAT,
  oracledb.DB_TYPE_BINARY_DOUBLE,
]);
const nativeTypes = new Set<DbType>([
  oracledb.DB_TYPE_CLOB,
  oracledb.DB_TYPE_NCLOB,
  oracledb.DB_TYPE_BLOB,
  oracledb.DB_TYPE_BFILE,
  oracledb.DB_TYPE_OBJECT,
  oracledb.DB_TYPE_CURSOR,
  oracledb.DB_TYPE_JSON,
  oracledb.DB_TYPE_VECTOR,
  oracledb.DB_TYPE_XMLTYPE,
  oracledb.DB_TYPE_DATE,
  oracledb.DB_TYPE_TIMESTAMP,
  oracledb.DB_TYPE_TIMESTAMP_TZ,
  oracledb.DB_TYPE_TIMESTAMP_LTZ,
]);

/** Per-execution conversion avoids process-wide number, date and LOB conversion settings. */
export const oracleFetchType: NonNullable<ExecuteOptions['fetchTypeHandler']> = (metadata) => {
  if (nativeTypes.has(metadata.dbType!))
    throw new KitError({
      code: 'EK_DATABASE_QUERY',
      message:
        'Oracle temporal results require explicit TO_CHAR; LOB and advanced results require the owned native API',
    });
  // Explicit types and an identity converter override ambient fetch and legacy JSON conversion.
  return {
    type: exactTypes.has(metadata.dbType!) ? oracledb.DB_TYPE_VARCHAR : metadata.dbType!,
    converter: (value) => value,
  };
};

function binds(compiled: CompiledSql): BindParameters {
  const values: BindParameters = Object.create(null) as Record<string, oracledb.BindParameter>;
  for (const [name, value] of Object.entries(
    compiled.parameters as Readonly<Record<string, SqlValue>>,
  ))
    values[name] =
      value instanceof Date
        ? Date.prototype.toISOString.call(value)
        : typeof value === 'bigint'
          ? String(value)
          : value instanceof Uint8Array
            ? Buffer.from(value)
            : value;
  return values;
}

/** One native pool owns bounded cursors, pinned transactions and late acquisition cleanup. */
export class OracleConnection implements SqlConnectionAdapter {
  private readonly stop = new AbortController();
  private readonly active = new Map<Connection, Lease>();
  private readonly pending = new Set<Promise<Lease>>();
  private readonly disposing = new Set<Promise<void>>();
  private readonly cleanupFailures: unknown[] = [];
  private readonly capacity: number;
  private closed = false;
  private closing: Promise<void> | undefined;
  private observerFailures = 0;
  private operations = 0;
  private cleanupCount = 0;

  private constructor(
    private readonly name: string,
    private readonly pool: Pool,
    private readonly observation: SqlObservationPorts,
  ) {
    this.capacity = Math.max(pool.poolMax, 128);
    setMaxListeners(this.capacity * 2 + 16, this.stop.signal);
  }

  /** The SDK mode is process-wide; a conflicting existing mode fails before pool creation. */
  static async create(
    name: string,
    config: PoolAttributes,
    observation: SqlObservationPorts,
    mode: 'thin' | 'thick',
    options: OperationOptions = {},
  ): Promise<OracleConnection> {
    const deadline = new SqlDeadline(options);
    try {
      deadline.check();
      if (processMode !== undefined && processMode !== mode)
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Oracle mode conflicts with the mode already selected in this process',
        });
      if (mode === 'thick' && oracledb.thin) oracledb.initOracleClient();
      if (oracledb.thin !== (mode === 'thin'))
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Oracle process-wide Thin/Thick mode conflicts with the requested mode',
        });
      processMode = mode;
      const requested = oracledb.createPool(config).then(async (pool) => {
        if (deadline.signal.aborted) {
          await pool.close(0);
          deadline.check();
        }
        return new OracleConnection(name, pool, observation);
      });
      return await deadline.run(() => requested);
    } catch (cause) {
      throw oracleError(cause, 'connect');
    } finally {
      deadline.close();
    }
  }

  private open(): void {
    if (this.closed)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Oracle pool is closed' });
  }
  private remember(cause: unknown): void {
    this.cleanupCount++;
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
  private missing(session: MeterSession | undefined, reason: string): void {
    if (!session) return;
    this.diagnostic(() => {
      const meter = this.observation.meter as SqlObservationPorts['meter'] & {
        markMissing?: (session: MeterSession, reason: string) => void;
      };
      if (!meter?.markMissing) throw new Error('Meter quality controls are unavailable');
      meter.markMissing(session, reason);
    });
  }

  private releaseError(
    message: string,
    failure: unknown,
    cause: unknown,
    failed: boolean,
  ): KitError {
    const outcome = failure instanceof KitError ? failure.details?.outcome : undefined;
    return new KitError({
      code: outcome === undefined ? 'EK_DATABASE_QUERY' : 'EK_DATABASE_TRANSACTION',
      message,
      cause: failed ? new AggregateError([failure, cause]) : cause,
      ...(typeof outcome === 'string' ? { details: { outcome } } : {}),
    });
  }

  private async acquire(deadline: SqlDeadline): Promise<Lease> {
    this.open();
    deadline.check();
    if (this.active.size + this.pending.size >= this.capacity)
      throw new KitError({
        code: 'EK_DATABASE_POOL_TIMEOUT',
        message: 'Oracle acquisition capacity is exhausted',
        retryable: true,
      });
    const began = performance.now();
    const requested = this.pool.getConnection().then(
      async (client): Promise<Lease> => {
        let disposal: Promise<void> | undefined;
        const running = new Set<Promise<unknown>>();
        const owned = new Set<() => Promise<void>>();
        const cancel = () => {
          void lease.release(true).catch((cause: unknown) => this.remember(cause));
        };
        const lease: Lease = {
          client,
          get released() {
            return disposal !== undefined;
          },
          own(cleanup) {
            owned.add(cleanup);
            return () => {
              owned.delete(cleanup);
            };
          },
          call: <T>(work: () => Promise<T>, late?: (value: T) => Promise<void>): Promise<T> => {
            const promise = Promise.resolve()
              .then(work)
              .then(async (value) => {
                if (disposal && late) await late(value);
                return value;
              });
            running.add(promise);
            void promise.then(
              () => running.delete(promise),
              () => running.delete(promise),
            );
            return promise;
          },
          release: (drop = false) => {
            if (disposal) return disposal;
            deadline.signal.removeEventListener('abort', cancel);
            this.active.delete(client);
            disposal = (async () => {
              const cleanup = new SqlDeadline({ timeoutMs: 5000 });
              const failures: unknown[] = [];
              // A cancelled native call is observed before its session can re-enter the pool.
              if (drop)
                try {
                  await cleanup.run(() => client.break());
                } catch (cause) {
                  failures.push(cause);
                }
              try {
                await cleanup.run(() => Promise.allSettled([...running]));
              } catch (cause) {
                failures.push(cause);
              }
              for (const close of owned) {
                const closing = Promise.resolve().then(close);
                try {
                  await cleanup.run(() => closing);
                } catch (cause) {
                  failures.push(cause);
                }
                void closing.catch((cause: unknown) => this.remember(cause));
              }
              const closing = client.close({ drop: drop || this.closed || failures.length > 0 });
              void closing.catch((cause: unknown) => this.remember(cause));
              try {
                await cleanup.run(() => closing);
              } catch (cause) {
                failures.push(cause);
              }
              cleanup.close();
              if (failures.length)
                throw new AggregateError(failures, 'Oracle connection disposal failed');
            })();
            this.disposing.add(disposal);
            void disposal.then(
              () => this.disposing.delete(disposal!),
              () => this.disposing.delete(disposal!),
            );
            return disposal;
          },
        };
        try {
          client.callTimeout = 5000;
        } catch (cause) {
          try {
            await lease.release(true);
          } catch (cleanup) {
            throw new AggregateError(
              [cause, cleanup],
              'Oracle timeout configuration and disposal failed',
              { cause: cleanup },
            );
          }
          throw cause;
        }
        if (this.closed || deadline.signal.aborted) {
          try {
            await lease.release(true);
          } catch (cause) {
            this.remember(cause);
            throw cause;
          }
          deadline.check();
          this.open();
        }
        this.active.set(client, lease);
        deadline.signal.addEventListener('abort', cancel, { once: true });
        return lease;
      },
      (cause: unknown) => {
        throw oracleError(cause, 'connect');
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
          message: 'Oracle pool acquisition deadline exceeded',
          cause,
          retryable: true,
        });
      throw cause;
    } finally {
      this.diagnostic(() =>
        this.observation.telemetry?.recordHistogram(
          'arkenivajs.db.pool.acquire.duration',
          (performance.now() - began) / 1000,
          { pool: this.name, driver: 'oracle' },
        ),
      );
    }
  }

  private command(lease: Lease, text: string, deadline: SqlDeadline): Promise<unknown> {
    return deadline.run(() =>
      lease.call(() => lease.client.execute(text, {}, { autoCommit: false })),
    );
  }
  private async reset(lease: Lease, deadline: SqlDeadline): Promise<void> {
    await deadline.run(() => lease.call(() => lease.client.rollback()));
    await this.command(
      lease,
      `ALTER SESSION SET TIME_ZONE = '+00:00' NLS_NUMERIC_CHARACTERS = '.,' NLS_DATE_FORMAT = 'YYYY-MM-DD HH24:MI:SS' NLS_TIMESTAMP_FORMAT = 'YYYY-MM-DD HH24:MI:SS.FF9' NLS_TIMESTAMP_TZ_FORMAT = 'YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM'`,
      deadline,
    );
  }

  private async run(
    lease: Lease,
    compiled: CompiledSql,
    kind: Kind,
    limit: number,
    deadline: SqlDeadline,
    session: MeterSession | undefined,
    transaction = false,
  ): Promise<SqlResult> {
    const attributes = {
      'db.system.name': 'oracle',
      'db.operation.name': kind === 'queryOne' ? 'query' : kind,
    };
    return instrumentOperation(
      this.observation.telemetry,
      'db.client.operation',
      attributes,
      async () => {
        deadline.check();
        this.operations++;
        this.diagnostic(() => session?.recordOperation('db.query'));
        this.missing(session, 'driver_bytes_unavailable');
        const began = performance.now();
        let cursor: ResultSet<Row> | undefined,
          result: SqlResult | undefined,
          failure: unknown,
          failed = false;
        const cursorClosures = new Map<ResultSet<Row>, Promise<void>>();
        let disown = () => {};
        const closeCursor = (value: ResultSet<Row>) => {
          let closing = cursorClosures.get(value);
          if (!closing) {
            closing = value.close().finally(() => disown());
            cursorClosures.set(value, closing);
          }
          return closing;
        };
        try {
          const native = await deadline.run(() =>
            lease.call(
              () =>
                lease.client
                  .execute<Row>(compiled.text, binds(compiled), {
                    autoCommit: false,
                    resultSet: true,
                    outFormat: oracledb.OUT_FORMAT_OBJECT,
                    prefetchRows: 0,
                    fetchArraySize: Math.min(256, limit + 1),
                    fetchTypeHandler: oracleFetchType,
                    dbObjectAsPojo: false,
                  })
                  .then((value) => {
                    if (value.resultSet) disown = lease.own(() => closeCursor(value.resultSet!));
                    return value;
                  }),
              async (late: Result<Row>) => {
                if (late.resultSet) await closeCursor(late.resultSet);
              },
            ),
          );
          cursor = native.resultSet;
          const rows: Row[] = [];
          if (cursor) {
            while (true) {
              const batch = await deadline.run(() =>
                lease.call(() => cursor!.getRows(Math.min(256, limit + 1 - rows.length))),
              );
              if (batch.length === 0) break;
              if (rows.length + batch.length > limit)
                throw new KitError({
                  code: 'EK_DATABASE_QUERY',
                  message:
                    kind === 'queryOne'
                      ? 'SQL queryOne returned more than one row'
                      : 'SQL result exceeds maxRows',
                  ...(kind === 'queryOne' ? {} : { details: { limitExceeded: true } }),
                });
              rows.push(...batch);
            }
          }
          if (transaction && lease.client.transactionInProgress !== true)
            throw new KitError({
              code: 'EK_DATABASE_TRANSACTION',
              message:
                'Oracle transaction ended during statement execution; prior effects may have committed',
              retryable: false,
              details: {
                outcome:
                  lease.client.transactionInProgress === false ? 'implicitly_committed' : 'unknown',
              },
            });
          const count =
            Number.isSafeInteger(native.rowsAffected) && native.rowsAffected! >= 0
              ? native.rowsAffected!
              : null;
          result = Object.freeze({
            rows: Object.freeze(rows),
            rowCount: cursor ? rows.length : count,
            metadata: Object.freeze(count === null ? {} : { affectedRows: count }),
          });
        } catch (cause) {
          failed = true;
          failure = oracleError(cause, 'query');
        } finally {
          if (cursor) {
            const cleanup = new SqlDeadline({ timeoutMs: 5000 });
            try {
              await cleanup.run(() => lease.call(() => closeCursor(cursor!)));
            } catch (cause) {
              failure = new KitError({
                code: 'EK_DATABASE_QUERY',
                message: 'Oracle cursor cleanup failed',
                cause: failed ? new AggregateError([failure, cause]) : cause,
              });
              failed = true;
            } finally {
              cleanup.close();
            }
          }
          const elapsed = performance.now() - began;
          this.diagnostic(() =>
            this.observation.telemetry?.recordHistogram(
              'db.client.operation.duration',
              elapsed / 1000,
              attributes,
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
            this.observation.logger?.warn('Oracle statement failed', {
              driver: 'oracle',
              connection: this.name,
              fingerprint: compiled.fingerprint,
              errorCode: (failure as KitError).code,
            }),
          );
          throw failure;
        }
        return result!;
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
    const compiled = compile(statement),
      limit = kind === 'queryOne' ? 1 : limitRows(options);
    const deadline = new SqlDeadline(options, this.stop.signal);
    let lease: Lease | undefined,
      result: SqlResult | undefined,
      failure: unknown,
      failed = false;
    try {
      lease = await this.acquire(deadline);
      await this.reset(lease, deadline);
      result = await this.run(lease, compiled, kind, limit, deadline, this.current());
      // autoCommit on execute would commit before a bounded RETURNING result is validated.
      try {
        await deadline.run(() => lease!.call(() => lease!.client.commit()));
      } catch (cause) {
        throw oracleCommitError(cause);
      }
    } catch (cause) {
      failed = true;
      failure = oracleError(cause, 'query');
    } finally {
      deadline.close();
      try {
        await lease?.release(failed);
      } catch (cause) {
        failure = this.releaseError('Oracle lease release failed', failure, cause, failed);
        failed = true;
      }
    }
    if (failed) throw failure;
    return result!;
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
    return (
      ((await this.standalone(statement, 'queryOne', options)).rows[0] as T | undefined) ?? null
    );
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
    setMaxListeners(this.capacity + 16, deadline.signal);
    let lease: Lease | undefined,
      active = true,
      began = false,
      committing = false,
      failed = false,
      failure: unknown,
      result: T | undefined;
    let queue: Promise<unknown> = Promise.resolve(),
      statementFailed = false,
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
            message: 'Oracle transaction handle is no longer active',
          }),
        );
      if (pending.size >= this.capacity)
        return Promise.reject(
          new KitError({
            code: 'EK_DATABASE_TRANSACTION',
            message: 'Oracle pending transaction statement capacity is exhausted',
          }),
        );
      const compiled = compile(statement),
        limit = limitRows(input),
        operation = new SqlDeadline(input);
      const parent = () => operation.abort(deadline.signal.reason as KitError),
        cancel = () => deadline.abort(operation.signal.reason as KitError);
      deadline.signal.addEventListener('abort', parent, { once: true });
      operation.signal.addEventListener('abort', cancel, { once: true });
      if (operation.signal.aborted) cancel();
      if (deadline.signal.aborted) parent();
      const previous = queue,
        session = this.current();
      const work = operation.run(() =>
        previous.then(async () => {
          operation.check();
          if (statementFailed) throw statementFailure;
          try {
            return await this.run(lease!, compiled, kind, limit, operation, session, true);
          } catch (cause) {
            statementFailed = true;
            statementFailure = oracleError(cause, 'query');
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
          deadline.signal.removeEventListener('abort', parent);
          operation.signal.removeEventListener('abort', cancel);
          operation.close();
        })
        .catch(() => undefined);
      return work;
    };
    try {
      lease = await this.acquire(deadline);
      await this.reset(lease, deadline);
      await this.command(lease, 'SET TRANSACTION READ WRITE', deadline);
      began = true;
      const tx: SqlTransaction = Object.freeze({
        query: async <R extends object = Row>(statement: SqlStatement, input?: SqlQueryOptions) =>
          enqueue(statement, 'query', input) as Promise<SqlResult<R>>,
        execute: async (statement: SqlStatement, input?: OperationOptions) =>
          enqueue(statement, 'execute', input),
      });
      const answer = await deadline.run(async () => {
        const value = await handler(tx);
        active = false;
        await queue;
        if (statementFailed) throw statementFailure;
        return value;
      });
      committing = true;
      try {
        await deadline.run(() => lease!.call(() => lease!.client.commit()));
      } catch (cause) {
        throw oracleCommitError(cause);
      }
      result = answer;
    } catch (cause) {
      failed = true;
      failure = began ? cause : oracleError(cause, 'query');
      if (began && !committing && lease && !lease.released) {
        const cleanup = new SqlDeadline({ timeoutMs: 5000 });
        try {
          await cleanup.run(() => queue);
          await cleanup.run(() => lease!.call(() => lease!.client.rollback()));
        } catch (rollback) {
          failure = new KitError({
            code: 'EK_DATABASE_TRANSACTION',
            message: 'Oracle transaction and rollback failed',
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
      } catch (cause) {
        failure = this.releaseError(
          'Oracle transaction lease release failed',
          failure,
          cause,
          failed,
        );
        failed = true;
      }
    }
    if (failed) throw failure;
    return result as T;
  }

  async ping(options?: OperationOptions): Promise<boolean> {
    try {
      return (
        (await this.standalone({ text: 'SELECT 1 AS "healthy" FROM DUAL' }, 'ping', options))
          .rows[0]?.healthy === '1'
      );
    } catch (cause) {
      if (
        cause instanceof KitError &&
        ((cause.code === 'EK_DATABASE_CONNECT' && cause.retryable) ||
          ['EK_DATABASE_UNAVAILABLE', 'EK_DATABASE_POOL_TIMEOUT'].includes(cause.code))
      )
        return false;
      throw cause;
    }
  }
  stats(): Readonly<Record<string, number | null>> {
    this.open();
    return Object.freeze({
      total: this.pool.connectionsOpen,
      nativeActive: this.pool.connectionsInUse,
      idle: this.pool.connectionsOpen - this.pool.connectionsInUse,
      waiting: null,
      active: this.active.size,
      pendingAcquires: this.pending.size,
      operations: this.operations,
      observerFailures: this.observerFailures,
      cleanupFailures: this.cleanupCount,
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
      const deadline = new SqlDeadline({ timeoutMs: 5000 });
      const failures: unknown[] = [];
      try {
        await deadline.run(() => Promise.allSettled([...this.pending]));
      } catch (cause) {
        failures.push(cause);
      }
      try {
        const settled = await deadline.run(() => Promise.allSettled([...this.disposing]));
        failures.push(
          ...settled
            .filter((item) => item.status === 'rejected')
            .map((item) => item.reason as unknown),
        );
      } catch (cause) {
        failures.push(cause);
      }
      failures.push(...this.cleanupFailures);
      const closing = this.pool.close(0);
      void closing.catch((cause: unknown) => this.remember(cause));
      try {
        await deadline.run(() => closing);
      } catch (cause) {
        failures.push(cause);
      }
      deadline.close();
      if (failures.length)
        throw new KitError({
          code: 'EK_DATABASE_UNAVAILABLE',
          message: 'Oracle pool shutdown cleanup failed',
          cause: new AggregateError(failures),
        });
    })();
    return this.closing;
  }
}
