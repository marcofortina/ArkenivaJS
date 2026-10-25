import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { setMaxListeners } from 'node:events';
import { BSON } from 'mongodb';
import type { MongoClient, ClientSession, AbstractCursor, Document } from 'mongodb';
import { KitError } from '@arkenivajs/core';
import type {
  DocumentProvider,
  OperationOptions,
  Logger,
  Telemetry,
  UsageMeter,
  MeterSession,
} from '@arkenivajs/core';
import { instrumentOperation, within } from '@arkenivajs/core/support';
import type { MongoConfiguration } from './config.js';
import {
  mongoOptions,
  mongoCollection,
  mongoDocument,
  mongoPipeline,
  mongoInsertedId,
} from './common.js';
import { mongoError } from './errors.js';
import { MONGODB_LIMITS } from './limits.js';
import { MongoTransport, mongoNativeBudget } from './transport.js';
import type { MongoCallScope } from './transport.js';

/** Optional observation dependencies remain application-owned and never replace global SDK providers. */
export interface MongoObservationPorts {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
  readonly meter?: UsageMeter;
}
type Operation =
  | 'findOne'
  | 'findMany'
  | 'insertOne'
  | 'updateOne'
  | 'deleteOne'
  | 'aggregate'
  | 'withTransaction';

/** One actual MongoClient owns bounded portable attempts, cursors and native session transactions. */
export class MongoConnection implements DocumentProvider {
  private readonly stop = new AbortController();
  private readonly transport: MongoTransport;
  private readonly attempts = new Set<object>();
  private readonly nativeWork = new Set<Promise<unknown>>();
  private readonly cursors = new Set<AbstractCursor>();
  private readonly sessions = new Set<ClientSession>();
  private readonly cleanupFailures: unknown[] = [];
  private closed = false;
  private ready = false;
  private transactional = false;
  private starting: Promise<void> | undefined;
  private closing: Promise<void> | undefined;
  private nativeClosing: Promise<void> | undefined;
  private observerFailures = 0;
  private operations = 0;
  private cleanupFailureCount = 0;
  private nativeConnections = 0;

  constructor(
    private readonly name: string,
    private readonly configuration: MongoConfiguration,
    private readonly observation: MongoObservationPorts = {},
  ) {
    setMaxListeners(MONGODB_LIMITS.pending + MONGODB_LIMITS.transactions + 16, this.stop.signal);
    this.transport = new MongoTransport(
      {
        ...configuration,
        native: { ...configuration.native, appName: 'arkenivajs:' + randomUUID() },
      },
      () => {
        this.observerFailures++;
      },
    );
    this.transport.client.on('connectionCreated', () => {
      this.nativeConnections++;
    });
    this.transport.client.on('connectionClosed', () => {
      this.nativeConnections--;
    });
  }
  private open(): void {
    if (this.closed)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'MongoDB connection is closed' });
  }
  private diagnostic(work: () => void): void {
    try {
      work();
    } catch {
      this.observerFailures++;
    }
  }
  private meterSession(): MeterSession | undefined {
    let session: MeterSession | undefined;
    this.diagnostic(() => {
      session = this.observation.meter?.current();
    });
    return session;
  }
  private missing(session: MeterSession | undefined, reason: string): void {
    if (!session) return;
    this.diagnostic(() => {
      const meter = this.observation.meter as UsageMeter & {
        markMissing?: (session: MeterSession, reason: string) => void;
      };
      if (!meter?.markMissing) throw new Error('Meter quality controls are unavailable');
      meter.markMissing(session, reason);
    });
  }
  private remember(cause: unknown): void {
    this.cleanupFailureCount++;
    if (this.cleanupFailures.length < 16) this.cleanupFailures.push(cause);
    this.diagnostic(() =>
      this.observation.logger?.warn('MongoDB resource cleanup failed', {
        driver: 'mongodb',
        connection: this.name,
      }),
    );
  }

  /** Readiness proves native authentication and scoped read access without materializing document values. */
  start(input?: OperationOptions): Promise<void> {
    this.open();
    if (this.starting) return this.starting;
    const captured = mongoOptions(input, MONGODB_LIMITS.startupMs);
    this.starting = (async () => {
      try {
        await this.run(
          'findOne',
          false,
          captured,
          async (scope) => {
            await this.transport.client.connect();
            if (this.closed) {
              if (this.nativeClosing) {
                await this.nativeClosing.catch(() => undefined);
                await this.transport.client.close(true);
              }
              throw new KitError({
                code: 'EK_RESOURCE_CLOSED',
                message: 'MongoDB startup completed after closure',
              });
            }
            const db = this.transport.client.db(this.configuration.database);
            const hello: Document = await db.command(
              { hello: 1 },
              { timeoutMS: mongoNativeBudget(scope) },
            );
            this.transactional = typeof hello.setName === 'string' || hello.msg === 'isdbgrid';
            await this.probe(scope);
          },
          true,
        );
        this.open();
        this.ready = true;
      } catch (cause) {
        try {
          await this.close();
        } catch (cleanup) {
          throw new KitError({
            code: 'EK_DATABASE_CONNECT',
            message: 'MongoDB startup and cleanup failed',
            cause: new AggregateError([cause, cleanup]),
          });
        }
        throw cause;
      }
    })();
    return this.starting;
  }

  private async probe(scope: MongoCallScope): Promise<void> {
    const cursor = this.transport.client
      .db(this.configuration.database)
      .collection(this.configuration.prefix + '.arkenivajs_readiness')
      .find(
        {},
        {
          projection: { _id: 1 },
          limit: 1,
          batchSize: 1,
          timeoutMS: mongoNativeBudget(scope),
          signal: scope.signal,
        },
      );
    await this.collect(cursor, 1, scope);
  }

  /** Recheck actual authenticated scoped read access without charging a business metering operation. */
  async health(input?: OperationOptions): Promise<boolean> {
    this.open();
    if (!this.ready)
      throw new KitError({ code: 'EK_LIFECYCLE_STATE', message: 'MongoDB provider is not ready' });
    await this.run('findOne', false, input, (scope) => this.probe(scope), true);
    return true;
  }

  private run<T>(
    operation: Operation,
    write: boolean,
    input: OperationOptions | undefined,
    command: (scope: MongoCallScope) => Promise<T>,
    startup = false,
  ): Promise<T> {
    this.open();
    const captured = mongoOptions(input);
    if (!this.ready && !startup)
      throw new KitError({ code: 'EK_LIFECYCLE_STATE', message: 'MongoDB provider is not ready' });
    if (this.attempts.size >= MONGODB_LIMITS.pending || this.cursors.size >= MONGODB_LIMITS.pending)
      throw new KitError({
        code: 'EK_DATABASE_UNAVAILABLE',
        message: 'MongoDB portable capacity is exhausted',
        retryable: true,
      });
    const token = {},
      controller = new AbortController();
    const signal = AbortSignal.any([
      controller.signal,
      this.stop.signal,
      ...(captured.signal ? [captured.signal] : []),
    ]);
    const scope: MongoCallScope = {
      signal,
      timeoutMs: captured.timeoutMs,
      began: performance.now(),
      write,
      atomic: operation !== 'aggregate' && operation !== 'withTransaction',
      submitted: false,
      acknowledged: false,
      cleanupFailures: [],
    };
    const attributes = { 'db.system.name': 'mongodb', 'db.operation.name': operation };
    const session = startup ? undefined : this.meterSession();
    let began = false,
      settled = false,
      completed = false,
      answer: T,
      failure: KitError | undefined;
    this.attempts.add(token);
    const execute = async () => {
      if (signal.aborted)
        throw signal.reason instanceof KitError && signal.reason.code === 'EK_TIMEOUT'
          ? signal.reason
          : new KitError({
              code: 'EK_ABORTED',
              message: 'MongoDB operation aborted',
              cause: signal.reason,
            });
      began = true;
      if (!startup) {
        this.operations++;
        this.diagnostic(() => session?.recordOperation('db.query'));
        this.missing(session, 'driver_bytes_unavailable');
      }
      const started = performance.now();
      const raw = Promise.resolve().then(() => {
        mongoNativeBudget(scope);
        return this.transport.run(scope, () => command(scope));
      });
      this.nativeWork.add(raw);
      void raw.then(
        () => this.nativeWork.delete(raw),
        () => this.nativeWork.delete(raw),
      );
      try {
        answer = await raw;
        completed = true;
        return answer;
      } catch (cause) {
        failure = mongoError(cause, scope);
        this.diagnostic(() =>
          this.observation.logger?.warn('MongoDB command failed', {
            driver: 'mongodb',
            connection: this.name,
            operation,
            errorCode: failure!.code,
          }),
        );
        throw failure;
      } finally {
        settled = true;
        this.attempts.delete(token);
        if (!startup) {
          const elapsed = performance.now() - started;
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
      }
    };
    return (async () => {
      try {
        return await within(
          () =>
            startup
              ? execute()
              : instrumentOperation(
                  this.observation.telemetry,
                  'db.client.operation',
                  attributes,
                  execute,
                  () => {
                    this.observerFailures++;
                  },
                ),
          { timeoutMs: captured.timeoutMs, signal },
        );
      } catch (cause) {
        controller.abort(cause);
        if (completed) {
          this.observerFailures++;
          return answer!;
        }
        if (failure) throw failure;
        throw mongoError(cause, scope);
      } finally {
        // Non-abortable native writes retain admission until settlement, even after their caller has stopped waiting.
        if (!began || settled) this.attempts.delete(token);
      }
    })();
  }

  private collection(name: string) {
    return this.transport.client
      .db(this.configuration.database)
      .collection(mongoCollection(name, this.configuration.prefix, this.configuration.database));
  }
  private async collect<T extends object>(
    cursor: AbstractCursor,
    maximum: number,
    scope: MongoCallScope,
  ): Promise<readonly T[]> {
    this.cursors.add(cursor);
    const rows: T[] = [],
      failures: unknown[] = [];
    let bytes = 0;
    try {
      while (true) {
        const row: unknown = await cursor.next();
        if (scope.write) {
          scope.acknowledged = true;
          scope.outcome = 'acknowledged';
        }
        if (row === null) break;
        if (!row || typeof row !== 'object' || Array.isArray(row))
          throw new KitError({
            code: 'EK_DOCUMENT_OPERATION',
            message: 'MongoDB returned an invalid document',
          });
        const size = BSON.calculateObjectSize(row);
        bytes += size;
        if (
          size > MONGODB_LIMITS.documentBytes ||
          bytes > MONGODB_LIMITS.resultBytes ||
          rows.length >= maximum
        )
          throw new KitError({
            code: 'EK_DOCUMENT_OPERATION',
            message: 'MongoDB result exceeds its proved portable bound',
            details: { limitExceeded: true },
          });
        rows.push(row as T);
      }
    } catch (cause) {
      failures.push(cause);
    }
    scope.closingCursor = true;
    const closing = Promise.resolve().then(() => this.transport.run(scope, () => cursor.close()));
    void closing.then(
      () => {
        scope.closingCursor = false;
        this.cursors.delete(cursor);
      },
      () => {
        scope.closingCursor = false;
      },
    );
    try {
      await within(() => closing, { timeoutMs: MONGODB_LIMITS.cleanupMs });
      if (scope.cleanupFailures.length)
        throw new AggregateError(
          scope.cleanupFailures,
          'MongoDB cursor cleanup was not acknowledged',
        );
    } catch (cause) {
      failures.push(cause);
      this.remember(cause);
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1)
      throw new KitError({
        code: 'EK_DOCUMENT_OPERATION',
        message: 'MongoDB cursor work and cleanup failed',
        cause: new AggregateError(failures),
        details: { cleanupFailed: true },
      });
    return Object.freeze(rows);
  }

  async findOne<T extends object>(
    name: string,
    filter: Readonly<Record<string, unknown>>,
    input?: OperationOptions,
  ): Promise<T | null> {
    this.open();
    const collection = this.collection(name),
      captured = mongoDocument(filter);
    return this.run('findOne', false, input, async (scope) => {
      const cursor = collection.find(captured, {
        limit: 1,
        batchSize: 1,
        timeoutMS: mongoNativeBudget(scope),
        signal: scope.signal,
        promoteValues: false,
        promoteLongs: false,
        bsonRegExp: true,
      });
      return (await this.collect<T>(cursor, 1, scope))[0] ?? null;
    });
  }
  async findMany<T extends object>(
    name: string,
    filter: Readonly<Record<string, unknown>>,
    input?: OperationOptions & { limit?: number },
  ): Promise<readonly T[]> {
    this.open();
    mongoOptions(input);
    const limit = input?.limit ?? MONGODB_LIMITS.defaultRows;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MONGODB_LIMITS.maximumRows)
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'MongoDB find limit must be an integer from 1 through 1000',
      });
    const collection = this.collection(name),
      captured = mongoDocument(filter);
    return this.run('findMany', false, input, async (scope) =>
      this.collect<T>(
        collection.find(captured, {
          limit,
          batchSize: 1,
          timeoutMS: mongoNativeBudget(scope),
          signal: scope.signal,
          promoteValues: false,
          promoteLongs: false,
          bsonRegExp: true,
        }),
        limit,
        scope,
      ),
    );
  }
  async insertOne<T extends object>(
    name: string,
    document: T,
    input?: OperationOptions,
  ): Promise<string> {
    this.open();
    const collection = this.collection(name),
      captured = mongoDocument(document);
    return this.run('insertOne', true, input, async (scope) => {
      const result = await collection.insertOne(captured, { timeoutMS: mongoNativeBudget(scope) });
      if (result.acknowledged !== true)
        throw new KitError({
          code: 'EK_DOCUMENT_OPERATION',
          message: 'MongoDB insert was not acknowledged',
        });
      scope.acknowledged = true;
      scope.outcome = 'acknowledged';
      return mongoInsertedId(result.insertedId);
    });
  }
  async updateOne(
    name: string,
    filter: Readonly<Record<string, unknown>>,
    update: Readonly<Record<string, unknown>>,
    input?: OperationOptions,
  ): Promise<number> {
    this.open();
    const collection = this.collection(name),
      captured = mongoDocument(filter),
      changes = mongoDocument(update);
    return this.run('updateOne', true, input, async (scope) => {
      const result = await collection.updateOne(captured, changes, {
        timeoutMS: mongoNativeBudget(scope),
      });
      if (result.acknowledged !== true)
        throw new KitError({
          code: 'EK_DOCUMENT_OPERATION',
          message: 'MongoDB update was not acknowledged',
        });
      scope.acknowledged = true;
      scope.outcome = 'acknowledged';
      if (
        !Number.isSafeInteger(result.modifiedCount) ||
        result.modifiedCount < 0 ||
        result.modifiedCount > 1
      )
        throw new KitError({
          code: 'EK_DOCUMENT_OPERATION',
          message: 'MongoDB returned an invalid modification count',
        });
      return result.modifiedCount;
    });
  }
  async deleteOne(
    name: string,
    filter: Readonly<Record<string, unknown>>,
    input?: OperationOptions,
  ): Promise<number> {
    this.open();
    const collection = this.collection(name),
      captured = mongoDocument(filter);
    return this.run('deleteOne', true, input, async (scope) => {
      const result = await collection.deleteOne(captured, { timeoutMS: mongoNativeBudget(scope) });
      if (result.acknowledged !== true)
        throw new KitError({
          code: 'EK_DOCUMENT_OPERATION',
          message: 'MongoDB deletion was not acknowledged',
        });
      scope.acknowledged = true;
      scope.outcome = 'acknowledged';
      if (
        !Number.isSafeInteger(result.deletedCount) ||
        result.deletedCount < 0 ||
        result.deletedCount > 1
      )
        throw new KitError({
          code: 'EK_DOCUMENT_OPERATION',
          message: 'MongoDB returned an invalid deletion count',
        });
      return result.deletedCount;
    });
  }
  async aggregate<T extends object>(
    name: string,
    pipeline: readonly Record<string, unknown>[],
    input?: OperationOptions,
  ): Promise<readonly T[]> {
    this.open();
    const collection = this.collection(name),
      captured = mongoPipeline(pipeline);
    return this.run('aggregate', captured.writes, input, async (scope) =>
      this.collect<T>(
        collection.aggregate(captured.pipeline, {
          batchSize: 1,
          allowDiskUse: false,
          timeoutMS: mongoNativeBudget(scope),
          signal: scope.signal,
          promoteValues: false,
          promoteLongs: false,
          bsonRegExp: true,
        }),
        captured.maximum,
        scope,
      ),
    );
  }

  /** The callback receives the actual SDK session; it must pass that session explicitly to native operations. */
  async withTransaction<T>(
    handler: (session: unknown) => Promise<T>,
    input?: OperationOptions,
  ): Promise<T> {
    this.open();
    mongoOptions(input);
    if (typeof handler !== 'function')
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'MongoDB transaction requires an asynchronous callback',
      });
    if (!this.ready)
      throw new KitError({ code: 'EK_LIFECYCLE_STATE', message: 'MongoDB provider is not ready' });
    if (!this.transactional)
      throw new KitError({
        code: 'EK_UNSUPPORTED_CAPABILITY',
        message: 'MongoDB transactions require a replica set or sharded deployment',
      });
    if (this.sessions.size >= MONGODB_LIMITS.transactions)
      throw new KitError({
        code: 'EK_DATABASE_UNAVAILABLE',
        message: 'MongoDB transaction capacity is exhausted',
      });
    this.missing(this.meterSession(), 'not_instrumented');
    return this.run('withTransaction', true, input, async (scope) => {
      if (this.sessions.size >= MONGODB_LIMITS.transactions)
        throw new KitError({
          code: 'EK_DATABASE_UNAVAILABLE',
          message: 'MongoDB transaction capacity is exhausted',
        });
      const session = this.transport.client.startSession({
        defaultTimeoutMS: mongoNativeBudget(scope),
      });
      this.sessions.add(session);
      scope.session = session;
      let result: T | undefined,
        failed = false,
        primary: unknown;
      const cleanup: unknown[] = [];
      try {
        session.startTransaction({
          readConcern: { level: 'snapshot' },
          writeConcern: { w: 'majority' },
        });
        const work = handler(session);
        if (!work || typeof work.then !== 'function')
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'MongoDB transaction callback must return a promise',
          });
        // Arbitrary callback code cannot be forcibly stopped; retain ownership until it settles and never commit after cancellation.
        result = await work;
        mongoNativeBudget(scope);
        if (!session.inTransaction())
          throw new KitError({
            code: 'EK_DATABASE_TRANSACTION',
            message: 'The callback changed its owned transaction lifecycle',
            details: { outcome: scope.commitAcknowledged ? 'acknowledged' : 'unknown' },
          });
        await session.commitTransaction({ timeoutMS: mongoNativeBudget(scope) });
        scope.acknowledged = true;
        scope.outcome = 'acknowledged';
      } catch (cause) {
        failed = true;
        primary = cause;
        if (scope.commitAcknowledged) {
          scope.acknowledged = true;
          scope.outcome = 'acknowledged';
        }
      }
      if (!scope.commitSubmitted && !scope.acknowledged) {
        try {
          if (session.inTransaction())
            // Await native CSOT settlement before ending the same session; two competing timers can overlap aborts.
            await this.transport.run(scope, () =>
              session.abortTransaction({ timeoutMS: MONGODB_LIMITS.cleanupMs }),
            );
          if (scope.transactionUsed && !scope.abortAcknowledged)
            throw new Error('MongoDB transaction rollback was not acknowledged');
          scope.acknowledged = true;
          scope.outcome = 'rolled_back';
        } catch (cause) {
          cleanup.push(cause);
        }
      }
      try {
        await session.endSession({ timeoutMS: MONGODB_LIMITS.cleanupMs });
      } catch (cause) {
        cleanup.push(cause);
      }
      if (session.hasEnded) this.sessions.delete(session);
      else cleanup.push(new Error('MongoDB transaction session did not end'));
      cleanup.push(...scope.cleanupFailures);
      if (cleanup.length) {
        const failure = new KitError({
          code: 'EK_DATABASE_TRANSACTION',
          message: 'MongoDB transaction cleanup failed',
          cause: new AggregateError([...(failed ? [primary] : []), ...cleanup]),
          details: { cleanupFailed: true, ...(scope.outcome ? { outcome: scope.outcome } : {}) },
        });
        this.remember(failure);
        throw failure;
      }
      if (failed) throw primary;
      return result as T;
    });
  }

  native(): MongoClient {
    this.open();
    if (!this.ready)
      throw new KitError({ code: 'EK_LIFECYCLE_STATE', message: 'MongoDB provider is not ready' });
    this.missing(this.meterSession(), 'not_instrumented');
    return this.transport.client;
  }
  stats(): Readonly<Record<string, number | null>> {
    return Object.freeze({
      ready: this.ready && !this.closed ? 1 : 0,
      pending: this.attempts.size,
      nativePending: this.nativeWork.size,
      cursors: this.cursors.size,
      sessions: this.sessions.size,
      nativeConnections: this.nativeConnections >= 0 ? this.nativeConnections : null,
      operations: this.operations,
      observerFailures: this.observerFailures,
      cleanupFailures: this.cleanupFailureCount,
    });
  }

  /** Stop admission and owned work; observe late native startup, writes, cursors and sessions within a bounded drain. */
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    this.ready = false;
    this.stop.abort(
      new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'MongoDB connection is closing' }),
    );
    this.closing = (async () => {
      const failures: unknown[] = [];
      const closeClient = () => {
        this.nativeClosing ??= Promise.resolve().then(() => this.transport.client.close(true));
        void this.nativeClosing.catch(() => undefined);
        return this.nativeClosing;
      };
      try {
        await within(
          async () => {
            // Cooperative calls release their own cursors and sessions before the shared pool closes.
            await Promise.allSettled([...this.nativeWork]);
            await closeClient();
          },
          { timeoutMs: MONGODB_LIMITS.shutdownMs },
        );
      } catch (cause) {
        failures.push(cause);
        // An uncooperative callback cannot prevent a native close attempt; late completion remains observed.
        closeClient();
      }
      failures.push(...this.cleanupFailures);
      if (this.cursors.size || this.sessions.size || this.nativeWork.size)
        failures.push(new Error('MongoDB owned work did not finish during shutdown'));
      if (failures.length)
        throw new KitError({
          code: 'EK_DATABASE_UNAVAILABLE',
          message: 'MongoDB connection cleanup failed',
          cause: new AggregateError(failures),
          details: { cleanupFailed: true, cleanupFailureCount: this.cleanupFailureCount },
        });
    })();
    return this.closing;
  }
}
