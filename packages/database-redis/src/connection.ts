import { performance } from 'node:perf_hooks';
import { setMaxListeners } from 'node:events';
import { TextDecoder } from 'node:util';
import redis from 'redis';
import type { RedisClientType } from 'redis';
import { KitError } from '@arkenivajs/core';
import type {
  RedisProvider,
  OperationOptions,
  Logger,
  Telemetry,
  UsageMeter,
  MeterSession,
} from '@arkenivajs/core';
import { instrumentOperation, within } from '@arkenivajs/core/support';
import type { RedisConfiguration } from './config.js';
import { redisError, redisVendor } from './errors.js';
import { SAFE_INCREMENT, BOUNDED_GET } from './increment.js';
import { REDIS_LIMITS } from './limits.js';

/** Optional ports are resolved only through explicit application plugin dependencies. */
export interface RedisObservationPorts {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
  readonly meter?: UsageMeter;
}
type Operation = 'get' | 'set' | 'del' | 'increment' | 'publish' | 'ping';

function options(input: OperationOptions = {}): { timeoutMs: number; signal?: AbortSignal } {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    (input.signal !== undefined && !(input.signal instanceof AbortSignal))
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Redis operation options require an object and an AbortSignal',
    });
  const timeoutMs = input.timeoutMs ?? REDIS_LIMITS.timeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Redis timeout must be a positive integer',
    });
  if (input.signal?.aborted)
    throw new KitError({
      code: 'EK_ABORTED',
      message: 'Redis operation aborted',
      cause: input.signal.reason,
    });
  return { timeoutMs, ...(input.signal === undefined ? {} : { signal: input.signal }) };
}
function text(value: string, maximum: number, identifier = false): void {
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value) > maximum ||
    Buffer.from(value).toString('utf8') !== value ||
    (identifier && (value.length === 0 || /[\0\r\n]/.test(value)))
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: identifier
        ? 'Redis key or channel is invalid or exceeds its byte limit'
        : 'Redis text value is invalid or exceeds its byte limit',
    });
}
function safeCount(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0)
    throw new KitError({
      code: 'EK_BACKEND_UNAVAILABLE',
      message: 'Redis returned an invalid count',
    });
  return value;
}

/** One native multiplexed connection owns bounded command attempts and reconnect lifecycle. */
export class RedisConnection implements RedisProvider {
  private readonly client: RedisClientType;
  private readonly stop = new AbortController();
  private readonly pending = new Set<Promise<unknown>>();
  private closed = false;
  private closing: Promise<void> | undefined;
  private starting: Promise<void> | undefined;
  private operations = 0;
  private reconnects = 0;
  private observerFailures = 0;

  constructor(
    private readonly name: string,
    private readonly configuration: RedisConfiguration,
    private readonly observation: RedisObservationPorts,
  ) {
    setMaxListeners(REDIS_LIMITS.pending + 16, this.stop.signal);
    this.client = redis.createClient(configuration.native);
    this.client.on('error', (cause: unknown) =>
      this.diagnostic(() =>
        this.observation.logger?.warn('Redis transport failed', {
          driver: 'redis',
          connection: name,
          ...(redisVendor(cause) === undefined ? {} : { vendorCode: redisVendor(cause)! }),
        }),
      ),
    );
    this.client.on('reconnecting', () => {
      this.reconnects++;
    });
  }
  private open(): void {
    if (this.closed)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Redis connection is closed' });
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
      const meter = this.observation.meter as UsageMeter & {
        markMissing?: (session: MeterSession, reason: string) => void;
      };
      if (!meter?.markMissing) throw new Error('Meter quality controls are unavailable');
      meter.markMissing(session, reason);
    });
  }
  private key(value: string): string {
    text(value, REDIS_LIMITS.keyBytes, true);
    return this.configuration.prefix + value;
  }

  /** Connection and authenticated PING are startup work, without application command attribution. */
  start(input?: OperationOptions): Promise<void> {
    this.open();
    if (this.starting) return this.starting;
    const captured = options(input);
    this.starting = (async () => {
      const began = performance.now(),
        controller = new AbortController();
      const signals = [captured.signal, this.stop.signal].filter(
        (signal): signal is AbortSignal => signal !== undefined,
      );
      const remove: (() => void)[] = [];
      for (const signal of signals) {
        const abort = () => controller.abort(signal.reason);
        if (signal.aborted) abort();
        else {
          signal.addEventListener('abort', abort, { once: true });
          remove.push(() => signal.removeEventListener('abort', abort));
        }
      }
      try {
        const requested = this.client.connect().then(async () => {
          if (this.closed || controller.signal.aborted) {
            if (this.client.isOpen) this.client.destroy();
            throw new KitError({
              code: 'EK_ABORTED',
              message: 'Redis startup aborted',
              cause: controller.signal.reason,
            });
          }
          return this.client.withAbortSignal(controller.signal).ping();
        });
        const pong = await within(() => requested, {
          timeoutMs: captured.timeoutMs,
          signal: controller.signal,
        });
        if (pong !== 'PONG')
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'Redis startup health check failed',
          });
        this.diagnostic(() =>
          this.observation.logger?.debug('Redis connection is ready', {
            driver: 'redis',
            connection: this.name,
            elapsedMs: performance.now() - began,
          }),
        );
      } catch (cause) {
        controller.abort(cause);
        try {
          if (this.client.isOpen) this.client.destroy();
        } catch (cleanup) {
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'Redis startup and cleanup failed',
            cause: new AggregateError([cause, cleanup]),
          });
        }
        throw redisError(cause);
      } finally {
        for (const detach of remove) detach();
      }
    })();
    return this.starting;
  }

  /** Readiness uses the actual scoped native PING and the same owned cancellation/admission as other readonly calls. */
  async health(input?: OperationOptions): Promise<boolean> {
    return (await this.run('ping', false, input, (client) => client.ping())) === 'PONG';
  }

  private run<T>(
    operation: Operation,
    write: boolean,
    input: OperationOptions | undefined,
    command: (client: RedisClientType) => Promise<T>,
  ): Promise<T> {
    this.open();
    const captured = options(input);
    if (!this.client.isReady)
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'Redis transport is not ready',
        retryable: true,
      });
    if (this.pending.size >= REDIS_LIMITS.pending)
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'Redis pending command capacity is exhausted',
        retryable: true,
      });
    const controller = new AbortController(),
      remove: (() => void)[] = [];
    for (const signal of [captured.signal, this.stop.signal]) {
      if (!signal) continue;
      const abort = () => controller.abort(signal.reason);
      if (signal.aborted) abort();
      else {
        signal.addEventListener('abort', abort, { once: true });
        remove.push(() => signal.removeEventListener('abort', abort));
      }
    }
    const attributes = { 'db.system.name': 'redis', 'db.operation.name': operation };
    const session = this.current();
    let attempted = false,
      completed = false,
      answer: T,
      failure: KitError | undefined;
    const work = (async () => {
      try {
        return await within(
          () =>
            instrumentOperation(
              this.observation.telemetry,
              'db.client.operation',
              attributes,
              async () => {
                if (controller.signal.aborted)
                  throw new KitError({
                    code: 'EK_ABORTED',
                    message: 'Redis operation aborted',
                    cause: controller.signal.reason,
                  });
                attempted = true;
                this.operations++;
                this.diagnostic(() => session?.recordOperation('db.query'));
                this.missing(session, 'driver_bytes_unavailable');
                const began = performance.now();
                try {
                  answer = await command(this.client.withAbortSignal(controller.signal));
                  completed = true;
                  return answer;
                } catch (cause) {
                  failure = redisError(cause, write, attempted);
                  this.diagnostic(() =>
                    this.observation.logger?.warn('Redis command failed', {
                      driver: 'redis',
                      connection: this.name,
                      operation,
                      errorCode: failure!.code,
                    }),
                  );
                  throw failure;
                } finally {
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
              },
              () => {
                this.observerFailures++;
              },
            ),
          { timeoutMs: captured.timeoutMs, signal: controller.signal },
        );
      } catch (cause) {
        controller.abort(cause);
        // A late diagnostic wrapper cannot replace an already established native outcome.
        if (completed) {
          this.observerFailures++;
          return answer!;
        }
        if (failure) throw failure;
        throw redisError(cause, write, attempted);
      } finally {
        for (const detach of remove) detach();
      }
    })();
    this.pending.add(work);
    void work.then(
      () => this.pending.delete(work),
      () => this.pending.delete(work),
    );
    return work;
  }

  async get(key: string, input?: OperationOptions): Promise<string | null> {
    this.open();
    const name = this.key(key);
    return this.run('get', false, input, async (client) => {
      const value = await client
        .withTypeMapping({ [redis.RESP_TYPES.BLOB_STRING]: Buffer })
        .evalRo(BOUNDED_GET, { keys: [name], arguments: [String(REDIS_LIMITS.valueBytes)] });
      if (value === null) return null;
      if (!Buffer.isBuffer(value))
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'Redis returned an invalid text value',
        });
      try {
        return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(value);
      } catch (cause) {
        throw new KitError({
          code: 'EK_KV_CONFLICT',
          message: 'Redis value is not valid UTF-8',
          cause,
        });
      }
    });
  }
  async set(
    key: string,
    value: string,
    input: OperationOptions & { ttlMs?: number; onlyIfAbsent?: boolean } = {},
  ): Promise<boolean> {
    this.open();
    const name = this.key(key);
    text(value, REDIS_LIMITS.valueBytes);
    options(input);
    if (
      (input.ttlMs !== undefined && (!Number.isSafeInteger(input.ttlMs) || input.ttlMs <= 0)) ||
      (input.onlyIfAbsent !== undefined && typeof input.onlyIfAbsent !== 'boolean')
    )
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Redis TTL must be positive integer milliseconds and onlyIfAbsent must be boolean',
      });
    const ttlMs = input.ttlMs,
      onlyIfAbsent = input.onlyIfAbsent;
    return this.run('set', true, input, async (client) => {
      const reply = await client.set(name, value, {
        ...(ttlMs === undefined ? {} : { expiration: { type: 'PX', value: ttlMs } }),
        ...(onlyIfAbsent ? { condition: 'NX' } : {}),
      });
      if (reply === 'OK') return true;
      if (reply === null && onlyIfAbsent) return false;
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'Redis returned an invalid SET acknowledgment',
      });
    });
  }
  async del(keys: readonly string[], input?: OperationOptions): Promise<number> {
    this.open();
    options(input);
    if (!Array.isArray(keys) || keys.length > REDIS_LIMITS.deleteKeys)
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Redis delete requires a bounded array of keys',
      });
    const names = keys.map((key: string) => this.key(key));
    if (!names.length) return 0;
    return this.run('del', true, input, async (client) => safeCount(await client.del(names)));
  }
  async increment(key: string, amount = 1, input?: OperationOptions): Promise<number> {
    this.open();
    const name = this.key(key);
    if (!Number.isSafeInteger(amount))
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Redis increment requires a safe integer amount',
      });
    return this.run('increment', true, input, async (client) => {
      const value = await client
        .withTypeMapping({ [redis.RESP_TYPES.NUMBER]: String })
        .eval(SAFE_INCREMENT, {
          keys: [name],
          arguments: [String(amount)],
        });
      if (
        typeof value !== 'string' ||
        value.length > 17 ||
        !/^(?:0|-?[1-9]\d*)(?![\s\S])/.test(value)
      )
        throw new KitError({
          code: 'EK_KV_CONFLICT',
          message: 'Redis returned an unsafe increment result',
        });
      const exact = BigInt(value);
      if (exact > BigInt(Number.MAX_SAFE_INTEGER) || exact < BigInt(Number.MIN_SAFE_INTEGER))
        throw new KitError({
          code: 'EK_KV_CONFLICT',
          message: 'Redis returned an unsafe increment result',
        });
      return Number(exact);
    });
  }
  async publish(channel: string, message: string, input?: OperationOptions): Promise<number> {
    this.open();
    const name = this.key(channel);
    text(message, REDIS_LIMITS.valueBytes);
    return this.run('publish', true, input, async (client) =>
      safeCount(await client.publish(name, message)),
    );
  }
  native(): RedisClientType {
    this.open();
    this.missing(this.current(), 'not_instrumented');
    return this.client;
  }
  stats(): Readonly<Record<string, number>> {
    return Object.freeze({
      ready: this.client.isReady ? 1 : 0,
      transportOpen: this.client.isOpen ? 1 : 0,
      pending: this.pending.size,
      operations: this.operations,
      reconnects: this.reconnects,
      observerFailures: this.observerFailures,
    });
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    this.stop.abort();
    this.closing = (async () => {
      const failures: unknown[] = [];
      try {
        if (this.client.isOpen) this.client.destroy();
      } catch (cause) {
        failures.push(cause);
      }
      try {
        await within(
          () => Promise.allSettled([...this.pending, ...(this.starting ? [this.starting] : [])]),
          { timeoutMs: 5000 },
        );
      } catch (cause) {
        failures.push(cause);
      }
      if (failures.length)
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'Redis shutdown cleanup failed',
          cause: new AggregateError(failures),
        });
    })();
    return this.closing;
  }
}
