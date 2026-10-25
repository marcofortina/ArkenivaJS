import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { setMaxListeners } from 'node:events';
import { performance } from 'node:perf_hooks';
import nats from 'nats';
import type { NatsConnection, Subscription as NativeSubscription } from 'nats';
import { KitError } from '@arkenivajs/core';
import type {
  MessageEnvelope,
  MeterSession,
  OperationOptions,
  Subscription,
  UsageMeter,
} from '@arkenivajs/core';
import { instrumentOperation, within } from '@arkenivajs/core/support';
import type { NatsConfiguration } from './config.js';
import type {
  ManagedMessageBus,
  MessageBusStats,
  MessageFailure,
  NatsBusOptions,
} from './types.js';
import {
  encodeMessage,
  decodeMessage,
  messageCorrelation,
  messageTopic,
  MAX_MESSAGE_BYTES,
} from './wire.js';

const MAX_PENDING = 64,
  MAX_BYTES = 8_388_608,
  MAX_SUBSCRIPTIONS = 32,
  MAX_QUEUED = 128;
type ScopedMeter = UsageMeter & {
  withoutScope<T>(work: () => T): T;
  markMissing(session: MeterSession, reason: 'driver_bytes_unavailable'): void;
};
type OwnedSubscription = {
  readonly topic: string;
  readonly handler: (message: MessageEnvelope<unknown>) => Promise<void>;
  readonly queue: Uint8Array[];
  native?: NativeSubscription;
  phase: 'opening' | 'open' | 'closing' | 'closed';
  worker?: Promise<void>;
  closing?: Promise<void>;
  removeAbort?: () => void;
  failure?: KitError;
};
const error = (message: string, cause?: unknown) =>
  new KitError({
    code: 'EK_BACKEND_UNAVAILABLE',
    message,
    ...(cause === undefined ? {} : { cause }),
  });
export function messageOptions(
  input: OperationOptions | undefined,
  correlation = false,
  allowAborted = false,
): OperationOptions & { timeoutMs: number } {
  if (
    input !== undefined &&
    (!input ||
      typeof input !== 'object' ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(input)) ||
      Reflect.ownKeys(input).some(
        (key) =>
          typeof key !== 'string' ||
          !['timeoutMs', 'signal', ...(correlation ? ['correlationId'] : [])].includes(key) ||
          !('value' in Object.getOwnPropertyDescriptor(input, key)!),
      ))
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Messaging options require supported data properties',
    });
  const timeoutMs = input?.timeoutMs ?? 5000,
    signal = input?.signal;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    (signal !== undefined && !(signal instanceof AbortSignal))
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Messaging requires a positive integer timeout and valid signal',
    });
  if (signal?.aborted && !allowAborted)
    throw new KitError({
      code: 'EK_ABORTED',
      message: 'Messaging operation aborted',
      cause: signal.reason,
    });
  return { timeoutMs, ...(signal === undefined ? {} : { signal }) };
}

/** One native connection owns bounded publications, subscriptions and observed callback settlement. */
export class NatsBus implements ManagedMessageBus {
  private client?: NatsConnection;
  private readonly stop = new AbortController();
  private readonly pending = new Set<Promise<unknown>>();
  private readonly errorTasks = new Set<Promise<unknown>>();
  private readonly subscriptions = new Set<OwnedSubscription>();
  private readonly handlerContext = new AsyncLocalStorage<OwnedSubscription | undefined>();
  private readonly cleanupErrors: unknown[] = [];
  private starting?: Promise<void>;
  private closing?: Promise<void>;
  private statusTask?: Promise<void>;
  private nativeClosing?: Promise<void>;
  private fatal?: KitError;
  private state: 'created' | 'ready' | 'closing' | 'closed' = 'created';
  private online = false;
  private bytes = 0;
  private queued = 0;
  private publications = 0;
  private handlers = 0;
  private readonly counts = {
    published: 0,
    received: 0,
    failed: 0,
    dropped: 0,
    observerFailures: 0,
  };

  constructor(
    private readonly configuration: NatsConfiguration,
    private readonly policy: Readonly<NatsBusOptions>,
    private readonly connect: typeof nats.connect = nats.connect,
  ) {
    setMaxListeners(256, this.stop.signal);
    if (
      policy.meter &&
      (typeof (policy.meter as ScopedMeter).withoutScope !== 'function' ||
        typeof (policy.meter as ScopedMeter).markMissing !== 'function')
    )
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Messaging requires an owned meter with explicit background scope controls',
      });
  }
  private diagnostic(work: () => void): void {
    try {
      work();
    } catch {
      this.counts.observerFailures++;
    }
  }
  private detached<T>(work: () => T): T {
    if (!this.policy.meter) return work();
    let invoked = false;
    const result = (this.policy.meter as ScopedMeter).withoutScope(() => {
      if (invoked || this.policy.meter!.current() !== undefined)
        throw new KitError({
          code: 'EK_METER_SESSION',
          message: 'Background metering scope isolation failed',
        });
      invoked = true;
      return work();
    });
    if (!invoked)
      throw new KitError({
        code: 'EK_METER_SESSION',
        message: 'Background metering scope was not entered synchronously',
      });
    return result;
  }
  private closeNative(): Promise<void> {
    if (!this.client) return Promise.resolve();
    this.nativeClosing ??= Promise.resolve().then(async () => {
      if (!this.client!.isClosed()) await this.client!.close();
    });
    return this.nativeClosing;
  }
  private cleanupFailure(cause: unknown): void {
    if (this.cleanupErrors.length < 32) this.cleanupErrors.push(cause);
    this.counts.failed++;
  }
  private available(): NatsConnection {
    if (this.state === 'closing' || this.state === 'closed')
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Messaging bus is closed' });
    if (this.state !== 'ready')
      throw new KitError({ code: 'EK_LIFECYCLE_STATE', message: 'Messaging bus is not started' });
    if (
      this.fatal ||
      !this.online ||
      !this.client?.info ||
      this.client.isClosed() ||
      this.client.isDraining()
    )
      throw error('Messaging transport is not available');
    return this.client;
  }
  private fail(cause: unknown, report: boolean | MessageFailure = true): void {
    if (this.fatal || this.state === 'closing' || this.state === 'closed') return;
    this.fatal = cause instanceof KitError ? cause : error('Messaging transport failed', cause);
    this.counts.failed++;
    this.online = false;
    if (report) {
      try {
        void this.detached(() =>
          this.report(
            typeof report === 'object' ? report : { kind: 'connection', error: this.fatal! },
          ),
        ).catch((failure: unknown) => this.cleanupFailure(failure));
      } catch (failure) {
        this.cleanupFailure(failure);
      }
    }
    this.handlerContext.run(undefined, () =>
      queueMicrotask(() => {
        void this.close().catch(() => {
          this.diagnostic(() =>
            this.policy.logger?.error('Messaging cleanup failed', { failed: this.counts.failed }),
          );
        });
      }),
    );
  }
  private async report(failure: MessageFailure): Promise<void> {
    const controller = new AbortController();
    const raw = Promise.resolve().then(() => {
      const result = this.policy.onError(Object.freeze(failure), {
        timeoutMs: 1000,
        signal: controller.signal,
      });
      if (!result || typeof result.then !== 'function')
        throw error('Messaging error strategy must return a promise');
      return result;
    });
    this.errorTasks.add(raw);
    try {
      await within(() => raw, { timeoutMs: 1000 });
    } catch (cause) {
      controller.abort(cause);
      const fault = error('Messaging error strategy failed', cause);
      this.cleanupFailure(fault);
      this.fail(fault, false);
    } finally {
      controller.abort();
      await Promise.allSettled([raw]);
      this.errorTasks.delete(raw);
    }
  }

  start(input?: OperationOptions): Promise<void> {
    if (this.state === 'closing' || this.state === 'closed')
      return Promise.reject(
        new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Messaging bus cannot restart' }),
      );
    if (this.starting) return this.starting;
    const operation = messageOptions(input);
    if (this.state !== 'created')
      return Promise.reject(
        new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Messaging bus cannot restart' }),
      );
    const raw = this.connect({ ...this.configuration.native }).then(async (client) => {
      this.client = client;
      if (this.state === 'closing' || this.state === 'closed' || operation.signal?.aborted) {
        await this.closeNative();
        throw new KitError({ code: 'EK_ABORTED', message: 'Messaging startup cancelled' });
      }
      this.online = true;
      this.state = 'ready';
      this.statusTask = this.detached(async () => {
        for await (const status of client.status()) {
          if (status.type === nats.Events.Disconnect) this.online = false;
          else if (status.type === nats.Events.Reconnect && !this.fatal && this.state === 'ready')
            this.online = true;
          else if (status.type === nats.Events.Error)
            this.fail(error('Native messaging status reported an error', status));
        }
      });
      void this.statusTask.catch((cause: unknown) => this.fail(cause));
      void client.closed().then((cause) => {
        this.online = false;
        if (this.state === 'ready')
          this.fail(cause ?? error('Messaging connection closed unexpectedly'));
      });
      await client.flush();
    });
    this.pending.add(raw);
    void raw.then(
      () => this.pending.delete(raw),
      () => this.pending.delete(raw),
    );
    this.starting = within(() => raw, operation).catch(async (cause: unknown) => {
      try {
        await this.close();
      } catch (cleanup) {
        throw error('Messaging startup and cleanup failed', new AggregateError([cause, cleanup]));
      }
      throw cause instanceof KitError ? cause : error('Messaging startup failed', cause);
    });
    return this.starting;
  }

  private async run<T>(
    name: 'publish' | 'subscribe' | 'health',
    input: OperationOptions & { timeoutMs: number },
    bytes: number,
    mutation: boolean,
    work: (client: NatsConnection, submitted: () => void) => Promise<T>,
  ): Promise<T> {
    this.available();
    if (this.pending.size >= MAX_PENDING || this.bytes + bytes > MAX_BYTES)
      throw error('Messaging operation capacity is exhausted');
    const controller = new AbortController(),
      signal = AbortSignal.any([
        controller.signal,
        this.stop.signal,
        ...(input.signal ? [input.signal] : []),
      ]);
    const admitted = performance.now();
    let submitted = false,
      completed = false,
      failed = false,
      answer!: T,
      failure: unknown;
    this.bytes += bytes;
    if (mutation) this.publications++;
    const raw = Promise.resolve().then(() =>
      instrumentOperation(
        this.policy.telemetry,
        'messaging.' + name,
        {},
        async () => {
          if (signal.aborted)
            throw new KitError({
              code: 'EK_ABORTED',
              message: 'Messaging operation aborted',
              cause: signal.reason,
            });
          if (performance.now() - admitted >= input.timeoutMs)
            throw new KitError({
              code: 'EK_TIMEOUT',
              message: 'Messaging operation timed out before submission',
            });
          const client = this.available(),
            began = performance.now();
          try {
            answer = await work(client, () => {
              submitted = true;
            });
            completed = true;
            return answer;
          } catch (cause) {
            failed = true;
            completed = true;
            failure =
              cause instanceof KitError ? cause : error('Native messaging operation failed', cause);
            throw failure;
          } finally {
            this.diagnostic(() =>
              this.policy.telemetry?.recordHistogram(
                'messaging.' + name + '.duration',
                (performance.now() - began) / 1000,
              ),
            );
          }
        },
        () => {
          this.counts.observerFailures++;
        },
      ),
    );
    this.pending.add(raw);
    const release = () => {
      this.pending.delete(raw);
      this.bytes -= bytes;
      if (mutation) this.publications--;
    };
    void raw.then(release, release);
    try {
      return await within(() => raw, { ...input, signal });
    } catch (cause) {
      controller.abort(cause);
      if (completed && !failed) return answer;
      this.counts.failed++;
      const original = completed ? failure : cause;
      const code = original instanceof KitError ? original.code : 'EK_BACKEND_UNAVAILABLE';
      throw new KitError({
        code,
        message: 'Messaging operation did not complete',
        cause: original,
        details: mutation && submitted ? { outcome: 'unknown' } : {},
      });
    } finally {
      controller.abort();
    }
  }

  async publish<T>(
    topic: string,
    payload: T,
    input?: OperationOptions & { correlationId?: string },
  ): Promise<{ messageId: string; acknowledged: boolean }> {
    const operation = messageOptions(input, true);
    messageTopic(topic);
    const correlationId = messageCorrelation(input?.correlationId),
      messageId = randomUUID();
    this.available();
    if (this.pending.size >= MAX_PENDING) throw error('Messaging operation capacity is exhausted');
    const bytes = encodeMessage({
      schemaVersion: 1,
      messageId,
      topic,
      payload,
      ...(correlationId === undefined ? {} : { correlationId }),
    });
    let session: MeterSession | undefined;
    this.diagnostic(() => {
      session = this.policy.meter?.current();
    });
    return this.run('publish', operation, bytes.byteLength, true, async (client, submitted) => {
      if (client.info && bytes.byteLength > client.info.max_payload)
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Message exceeds the broker payload limit',
        });
      const began = performance.now();
      submitted();
      client.publish(this.configuration.prefix + topic, bytes);
      this.diagnostic(() => {
        if (session) {
          session.recordOperation('messaging.publish');
          session.recordUsage('messaging.payload.bytes', {
            unit: 'bytes',
            source: 'observed',
            value: bytes.byteLength,
          });
          (this.policy.meter as ScopedMeter).markMissing(session, 'driver_bytes_unavailable');
        }
      });
      try {
        await client.flush();
        this.counts.published++;
        return Object.freeze({ messageId, acknowledged: false });
      } finally {
        this.diagnostic(() =>
          session?.recordUsage('messaging.client.elapsed', {
            unit: 'milliseconds',
            source: 'observed',
            value: performance.now() - began,
          }),
        );
      }
    });
  }

  private enqueue(owner: OwnedSubscription, bytes: Uint8Array): void {
    this.counts.received++;
    if (owner.phase === 'closed' || owner.phase === 'closing') {
      this.counts.dropped++;
      return;
    }
    if (
      !(bytes instanceof Uint8Array) ||
      bytes.byteLength > MAX_MESSAGE_BYTES ||
      this.bytes + bytes.byteLength > MAX_BYTES ||
      this.queued >= MAX_QUEUED
    ) {
      this.counts.dropped++;
      owner.failure = error('Messaging receive capacity is exhausted');
      this.fail(owner.failure, { kind: 'overflow', topic: owner.topic, error: owner.failure });
      return;
    }
    const captured = Uint8Array.from(bytes);
    this.bytes += captured.byteLength;
    this.queued++;
    owner.queue.push(captured);
    if (owner.phase === 'open') this.pump(owner);
  }
  private pump(owner: OwnedSubscription): void {
    if (owner.worker || owner.phase === 'closed' || owner.phase === 'opening') return;
    const worker = this.detached(() =>
      this.handlerContext.run(owner, async () => {
        while (owner.queue.length && owner.phase !== 'closed' && !this.stop.signal.aborted) {
          const bytes = owner.queue.shift()!;
          this.queued--;
          this.handlers++;
          let raw: Promise<unknown> | undefined;
          const began = performance.now();
          try {
            let message: MessageEnvelope<unknown>;
            try {
              message = decodeMessage(bytes, owner.topic);
            } catch (cause) {
              this.counts.failed++;
              await this.report({
                kind: 'wire',
                topic: owner.topic,
                error: cause instanceof KitError ? cause : error('Message decoding failed', cause),
              });
              continue;
            }
            let completed = false,
              failed = false,
              handlerFailure: unknown;
            raw = instrumentOperation(
              this.policy.telemetry,
              'messaging.process',
              {},
              async () => {
                if (this.stop.signal.aborted || performance.now() - began >= 5000)
                  throw new KitError({
                    code: this.stop.signal.aborted ? 'EK_ABORTED' : 'EK_TIMEOUT',
                    message: 'Message processing budget expired before handler invocation',
                  });
                try {
                  const result = owner.handler(message);
                  if (!result || typeof result.then !== 'function')
                    throw error('Message handler must return a promise');
                  await result;
                } catch (cause) {
                  failed = true;
                  handlerFailure = cause;
                  throw cause;
                } finally {
                  completed = true;
                }
              },
              () => {
                this.counts.observerFailures++;
              },
            );
            try {
              await within(() => raw!, { timeoutMs: 5000, signal: this.stop.signal });
            } catch (cause) {
              // Completed application work keeps its outcome even if diagnostics settle later.
              if (completed && !failed) continue;
              this.counts.failed++;
              const original = completed ? handlerFailure : cause;
              const fault =
                original instanceof KitError ? original : error('Message handler failed', original);
              await this.report({ kind: 'handler', topic: owner.topic, message, error: fault });
              if (fault.code === 'EK_TIMEOUT' || fault.code === 'EK_ABORTED')
                this.fail(fault, false);
            }
          } finally {
            if (raw) await Promise.allSettled([raw]);
            this.handlers--;
            this.bytes -= bytes.byteLength;
            this.diagnostic(() =>
              this.policy.telemetry?.recordHistogram(
                'messaging.process.duration',
                (performance.now() - began) / 1000,
              ),
            );
          }
        }
      }),
    );
    owner.worker = worker;
    void worker.then(
      () => {
        delete owner.worker;
      },
      (cause: unknown) => {
        delete owner.worker;
        this.fail(cause);
      },
    );
  }

  async subscribe<T>(
    topic: string,
    handler: (message: MessageEnvelope<T>) => Promise<void>,
    input?: OperationOptions,
  ): Promise<Subscription> {
    const operation = messageOptions(input);
    messageTopic(topic);
    if (typeof handler !== 'function')
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Message subscription requires a handler',
      });
    this.available();
    if (this.subscriptions.size >= MAX_SUBSCRIPTIONS)
      throw error('Messaging subscription capacity is exhausted');
    const owner: OwnedSubscription = {
      topic,
      handler: handler as OwnedSubscription['handler'],
      queue: [],
      phase: 'opening',
    };
    this.subscriptions.add(owner);
    try {
      return await this.run('subscribe', operation, 0, false, async (client) => {
        owner.native = client.subscribe(this.configuration.prefix + topic, {
          callback: (cause, message) => {
            try {
              this.detached(() => {
                if (cause) {
                  owner.failure = error('Native message subscription failed', cause);
                  this.fail(owner.failure, {
                    kind: 'subscription',
                    topic: owner.topic,
                    error: owner.failure,
                  });
                } else this.enqueue(owner, message.data);
              });
            } catch (failure) {
              this.cleanupFailure(failure);
              this.fail(failure, false);
            }
          },
        });
        await client.flush();
        if (owner.failure) throw owner.failure;
        if (owner.phase !== 'opening')
          throw new KitError({
            code: 'EK_RESOURCE_CLOSED',
            message: 'Message subscription closed during setup',
          });
        owner.phase = 'open';
        const abort = () =>
          this.handlerContext.run(undefined, () => {
            void this.closeSubscription(owner).catch((cause: unknown) =>
              this.cleanupFailure(cause),
            );
          });
        if (operation.signal) {
          const lifetime = AbortSignal.any([operation.signal]);
          lifetime.addEventListener('abort', abort, { once: true });
          owner.removeAbort = () => lifetime.removeEventListener('abort', abort);
          if (lifetime.aborted) abort();
        }
        this.pump(owner);
        return Object.freeze({ close: () => this.closeSubscription(owner) });
      });
    } catch (cause) {
      try {
        await this.closeSubscription(owner);
      } catch (cleanup) {
        throw error(
          'Message subscription setup and cleanup failed',
          new AggregateError([cause, cleanup]),
        );
      }
      throw cause;
    }
  }
  private closeSubscription(owner: OwnedSubscription): Promise<void> {
    if (this.handlerContext.getStore() === owner)
      return Promise.reject(
        new KitError({
          code: 'EK_LIFECYCLE_STATE',
          message: 'A handler cannot await closure of its own subscription',
        }),
      );
    if (owner.closing) return owner.closing;
    const opening = owner.phase === 'opening';
    owner.phase = 'closing';
    owner.removeAbort?.();
    let unsubscribeFailure: unknown,
      unsubscribeFailed = false;
    try {
      owner.native?.unsubscribe();
    } catch (cause) {
      unsubscribeFailed = true;
      unsubscribeFailure = cause;
    }
    if (opening) {
      for (const bytes of owner.queue) {
        this.bytes -= bytes.byteLength;
        this.queued--;
        this.counts.dropped++;
      }
      owner.queue.length = 0;
    } else this.pump(owner);
    owner.closing = (async () => {
      try {
        await within(
          async () => {
            const results = await Promise.allSettled([
              owner.worker,
              unsubscribeFailed ? undefined : owner.native?.closed,
            ]);
            for (const result of results) if (result.status === 'rejected') throw result.reason;
            if (unsubscribeFailed) throw unsubscribeFailure;
          },
          { timeoutMs: 5000 },
        );
      } catch (cause) {
        const failure = new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'Message subscription cleanup did not finish',
          cause,
          details: { cleanupFailed: true },
        });
        this.fail(failure, false);
        throw failure;
      } finally {
        owner.phase = 'closed';
        this.subscriptions.delete(owner);
        for (const bytes of owner.queue) {
          this.bytes -= bytes.byteLength;
          this.queued--;
          this.counts.dropped++;
        }
        owner.queue.length = 0;
      }
    })();
    return owner.closing;
  }

  async health(input?: OperationOptions): Promise<boolean> {
    const operation = messageOptions(input);
    if (this.fatal || !this.online) return false;
    try {
      return await this.run('health', operation, 0, false, async (client) => {
        await client.flush();
        return true;
      });
    } catch (cause) {
      if (
        cause instanceof KitError &&
        ['EK_CONFIG_INVALID', 'EK_ABORTED', 'EK_RESOURCE_CLOSED'].includes(cause.code)
      )
        throw cause;
      return false;
    }
  }

  close(input?: OperationOptions): Promise<void> {
    const operation = messageOptions(input, false, true);
    if (this.handlerContext.getStore())
      return Promise.reject(
        new KitError({
          code: 'EK_LIFECYCLE_STATE',
          message: 'A handler cannot await closure of its own bus',
        }),
      );
    const force = () => {
      this.stop.abort(operation.signal?.reason);
      void this.closeNative().catch((cause: unknown) => this.cleanupFailure(cause));
    };
    if (operation.signal && this.state !== 'closed') {
      operation.signal.addEventListener('abort', force, { once: true });
      if (operation.signal.aborted) force();
    }
    if (this.closing) {
      void this.closing.then(
        () => operation.signal?.removeEventListener('abort', force),
        () => operation.signal?.removeEventListener('abort', force),
      );
      return this.closing;
    }
    this.state = 'closing';
    this.online = false;
    const subscriptionClosures = [...this.subscriptions].map((owner) =>
      this.closeSubscription(owner),
    );
    const nativeDrain = Promise.resolve().then(async () => {
      if (this.client && !this.client.isClosed() && !this.client.isDraining())
        await this.client.drain();
    });
    const operationsSettled = Promise.allSettled([...this.pending]).then(() => undefined);
    const owned = [...subscriptionClosures, ...this.errorTasks, nativeDrain, operationsSettled];
    const settling = Promise.allSettled(owned);
    this.closing = (async () => {
      try {
        const results = await within(() => settling, {
          ...operation,
          timeoutMs: Math.min(operation.timeoutMs, 5000),
        });
        for (const result of results)
          if (result.status === 'rejected') this.cleanupFailure(result.reason);
      } catch (cause) {
        this.cleanupFailure(cause);
      } finally {
        this.stop.abort(
          new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Messaging bus is closed' }),
        );
        try {
          await within(
            async () => {
              await this.closeNative();
            },
            { timeoutMs: 1000 },
          );
        } catch (cause) {
          this.cleanupFailure(cause);
        }
        this.state = 'closed';
        operation.signal?.removeEventListener('abort', force);
      }
      if (this.cleanupErrors.length)
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'Messaging cleanup failed',
          cause: new AggregateError(this.cleanupErrors),
          details: { cleanupFailed: true },
        });
    })();
    return this.closing;
  }
  stats(): Readonly<MessageBusStats> {
    return Object.freeze({
      connected: this.state === 'ready' && this.online && !this.fatal,
      subscriptions: this.subscriptions.size,
      pendingPublications: this.publications,
      retainedBytes: this.bytes,
      queuedMessages: this.queued,
      activeHandlers: this.handlers,
      ...this.counts,
    });
  }
}
