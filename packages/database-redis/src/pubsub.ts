// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { RedisClientType } from 'redis';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions, Subscription } from '@arkenivajs/core';
import { captureAbortSignal, within } from '@arkenivajs/core/support';
import { types } from 'node:util';

export const REDIS_PUBSUB_CAPABILITY: unique symbol = Symbol('arkenivajs.redis.pubsub');
export interface RedisSubscriptionOptions extends OperationOptions {
  /** Transport failure, overflow and handler failure terminate this subscription without replay. */
  readonly onFailure: (error: KitError) => void | Promise<void>;
}
/** The named adapter owns the dedicated native connection and applies its configured channel prefix. */
export interface RedisPubsubProvider {
  readonly connectionName: string;
  subscribe(
    channel: string,
    handler: (message: string, options: OperationOptions) => Promise<void>,
    options: RedisSubscriptionOptions,
  ): Promise<Subscription>;
}
const fault = () =>
  new KitError({
    code: 'EK_BACKEND_UNAVAILABLE',
    message: 'Redis subscription could not continue',
  });
export function subscriptionOptions(
  input: RedisSubscriptionOptions,
): Required<Pick<RedisSubscriptionOptions, 'timeoutMs' | 'onFailure'>> &
  Pick<OperationOptions, 'signal'> {
  if (
    !input ||
    typeof input !== 'object' ||
    types.isProxy(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid Redis subscription options',
    });
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (
    Reflect.ownKeys(input).some(
      (key) =>
        typeof key !== 'string' ||
        !['signal', 'timeoutMs', 'onFailure'].includes(key) ||
        !('value' in descriptors[key]!),
    )
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid Redis subscription options',
    });
  const timeoutMs = descriptors.timeoutMs?.value ?? 15000;
  const onFailure = descriptors.onFailure?.value as RedisSubscriptionOptions['onFailure'];
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 15000 ||
    typeof onFailure !== 'function' ||
    types.isProxy(onFailure)
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid Redis subscription bounds or failure handler',
    });
  const signal =
    descriptors.signal?.value === undefined
      ? undefined
      : captureAbortSignal(descriptors.signal.value);
  if (signal?.aborted)
    throw new KitError({ code: 'EK_ABORTED', message: 'Redis subscription was cancelled' });
  return { timeoutMs: timeoutMs as number, onFailure, ...(signal ? { signal } : {}) };
}
/** Native Redis is responsible for protocol framing; this owner bounds callback work and retained bytes. */
export class RedisSubscriber implements Subscription {
  private readonly stop = new AbortController();
  private readonly pending = new Set<Promise<unknown>>();
  private readonly queue: { value: string; bytes: number }[] = [];
  private retained = 0;
  private closed = false;
  private worker: Promise<void> | undefined;
  private closing: Promise<void> | undefined;
  private starting: Promise<unknown> | undefined;
  private readonly abort = () => {
    this.end();
  };
  constructor(
    private readonly client: RedisClientType,
    private readonly handler: (message: string, options: OperationOptions) => Promise<void>,
    private readonly options: ReturnType<typeof subscriptionOptions>,
  ) {
    this.client.on('error', () => this.fail());
    this.client.on('reconnecting', () => this.fail());
    this.client.on('end', () => this.fail());
    options.signal?.addEventListener('abort', this.abort, { once: true });
    if (options.signal?.aborted) this.end();
  }
  private track<T>(task: Promise<T>): Promise<T> {
    this.pending.add(task);
    const release = () => this.pending.delete(task);
    void task.then(release, release);
    return task;
  }
  private end(): void {
    if (this.closed) return;
    this.closed = true;
    this.stop.abort();
    this.options.signal?.removeEventListener('abort', this.abort);
    this.queue.length = 0;
    this.retained = 0;
    if (this.client.isOpen) this.client.destroy();
  }
  private fail(): void {
    if (this.closed) return;
    this.end();
    void this.track(Promise.resolve().then(() => this.options.onFailure(fault()))).catch(
      () => undefined,
    );
  }
  private receive(value: string): void {
    if (this.closed) return;
    const size = typeof value === 'string' ? Buffer.byteLength(value) : Infinity;
    if (size > 1048576 || this.retained + size > 4194304 || this.queue.length >= 1024) {
      this.fail();
      return;
    }
    this.retained += size;
    this.queue.push({ value, bytes: size });
    if (this.worker) return;
    this.worker = this.track(
      Promise.resolve().then(async () => {
        while (!this.closed && this.queue.length) {
          const selected = this.queue.shift()!;
          try {
            const actual = this.track(
              Promise.resolve().then(() =>
                this.handler(selected.value, {
                  signal: this.stop.signal,
                  timeoutMs: this.options.timeoutMs,
                }),
              ),
            );
            await within(() => actual, {
              signal: this.stop.signal,
              timeoutMs: this.options.timeoutMs,
            });
          } finally {
            if (!this.closed) this.retained -= selected.bytes;
          }
        }
      }),
    );
    void this.worker.then(
      () => {
        this.worker = undefined;
      },
      () => {
        this.worker = undefined;
        this.fail();
      },
    );
  }
  async start(channel: string): Promise<void> {
    if (this.closed)
      throw new KitError({ code: 'EK_ABORTED', message: 'Redis subscription was cancelled' });
    this.starting = this.client.connect().then(async () => {
      if (this.closed) throw fault();
      await this.client.subscribe(channel, (message) => this.receive(message));
      if (this.closed) throw fault();
    });
    try {
      await within(() => this.starting!, {
        signal: this.stop.signal,
        timeoutMs: this.options.timeoutMs,
      });
    } catch {
      this.end();
      throw fault();
    }
  }
  close(): Promise<void> {
    this.end();
    return (this.closing ??= within(
      () =>
        Promise.allSettled([...this.pending, ...(this.starting ? [this.starting] : [])]).then(
          () => undefined,
        ),
      { timeoutMs: 5000 },
    ));
  }
}
